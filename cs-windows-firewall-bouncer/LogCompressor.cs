using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Threading;

namespace Logging
{
    // Gzip-compresses rotated log archives produced by NLog's FileTarget (named
    // "<base>_NN<ext>") into "<base>_NN<ext>.gz", and enforces count/age retention
    // over the compressed set. NLog cannot manage the .gz files itself (it no longer
    // tracks them once renamed), so retention lives here when compression is enabled.
    public class LogCompressor : IDisposable
    {
        private static readonly NLog.Logger Logger = NLog.LogManager.GetCurrentClassLogger();

        private readonly string _dir;
        private readonly string _activeName;   // e.g. cs_windows_firewall_bouncer.log
        private readonly string _baseName;     // e.g. cs_windows_firewall_bouncer
        private readonly string _ext;          // e.g. .log
        private readonly int _maxBackups;      // -1 = unlimited
        private readonly int _maxAge;          // days; 0 = unlimited
        private readonly TimeSpan _sweepInterval;
        private readonly object _lock = new object();

        private FileSystemWatcher _watcher;
        private Timer _timer;

        public LogCompressor(string logDir, string logName, int maxBackups, int maxAge)
            : this(logDir, logName, maxBackups, maxAge, TimeSpan.FromSeconds(60))
        {
        }

        public LogCompressor(string logDir, string logName, int maxBackups, int maxAge, TimeSpan sweepInterval)
        {
            _dir = logDir;
            _activeName = logName;
            _baseName = Path.GetFileNameWithoutExtension(logName);
            _ext = Path.GetExtension(logName);
            _maxBackups = maxBackups;
            _maxAge = maxAge;
            _sweepInterval = sweepInterval;
        }

        // Glob matching uncompressed archives only (the active log lacks the "_" suffix).
        private string ArchivePattern => $"{_baseName}_*{_ext}";

        // Glob matching already-compressed archives.
        private string CompressedPattern => $"{_baseName}_*{_ext}.gz";

        public void Start()
        {
            // Compress anything left uncompressed by a previous run, then prune.
            Sweep();

            // A FileSystemWatcher gives prompt compression, but it can silently drop
            // events under bursty rotation (and is unreliable on some platforms), so a
            // periodic timer is the reliable backstop. Both trigger a full sweep.
            _watcher = new FileSystemWatcher(_dir, ArchivePattern)
            {
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite,
            };
            _watcher.Created += OnArchiveAppeared;
            _watcher.Renamed += OnArchiveAppeared;
            _watcher.EnableRaisingEvents = true;

            _timer = new Timer(_ => Sweep(), null, _sweepInterval, _sweepInterval);
        }

        // Compress every pending archive in the directory and enforce retention.
        // A full sweep (rather than acting on the single triggering file) tolerates
        // missed watcher events: the next trigger or timer tick catches up.
        public void Sweep()
        {
            CompressPending();
            EnforceRetention();
        }

        private void OnArchiveAppeared(object sender, FileSystemEventArgs e)
        {
            Sweep();
        }

        // True for "<base>_*<ext>" files, excluding the active log and any .gz archive.
        private bool IsUncompressedArchive(string path)
        {
            var name = Path.GetFileName(path);
            if (string.Equals(name, _activeName, StringComparison.OrdinalIgnoreCase)) return false;
            if (name.EndsWith(".gz", StringComparison.OrdinalIgnoreCase)) return false;
            return name.StartsWith(_baseName + "_", StringComparison.OrdinalIgnoreCase)
                && name.EndsWith(_ext, StringComparison.OrdinalIgnoreCase);
        }

        public void CompressPending()
        {
            lock (_lock)
            {
                if (!Directory.Exists(_dir)) return;
                foreach (var f in Directory.GetFiles(_dir, ArchivePattern))
                {
                    if (IsUncompressedArchive(f))
                    {
                        CompressFile(f);
                    }
                }
            }
        }

        private void CompressFile(string path)
        {
            var gzPath = path + ".gz";
            // NLog may still hold the freshly-rotated file for a moment; retry briefly.
            for (int attempt = 0; ; attempt++)
            {
                try
                {
                    using (var src = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
                    using (var dst = new FileStream(gzPath, FileMode.Create, FileAccess.Write, FileShare.None))
                    using (var gz = new GZipStream(dst, CompressionLevel.Optimal))
                    {
                        src.CopyTo(gz);
                    }
                    File.Delete(path);
                    return;
                }
                catch (IOException) when (attempt < 5)
                {
                    Thread.Sleep(200);
                }
                catch (Exception ex)
                {
                    Logger.Warn("Failed to compress log archive {0}: {1}", path, ex.Message);
                    try { if (File.Exists(gzPath)) File.Delete(gzPath); } catch { }
                    return;
                }
            }
        }

        public void EnforceRetention()
        {
            lock (_lock)
            {
                if (!Directory.Exists(_dir)) return;

                var archives = Directory.GetFiles(_dir, CompressedPattern)
                    .Select(f => new FileInfo(f))
                    .OrderByDescending(fi => fi.LastWriteTimeUtc)
                    .ToList();

                if (_maxAge > 0)
                {
                    var cutoff = DateTime.UtcNow.AddDays(-_maxAge);
                    foreach (var fi in archives.Where(fi => fi.LastWriteTimeUtc < cutoff).ToList())
                    {
                        TryDelete(fi.FullName);
                        archives.Remove(fi);
                    }
                }

                if (_maxBackups >= 0)
                {
                    foreach (var fi in archives.Skip(_maxBackups))
                    {
                        TryDelete(fi.FullName);
                    }
                }
            }
        }

        private void TryDelete(string path)
        {
            try { File.Delete(path); }
            catch (Exception ex) { Logger.Warn("Failed to delete old log archive {0}: {1}", path, ex.Message); }
        }

        public void Dispose()
        {
            if (_watcher != null)
            {
                _watcher.EnableRaisingEvents = false;
                _watcher.Created -= OnArchiveAppeared;
                _watcher.Renamed -= OnArchiveAppeared;
                _watcher.Dispose();
                _watcher = null;
            }
            if (_timer != null)
            {
                _timer.Dispose();
                _timer = null;
            }
        }
    }
}
