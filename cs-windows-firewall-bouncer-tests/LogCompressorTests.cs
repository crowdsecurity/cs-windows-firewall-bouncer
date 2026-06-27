using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using Logging;
using Xunit;

namespace cs_windows_firewall_bouncer_tests
{
    public class LogCompressorTests : IDisposable
    {
        private const string LogName = "cs_windows_firewall_bouncer.log";
        private readonly string _dir;

        public LogCompressorTests()
        {
            _dir = Path.Combine(Path.GetTempPath(), "lc_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_dir);
        }

        public void Dispose()
        {
            try { Directory.Delete(_dir, true); } catch { }
        }

        private string Path_(string name) => Path.Combine(_dir, name);

        private void Write(string name, string content) => File.WriteAllText(Path_(name), content);

        [Fact]
        public void CompressPendingGzipsArchivesAndLeavesActiveLog()
        {
            Write("cs_windows_firewall_bouncer.log", "active");
            Write("cs_windows_firewall_bouncer_01.log", "one");
            Write("cs_windows_firewall_bouncer_02.log", "two");

            new LogCompressor(_dir, LogName, -1, 0).CompressPending();

            Assert.True(File.Exists(Path_("cs_windows_firewall_bouncer.log")));        // active untouched
            Assert.False(File.Exists(Path_("cs_windows_firewall_bouncer_01.log")));    // original removed
            Assert.True(File.Exists(Path_("cs_windows_firewall_bouncer_01.log.gz")));
            Assert.True(File.Exists(Path_("cs_windows_firewall_bouncer_02.log.gz")));

            using var fs = File.OpenRead(Path_("cs_windows_firewall_bouncer_01.log.gz"));
            using var gz = new GZipStream(fs, CompressionMode.Decompress);
            using var sr = new StreamReader(gz);
            Assert.Equal("one", sr.ReadToEnd());
        }

        [Fact]
        public void CompressPendingPreservesArchiveTimestamp()
        {
            Write("cs_windows_firewall_bouncer_01.log", "one");
            var archivedAt = DateTime.UtcNow.AddDays(-10);
            File.SetLastWriteTimeUtc(Path_("cs_windows_firewall_bouncer_01.log"), archivedAt);

            new LogCompressor(_dir, LogName, -1, 0).CompressPending();

            var gzWriteTime = File.GetLastWriteTimeUtc(Path_("cs_windows_firewall_bouncer_01.log.gz"));
            Assert.True(Math.Abs((gzWriteTime - archivedAt).TotalSeconds) < 2,
                $"expected ~{archivedAt:o}, got {gzWriteTime:o}");
        }

        [Fact]
        public void CompressPendingIsIdempotent()
        {
            Write("cs_windows_firewall_bouncer_01.log", "one");
            var lc = new LogCompressor(_dir, LogName, -1, 0);
            lc.CompressPending();
            lc.CompressPending(); // second pass: nothing left to compress, no double .gz.gz

            Assert.False(File.Exists(Path_("cs_windows_firewall_bouncer_01.log.gz.gz")));
            Assert.Single(Directory.GetFiles(_dir, "*.gz"));
        }

        [Fact]
        public void EnforceRetentionKeepsNewestBackups()
        {
            for (int i = 1; i <= 4; i++)
            {
                var name = $"cs_windows_firewall_bouncer_0{i}.log.gz";
                Write(name, "x");
                File.SetLastWriteTimeUtc(Path_(name), new DateTime(2026, 1, i, 0, 0, 0, DateTimeKind.Utc));
            }

            new LogCompressor(_dir, LogName, 2, 0).EnforceRetention(); // keep 2 newest

            var remaining = Directory.GetFiles(_dir, "*.gz").Select(Path.GetFileName).OrderBy(x => x).ToArray();
            Assert.Equal(
                new[] { "cs_windows_firewall_bouncer_03.log.gz", "cs_windows_firewall_bouncer_04.log.gz" },
                remaining);
        }

        [Fact]
        public void EnforceRetentionDeletesOldArchivesByAge()
        {
            Write("cs_windows_firewall_bouncer_01.log.gz", "x");
            File.SetLastWriteTimeUtc(Path_("cs_windows_firewall_bouncer_01.log.gz"), DateTime.UtcNow.AddDays(-40));
            Write("cs_windows_firewall_bouncer_02.log.gz", "x");
            File.SetLastWriteTimeUtc(Path_("cs_windows_firewall_bouncer_02.log.gz"), DateTime.UtcNow.AddDays(-1));

            new LogCompressor(_dir, LogName, -1, 30).EnforceRetention(); // 30-day age, unlimited count

            Assert.False(File.Exists(Path_("cs_windows_firewall_bouncer_01.log.gz")));
            Assert.True(File.Exists(Path_("cs_windows_firewall_bouncer_02.log.gz")));
        }

        [Fact]
        public void UnlimitedBackupsKeepsAll()
        {
            for (int i = 1; i <= 5; i++)
                Write($"cs_windows_firewall_bouncer_0{i}.log.gz", "x");

            new LogCompressor(_dir, LogName, -1, 0).EnforceRetention(); // unlimited count, no age limit

            Assert.Equal(5, Directory.GetFiles(_dir, "*.gz").Length);
        }
    }
}
