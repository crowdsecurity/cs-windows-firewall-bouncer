using System;
using System.Collections.Generic;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace Cfg
{
    public class Config
    {
        public string ApiEndpoint { get; set; }
        public string ApiKey { get; set; }
        public string LogLevel { get; set; }
        public int UpdateFrequency { get; set; }
        public string LogMedia { get; set; }
        public string LogDir { get; set; }
        public string LogName { get; set; }
        public int? LogMaxSize { get; set; }
        public int? LogMaxAge { get; set; }
        public int? LogMaxBackups { get; set; }
        public bool? CompressLogs { get; set; }
        public List<string> FwProfiles { get; set; }

        public string CertPath { get; set; }
        public string KeyPath { get; set; }
        public string CaCertPath { get; set; }
        public bool InsecureSkipVerify { get; set; }

        public List<string> Scopes { get; set; }
        public List<string> ScenariosContaining { get; set; }
        public List<string> ScenariosNotContaining { get; set; }
        public List<string> Origins { get; set; }
        public string SupportedDecisionType { get; set; }

        public PrometheusConfig Prometheus { get; set; }
    }

    // Resolved log-rotation settings with defaults applied and values validated.
    public class LogRotationSettings
    {
        public const string DefaultLogName = "cs_windows_firewall_bouncer.log";

        public string LogName { get; private set; }
        public int MaxSize { get; private set; }    // MB; 0 = no size-based rotation
        public int MaxAge { get; private set; }     // days; 0 = no age limit
        public int MaxBackups { get; private set; } // -1 = unlimited
        public bool Compress { get; private set; }

        public static LogRotationSettings From(Config config)
        {
            var settings = new LogRotationSettings
            {
                LogName = string.IsNullOrEmpty(config.LogName) ? DefaultLogName : config.LogName,
                MaxSize = config.LogMaxSize ?? 100,
                MaxAge = config.LogMaxAge ?? 30,
                MaxBackups = config.LogMaxBackups ?? 1,
                Compress = config.CompressLogs ?? true,
            };

            if (settings.MaxSize < 0)
                throw new ArgumentException("log_max_size must be >= 0");
            if (settings.MaxAge < 0)
                throw new ArgumentException("log_max_age must be >= 0");
            if (settings.MaxBackups < -1)
                throw new ArgumentException("log_max_backups must be >= -1");

            return settings;
        }

        // Archive file-name pattern derived from LogName, e.g. "cs_windows_firewall_bouncer.{#}.log".
        public string ArchiveFileName()
        {
            var name = System.IO.Path.GetFileNameWithoutExtension(LogName);
            var ext = System.IO.Path.GetExtension(LogName);
            return $"{name}.{{#}}{ext}";
        }

        // NLog MaxArchiveFiles value: -1 (unlimited) maps to 0 ("keep all").
        public int MaxArchiveFiles()
        {
            return MaxBackups == -1 ? 0 : MaxBackups;
        }
    }

    public class PrometheusConfig
    {
        // Nullable so an absent value defaults to enabled, while "enabled: false" still opts out.
        public bool? Enabled { get; set; }
        public string ListenAddr { get; set; }
        public int ListenPort { get; set; }
    }

    public class BouncerConfig
    {
        public Config config { get; set; }

        public BouncerConfig(string configPath)
        {
            using var reader = new System.IO.StreamReader(configPath);
            config = Deserialize(reader.ReadToEnd());
        }

        private BouncerConfig() { }

        public static BouncerConfig FromString(string yaml)
        {
            return new BouncerConfig { config = Deserialize(yaml) };
        }

        private static Config Deserialize(string yaml)
        {
            var deserializer = new DeserializerBuilder()
                .WithNamingConvention(UnderscoredNamingConvention.Instance)
                .Build();
            return deserializer.Deserialize<Config>(yaml);
        }
    }

}