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
        public List<string> FwProfiles { get; set; }

        public string CertPath { get; set; }
        public string KeyPath { get; set; }
        public string CaCertPath { get; set; }
        public bool InsecureSkipVerify { get; set; }

        public List<string> Scopes { get; set; }
        public List<string> ScenariosContaining { get; set; }
        public List<string> ScenariosNotContaining { get; set; }
        public List<string> Origins { get; set; }
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