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


    }

    public class BouncerConfig
    {
        private readonly string configPath;
        public Config config { get; set; }
        public BouncerConfig(string configPath)
        {
            this.configPath = configPath;
            this.loadConfig();
        }

        private void loadConfig()
        {
            var deserializer = new DeserializerBuilder()
                .WithNamingConvention(UnderscoredNamingConvention.Instance)
                .Build();

            using (var reader = new System.IO.StreamReader(this.configPath))
            {
                config = deserializer.Deserialize<Config>(reader.ReadToEnd());
            }
        }
    }

}