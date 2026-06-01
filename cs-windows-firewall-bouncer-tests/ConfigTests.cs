using Cfg;
using Xunit;

namespace cs_windows_firewall_bouncer_tests
{
    public class ConfigTests
    {
        [Fact]
        public void ParsesFullConfig()
        {
            const string yaml = @"
api_endpoint: http://localhost:8080
api_key: test-key
log_level: debug
update_frequency: 30
log_media: file
log_dir: C:\ProgramData\CrowdSec\log
fw_profiles:
  - domain
  - private
";
            var cfg = BouncerConfig.FromString(yaml).config;

            Assert.Equal("http://localhost:8080", cfg.ApiEndpoint);
            Assert.Equal("test-key", cfg.ApiKey);
            Assert.Equal("debug", cfg.LogLevel);
            Assert.Equal(30, cfg.UpdateFrequency);
            Assert.Equal("file", cfg.LogMedia);
            Assert.Equal(@"C:\ProgramData\CrowdSec\log", cfg.LogDir);
            Assert.Equal(new[] { "domain", "private" }, cfg.FwProfiles);
        }

        [Fact]
        public void ParsesPrometheusConfig()
        {
            const string yaml = @"
api_endpoint: http://localhost:8080
api_key: k
log_media: file
prometheus:
  enabled: true
  listen_addr: 0.0.0.0
  listen_port: 60601
";
            var cfg = BouncerConfig.FromString(yaml).config;

            Assert.NotNull(cfg.Prometheus);
            Assert.True(cfg.Prometheus.Enabled);
            Assert.Equal("0.0.0.0", cfg.Prometheus.ListenAddr);
            Assert.Equal(60601, cfg.Prometheus.ListenPort);
        }

        [Fact]
        public void PrometheusEnabledIsNullWhenOmitted()
        {
            // A null Enabled is treated as enabled by MetricsServer (on by default, opt-out).
            const string yaml = @"
api_endpoint: http://localhost:8080
api_key: k
log_media: file
prometheus:
  listen_port: 60601
";
            var cfg = BouncerConfig.FromString(yaml).config;

            Assert.NotNull(cfg.Prometheus);
            Assert.Null(cfg.Prometheus.Enabled);
            Assert.Equal(60601, cfg.Prometheus.ListenPort);
        }

        [Fact]
        public void ParsesDisabledPrometheusConfig()
        {
            const string yaml = @"
api_endpoint: http://localhost:8080
api_key: k
log_media: file
prometheus:
  enabled: false
";
            var cfg = BouncerConfig.FromString(yaml).config;

            Assert.NotNull(cfg.Prometheus);
            Assert.False(cfg.Prometheus.Enabled);
        }

        [Fact]
        public void ParsesConfigWithoutPrometheusBlock()
        {
            const string yaml = @"
api_endpoint: http://localhost:8080
api_key: k
log_media: file
";
            var cfg = BouncerConfig.FromString(yaml).config;
            Assert.Null(cfg.Prometheus);
        }

        [Fact]
        public void ParsesMinimalConfig()
        {
            const string yaml = @"
api_endpoint: http://localhost:8080
api_key: minimal-key
log_media: console
";
            var cfg = BouncerConfig.FromString(yaml).config;

            Assert.Equal("http://localhost:8080", cfg.ApiEndpoint);
            Assert.Equal("minimal-key", cfg.ApiKey);
            Assert.Equal("console", cfg.LogMedia);
            Assert.Null(cfg.FwProfiles);
            Assert.Equal(0, cfg.UpdateFrequency);
        }

        [Fact]
        public void ParsesEmptyFwProfilesAsEmptyList()
        {
            const string yaml = @"
api_endpoint: http://localhost:8080
api_key: k
log_media: file
fw_profiles: []
";
            var cfg = BouncerConfig.FromString(yaml).config;
            Assert.NotNull(cfg.FwProfiles);
            Assert.Empty(cfg.FwProfiles);
        }

        [Fact]
        public void ParsesSingleFwProfile()
        {
            const string yaml = @"
api_endpoint: http://localhost:8080
api_key: k
log_media: file
fw_profiles:
  - public
";
            var cfg = BouncerConfig.FromString(yaml).config;
            Assert.Single(cfg.FwProfiles);
            Assert.Equal("public", cfg.FwProfiles[0]);
        }
    }
}
