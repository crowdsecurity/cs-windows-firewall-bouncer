using System;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Api;
using Cfg;
using Manager;
using Xunit;

namespace cs_windows_firewall_bouncer_tests
{
    public class DecisionsManagerTests
    {
        private const string MinimalConfig = @"
api_endpoint: http://localhost:8080
api_key: k
log_media: file
update_frequency: 10
";

        private static (DecisionsManager mgr, FakeFirewall fw) BuildManager(string responseBody, HttpStatusCode status = HttpStatusCode.OK, FakeFirewall firewall = null)
        {
            var handler = new MockHttpMessageHandler
            {
                Responder = _ => new HttpResponseMessage(status) { Content = new StringContent(responseBody) }
            };
            var apiClient = new ApiClient("k", "http://localhost:8080", handler);
            var fw = firewall ?? new FakeFirewall();
            var config = BouncerConfig.FromString(MinimalConfig);
            var mgr = new DecisionsManager(config, fw, apiClient);
            return (mgr, fw);
        }

        [Fact]
        public void Constructor_ThrowsIfFirewallNotEnabled()
        {
            var handler = new MockHttpMessageHandler
            {
                Responder = _ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("{}") }
            };
            var apiClient = new ApiClient("k", "http://localhost:8080", handler);
            var fw = new FakeFirewall { Enabled = false };
            var config = BouncerConfig.FromString(MinimalConfig);

            var ex = Assert.Throws<Exception>(() => new DecisionsManager(config, fw, apiClient));
            Assert.Contains("Firewall is not enabled", ex.Message);
        }

        [Fact]
        public async Task RunOnce_PassesDecisionsToFirewall()
        {
            const string body = """
                {
                  "new": [{"id":1,"value":"1.2.3.4","scope":"Ip"}],
                  "deleted": [{"id":2,"value":"5.6.7.8","scope":"Ip"}]
                }
                """;
            var (mgr, fw) = BuildManager(body);

            await mgr.RunOnce(startup: true);

            Assert.Single(fw.Updates);
            Assert.Single(fw.Updates[0].New);
            Assert.Equal("1.2.3.4", fw.Updates[0].New[0].value);
            Assert.Single(fw.Updates[0].Deleted);
            Assert.Equal("5.6.7.8", fw.Updates[0].Deleted[0].value);
        }

        [Fact]
        public async Task RunOnce_DoesNotCallFirewallOnApiError()
        {
            var (mgr, fw) = BuildManager("forbidden", HttpStatusCode.Unauthorized);

            await mgr.RunOnce(startup: true);

            Assert.Empty(fw.Updates);
        }

        [Fact]
        public async Task RunOnce_HandlesEmptyDecisions()
        {
            var (mgr, fw) = BuildManager("{\"new\":[],\"deleted\":[]}");

            await mgr.RunOnce(startup: false);

            Assert.Single(fw.Updates);
            Assert.Empty(fw.Updates[0].New);
            Assert.Empty(fw.Updates[0].Deleted);
        }

        [Fact]
        public async Task RunOnce_NormalizesNullListsBeforeUpdating()
        {
            var (mgr, fw) = BuildManager("{\"new\":null,\"deleted\":null}");

            await mgr.RunOnce(startup: true);

            Assert.Single(fw.Updates);
            Assert.NotNull(fw.Updates[0].New);
            Assert.NotNull(fw.Updates[0].Deleted);
        }
    }
}
