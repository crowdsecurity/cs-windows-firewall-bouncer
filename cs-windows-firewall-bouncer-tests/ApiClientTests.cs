using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Api;
using Xunit;

namespace cs_windows_firewall_bouncer_tests
{
    public class ApiClientTests
    {
        private static MockHttpMessageHandler RespondWith(HttpStatusCode status, string body)
        {
            return new MockHttpMessageHandler
            {
                Responder = _ => new HttpResponseMessage(status)
                {
                    Content = new StringContent(body)
                }
            };
        }

        [Fact]
        public async Task SendsApiKeyAndUserAgentHeaders()
        {
            var handler = RespondWith(HttpStatusCode.OK, "{\"new\":[],\"deleted\":[]}");
            var client = new ApiClient("secret-key", "http://localhost:8080", handler);

            await client.GetDecisions(startup: true);

            Assert.NotNull(handler.LastRequest);
            Assert.Equal("secret-key", handler.LastRequest.Headers.GetValues("X-Api-Key").Single());
            Assert.Contains("cs-windows-fw-bouncer", handler.LastRequest.Headers.UserAgent.ToString());
        }

        [Fact]
        public async Task CallsStreamEndpointWithStartupTrue()
        {
            var handler = RespondWith(HttpStatusCode.OK, "{\"new\":[],\"deleted\":[]}");
            var client = new ApiClient("k", "http://localhost:8080", handler);

            await client.GetDecisions(startup: true);

            var url = handler.LastRequest.RequestUri.ToString();
            Assert.Contains("/v1/decisions/stream", url);
            Assert.Contains("startup=true", url);
            Assert.Contains("scope=ip,range", url);
        }

        [Fact]
        public async Task CallsStreamEndpointWithStartupFalse()
        {
            var handler = RespondWith(HttpStatusCode.OK, "{\"new\":[],\"deleted\":[]}");
            var client = new ApiClient("k", "http://localhost:8080", handler);

            await client.GetDecisions(startup: false);

            Assert.Contains("startup=false", handler.LastRequest.RequestUri.ToString());
        }

        [Fact]
        public async Task AppendsTrailingSlashToEndpoint()
        {
            var handler = RespondWith(HttpStatusCode.OK, "{\"new\":[],\"deleted\":[]}");
            var client = new ApiClient("k", "http://localhost:8080", handler);

            await client.GetDecisions(startup: true);

            Assert.StartsWith("http://localhost:8080/v1/decisions/stream", handler.LastRequest.RequestUri.ToString());
        }

        [Fact]
        public async Task PreservesExistingTrailingSlash()
        {
            var handler = RespondWith(HttpStatusCode.OK, "{\"new\":[],\"deleted\":[]}");
            var client = new ApiClient("k", "http://localhost:8080/", handler);

            await client.GetDecisions(startup: true);

            Assert.StartsWith("http://localhost:8080/v1/decisions/stream", handler.LastRequest.RequestUri.ToString());
        }

        [Fact]
        public async Task ParsesNewAndDeletedDecisions()
        {
            const string body = """
                {
                  "new": [
                    {"id":1,"origin":"crowdsec","type":"ban","scope":"Ip","value":"1.2.3.4","duration":"4h","scenario":"crowdsecurity/ssh-bf"},
                    {"id":2,"origin":"cscli","type":"ban","scope":"Range","value":"10.0.0.0/24","duration":"1h"}
                  ],
                  "deleted": [
                    {"id":99,"value":"5.6.7.8","scope":"Ip"}
                  ]
                }
                """;
            var handler = RespondWith(HttpStatusCode.OK, body);
            var client = new ApiClient("k", "http://localhost:8080", handler);

            var result = await client.GetDecisions(startup: true);

            Assert.NotNull(result);
            Assert.Equal(2, result.New.Count);
            Assert.Equal("1.2.3.4", result.New[0].value);
            Assert.Equal("crowdsec", result.New[0].origin);
            Assert.Equal(1, result.New[0].id);
            Assert.Equal("10.0.0.0/24", result.New[1].value);
            Assert.Single(result.Deleted);
            Assert.Equal("5.6.7.8", result.Deleted[0].value);
        }

        [Fact]
        public async Task NormalizesNullNewAndDeletedToEmptyLists()
        {
            var handler = RespondWith(HttpStatusCode.OK, "{\"new\":null,\"deleted\":null}");
            var client = new ApiClient("k", "http://localhost:8080", handler);

            var result = await client.GetDecisions(startup: true);

            Assert.NotNull(result);
            Assert.NotNull(result.New);
            Assert.NotNull(result.Deleted);
            Assert.Empty(result.New);
            Assert.Empty(result.Deleted);
        }

        [Fact]
        public async Task ReturnsNullOnHttpError()
        {
            var handler = RespondWith(HttpStatusCode.Unauthorized, "forbidden");
            var client = new ApiClient("bad-key", "http://localhost:8080", handler);

            var result = await client.GetDecisions(startup: true);

            Assert.Null(result);
        }

        [Fact]
        public async Task ReturnsNullOnServerError()
        {
            var handler = RespondWith(HttpStatusCode.InternalServerError, "boom");
            var client = new ApiClient("k", "http://localhost:8080", handler);

            var result = await client.GetDecisions(startup: true);

            Assert.Null(result);
        }
    }
}
