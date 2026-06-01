using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace cs_windows_firewall_bouncer_tests
{
    public class MockHttpMessageHandler : HttpMessageHandler
    {
        public HttpRequestMessage LastRequest { get; private set; }
        public Func<HttpRequestMessage, HttpResponseMessage> Responder { get; set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastRequest = request;
            return Task.FromResult(Responder(request));
        }
    }
}
