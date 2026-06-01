using System;
using System.Threading;
using System.Threading.Tasks;
using System.Net.Http;
using System.Net.Security;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Collections.Generic;
using System.Linq;

namespace Api
{

    public class Decision
    {
        public int id { get; set; }
        public string origin { get; set; }
        public string type { get; set; }
        public string scope { get; set; }
        public string value { get; set; }
        public string duration { get; set; }
        public string until { get; set; }
        public string scenario { get; set; }
        public bool simulated { get; set; }
    }

    public class DecisionStreamResponse
    {
        [JsonPropertyName("new")]
        public List<Decision> New { get; set; }
        [JsonPropertyName("deleted")]
        public List<Decision> Deleted { get; set; }
    }


    public class ApiClient
    {
        private readonly HttpClient client;
        private readonly string apiEndpoint;
        private readonly List<string> scopes;
        private readonly List<string> scenariosContaining;
        private readonly List<string> scenariosNotContaining;
        private readonly List<string> origins;

        private readonly NLog.Logger Logger = NLog.LogManager.GetCurrentClassLogger();

        public ApiClient(
            string apiKey,
            string apiEndpoint,
            HttpMessageHandler handler = null,
            string certPath = null,
            string keyPath = null,
            string caCertPath = null,
            bool insecureSkipVerify = false,
            List<string> scopes = null,
            List<string> scenariosContaining = null,
            List<string> scenariosNotContaining = null,
            List<string> origins = null)
        {
            client = handler != null
                ? new HttpClient(handler)
                : new HttpClient(BuildHttpHandler(certPath, keyPath, caCertPath, insecureSkipVerify));

            if (apiEndpoint.EndsWith('/'))
            {
                this.apiEndpoint = apiEndpoint;
            }
            else
            {
                this.apiEndpoint = apiEndpoint + '/';
            }
            this.scopes = scopes?.Count > 0 ? scopes : new List<string> { "ip", "range" };
            this.scenariosContaining = scenariosContaining;
            this.scenariosNotContaining = scenariosNotContaining;
            this.origins = origins;

            client.DefaultRequestHeaders.Add("X-Api-Key", apiKey);
            var version = Assembly.GetExecutingAssembly().GetName().Version.ToString(3);
            client.DefaultRequestHeaders.Add("User-Agent", $"cs-windows-fw-bouncer/{version}");
        }

        private static HttpClientHandler BuildHttpHandler(string certPath, string keyPath, string caCertPath, bool insecureSkipVerify)
        {
            var handler = new HttpClientHandler();
            if (insecureSkipVerify)
            {
                handler.ServerCertificateCustomValidationCallback = (_, _, _, _) => true;
            }
            else if (!string.IsNullOrEmpty(caCertPath))
            {
                var caCerts = new X509Certificate2Collection();
                caCerts.ImportFromPemFile(caCertPath);
                handler.ServerCertificateCustomValidationCallback = (_, cert, chain, _) =>
                {
                    if (cert == null) return false;
                    chain.ChainPolicy.CustomTrustStore.Clear();
                    chain.ChainPolicy.CustomTrustStore.AddRange(caCerts);
                    chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                    return chain.Build(cert);
                };
            }
            if (!string.IsNullOrEmpty(certPath) && !string.IsNullOrEmpty(keyPath))
            {
                var pemCert = X509Certificate2.CreateFromPemFile(certPath, keyPath);
                // Windows requires a PFX round-trip for ephemeral keys to be usable by SslStream
                var pfxBytes = pemCert.Export(X509ContentType.Pfx);
                handler.ClientCertificates.Add(X509CertificateLoader.LoadPkcs12(pfxBytes, password: null));
            }
            return handler;
        }

        public async Task<DecisionStreamResponse> GetDecisions(bool startup, CancellationToken ct = default)
        {
            Logger.Debug("starting GetDecisions");
            HttpResponseMessage response;
            try
            {
                var query = new List<string>
                {
                    "startup=" + startup.ToString().ToLower(),
                    "scopes=" + string.Join(",", scopes.Select(Uri.EscapeDataString))
                };
                if (scenariosContaining?.Count > 0)
                {
                    query.Add("scenarios_containing=" + string.Join(",", scenariosContaining.Select(Uri.EscapeDataString)));
                }
                if (scenariosNotContaining?.Count > 0)
                {
                    query.Add("scenarios_not_containing=" + string.Join(",", scenariosNotContaining.Select(Uri.EscapeDataString)));
                }
                if (origins?.Count > 0)
                {
                    query.Add("origins=" + string.Join(",", origins.Select(Uri.EscapeDataString)));
                }
                var uri = apiEndpoint + "v1/decisions/stream?" + string.Join("&", query);
                Logger.Trace("requesting {0}", uri);
                response = await client.GetAsync(uri, ct);
                response.EnsureSuccessStatusCode();
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                Logger.Error("Could not get decisions: {0}", ex.Message);
                return null;
            }
            var body = await response.Content.ReadAsStringAsync(ct);
            Logger.Trace("LAPI response: {0}", body);
            var decisions = JsonSerializer.Deserialize<DecisionStreamResponse>(body);
            if (decisions.New == null)
            {
                decisions.New = new List<Decision>();
            }
            if (decisions.Deleted == null)
            {
                decisions.Deleted = new List<Decision>();
            }
            Logger.Info("Got {0} IP to delete, {1} to add", decisions.Deleted.Count, decisions.New.Count);
            return decisions;
        }
    }
}