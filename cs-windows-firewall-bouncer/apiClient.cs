using System;
using System.Threading.Tasks;
using System.Net.Http;
using Newtonsoft.Json;
using System.Collections.Generic;

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
        [JsonProperty("new")]
        public List<Decision> New { get; set; }
        [JsonProperty("deleted")]
        public List<Decision> Deleted { get; set; }
    }


    public class ApiClient
    {
        private readonly HttpClient client = new HttpClient();
        private readonly string apiEndpoint;

        private readonly NLog.Logger Logger = NLog.LogManager.GetCurrentClassLogger();
        public ApiClient(string apiKey, string apiEndpoint)
        {
            if (apiEndpoint.EndsWith('/'))
            {
                this.apiEndpoint = apiEndpoint;
            }
            else
            {
                this.apiEndpoint = apiEndpoint + '/';
            }
            client.DefaultRequestHeaders.Add("X-Api-Key", apiKey);
            client.DefaultRequestHeaders.Add("User-Agent", "cs-windows-fw-bouncer/0.0.4");
        }

        public async Task<DecisionStreamResponse> GetDecisions(bool startup)
        {
            Logger.Debug("starting GetDecisions");
            HttpResponseMessage response;
            try
            {
                var uri = apiEndpoint + "v1/decisions/stream?startup=" + startup.ToString().ToLower() + "&scope=ip,range";
                Logger.Trace("requesting {0}", uri);
                response = await client.GetAsync(uri);
                response.EnsureSuccessStatusCode();
            }
            catch (Exception ex)
            {
                Logger.Error("Could not get decisions: {0}", ex.Message);
                return null;
            }
            var body = await response.Content.ReadAsStringAsync();
            Logger.Trace("LAPI response: {0}", body);
            var decisions = JsonConvert.DeserializeObject<DecisionStreamResponse>(body);
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