using System;
using System.Threading.Tasks;
using System.Net.Http;
using Newtonsoft.Json;
using System.Collections.Generic;



public class Decision {
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

public class DecisionStreamResponse {
	[JsonProperty("new")]
	public List<Decision> New { get; set; }
	[JsonProperty("deleted")]
	public List<Decision> Deleted { get; set; }
}


public class ApiClient
{
	private readonly HttpClient client = new HttpClient();
	private string apiKey;
	private string apiEndpoint;
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
		this.apiKey = apiKey;
		client.DefaultRequestHeaders.Add("X-Api-Key", apiKey);
		client.DefaultRequestHeaders.Add("User-Agent", "cs-windows-fw-bouncer/0.1");
	}

	public async Task<DecisionStreamResponse> GetDecisions(bool startup)
    {
		Console.WriteLine("starting getdecisions");
		HttpResponseMessage response;
		try
		{
			var uri = apiEndpoint + "v1/decisions/stream?startup=" + startup.ToString().ToLower() + "&scope=ip,range";
			Console.WriteLine("requesting {0}", uri);
			response = await client.GetAsync(uri);
			response.EnsureSuccessStatusCode();
		}
		catch (Exception ex)
        {
			Console.WriteLine("Could not get decisions: {0}", ex.Message);
			return null;
        }
		var body = await response.Content.ReadAsStringAsync();
		//Console.WriteLine("after get decisions");
		//Console.WriteLine("Raw body: {0}", body);
		var decisions = JsonConvert.DeserializeObject<DecisionStreamResponse>(body);
		//Console.WriteLine("after decode : {0}", decisions.New);
		if (decisions.New == null) 
		{
			decisions.New = new List<Decision>();
        }
		if (decisions.Deleted == null)
		{
			decisions.Deleted = new List<Decision>();
		}
		Console.WriteLine("Got {0} IP to delete, {1} to add", decisions.Deleted.Count, decisions.New.Count);

		/*foreach (var decision in decisions.New)
		{
			Console.WriteLine("Decision: {0}", decision.value);
		}
		foreach (var decision in decisions.Deleted)
		{
			Console.WriteLine("Decision: {0}", decision.value);
		}*/
		return decisions;
    }
}
