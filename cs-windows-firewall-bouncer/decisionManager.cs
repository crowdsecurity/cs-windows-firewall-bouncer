using System;
using System.Threading.Tasks;

public class DecisionsManager
{
	private ApiClient apiClient;
	private TimeSpan interval;
	private Firewall firewall;
	public DecisionsManager(BouncerConfig config)
	{
		apiClient = new(config.config.ApiKey, config.config.ApiEndpoint);
		//interval = TimeSpan.Parse(config.config.UpdateFrequency);
		firewall = new Firewall();

		if (firewall.IsEnabled() == false)
		{
			throw new Exception("Firewall is not enabled for the current profile, the bouncer won't work.");
		}
		Console.WriteLine("Firewall is enabled for profile {0}", firewall.GetCurrentProfile());
		//firewall.DeleteRule(); //Delete the rule on startup to make sure we have a clean state
		//firewall.CreateRule();

	}

	public async Task<bool> Run()
    {
		var decisions = await apiClient.GetDecisions(true);
		firewall.UpdateRule(decisions);
		while (true)
        {
			decisions = await apiClient.GetDecisions(false);
			firewall.UpdateRule(decisions);
			Task.Delay(1000).Wait();
        }
    }
}
