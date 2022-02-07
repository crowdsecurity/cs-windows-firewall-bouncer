using System;
using System.Threading.Tasks;

public class DecisionsManager
{
	private ApiClient apiClient;
	private Firewall firewall;
	private int interval;

	private readonly NLog.Logger Logger = NLog.LogManager.GetCurrentClassLogger();
	public DecisionsManager(BouncerConfig config)
	{
		apiClient = new(config.config.ApiKey, config.config.ApiEndpoint);
		interval = config.config.UpdateFrequency;
		if (interval <= 0)
        {
			interval = 10;
        }
		firewall = new Firewall();

		if (firewall.IsEnabled() == false)
		{
			throw new Exception("Firewall is not enabled for the current profile, the bouncer won't work.");
		}
		Logger.Debug("Firewall is enabled for profile {0}", firewall.GetCurrentProfile());
	}

	public async Task<bool> Run()
    {
		var decisions = await apiClient.GetDecisions(true);
		if (decisions == null)
        {
			Logger.Error("Could not get initial decisions from LAPI.");
			return false;
        }
		firewall.UpdateRule(decisions);
		var interval = this.interval * 1000;
		while (true)
        {
			decisions = await apiClient.GetDecisions(false);
			if (decisions == null)
			{
				Logger.Error("Could not get decisions from LAPI.");
				Task.Delay(interval).Wait();
				continue;
			}
			firewall.UpdateRule(decisions);
			Task.Delay(interval).Wait();
		}
	}
}
