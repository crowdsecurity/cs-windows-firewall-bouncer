using System;
using System.Threading;
using System.Threading.Tasks;

using Api;
using Cfg;
using Fw;

namespace Manager
{
    public class DecisionsManager
    {
        private readonly ApiClient apiClient;
        private readonly IFirewall firewall;
        private readonly int interval;

        private readonly NLog.Logger Logger = NLog.LogManager.GetCurrentClassLogger();
        public DecisionsManager(BouncerConfig config, IFirewall firewall = null, ApiClient apiClient = null)
        {
            this.apiClient = apiClient ?? new ApiClient(config.config.ApiKey, config.config.ApiEndpoint);
            interval = config.config.UpdateFrequency;
            if (interval <= 0)
            {
                interval = 10;
            }
            this.firewall = firewall ?? new Firewall(config.config.FwProfiles);

            if (!this.firewall.IsEnabled())
            {
                throw new Exception("Firewall is not enabled for the current profile, the bouncer won't work.");
            }
            Logger.Debug("Firewall is enabled for profile {0}", this.firewall.GetCurrentProfile());
        }

        public async Task RunOnce(bool startup, CancellationToken ct = default)
        {
            var decisions = await apiClient.GetDecisions(startup, ct);
            if (decisions == null)
            {
                Logger.Error("Could not get decisions from LAPI. (startup: {0})", startup);
                return;
            }
            firewall.UpdateRule(decisions);
        }

        public async Task Run(CancellationToken ct = default)
        {
            var intervalms = this.interval * 1000;
            var startup = true;
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await RunOnce(startup, ct);
                    if (startup)
                    {
                        startup = false;
                    }
                    await Task.Delay(intervalms, ct);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    break;
                }
            }
            Logger.Info("Bouncer loop exiting (cancellation requested)");
        }
    }
}