using System;
using Prometheus;

using Cfg;

namespace Telemetry
{
    // Metric definitions. These are created at class-load and are no-ops until a
    // MetricServer is started, so they are safe to reference unconditionally.
    public static class BouncerMetrics
    {
        private const string Prefix = "cs_windows_fw_bouncer_";

        public static readonly Gauge ActiveDecisions = Prometheus.Metrics.CreateGauge(
            Prefix + "active_decisions",
            "Number of IP addresses currently blocked by the bouncer.");

        public static readonly Gauge FirewallRules = Prometheus.Metrics.CreateGauge(
            Prefix + "firewall_rules",
            "Number of Windows Firewall rules currently managed by the bouncer.");

        public static readonly Counter Decisions = Prometheus.Metrics.CreateCounter(
            Prefix + "decisions_total",
            "Total number of decisions applied to the firewall.",
            new CounterConfiguration { LabelNames = new[] { "action", "origin" } });

        public static readonly Counter LapiRequests = Prometheus.Metrics.CreateCounter(
            Prefix + "lapi_requests_total",
            "Total number of requests made to the LAPI decisions stream.",
            new CounterConfiguration { LabelNames = new[] { "status" } });
    }

    // Wraps the prometheus-net HttpListener-based metrics server.
    public class MetricsServer
    {
        private readonly NLog.Logger Logger = NLog.LogManager.GetCurrentClassLogger();
        private readonly bool enabled;
        private readonly string addr;
        private readonly int port;
        private MetricServer server;

        public MetricsServer(PrometheusConfig config)
        {
            // Metrics are on by default; only an explicit "enabled: false" disables them.
            enabled = config?.Enabled ?? true;
            addr = string.IsNullOrEmpty(config?.ListenAddr) ? "127.0.0.1" : config.ListenAddr;
            port = config != null && config.ListenPort > 0 ? config.ListenPort : 60601;
        }

        public void Start()
        {
            if (!enabled)
            {
                Logger.Debug("Prometheus metrics are disabled");
                return;
            }
            try
            {
                server = new MetricServer(hostname: addr, port: port);
                server.Start();
                Logger.Info("Prometheus metrics server listening on {0}:{1}/metrics", addr, port);
            }
            catch (Exception ex)
            {
                Logger.Error("Could not start Prometheus metrics server: {0}", ex.Message);
            }
        }

        public void Stop()
        {
            try
            {
                server?.Stop();
            }
            catch (Exception ex)
            {
                Logger.Debug("Error while stopping Prometheus metrics server: {0}", ex.Message);
            }
        }
    }
}
