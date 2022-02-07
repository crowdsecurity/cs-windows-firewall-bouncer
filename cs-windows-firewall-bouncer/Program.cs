using System;
using System.Threading.Tasks;
using CommandLine;

namespace cs_windows_firewall_bouncer
{
    class Program
    {
        public class Options
        {
            [Option('c', "config", Required = false, Default = "C:\\Program Files\\CrowdSec\\bouncers\\cs-windows-firewall-bouncer\\cs-windows-firewall-bouncer.yaml", HelpText = "Path to the config file")]
            public string Config { get; set; }
            [Option('r', "remove", Required = false, Default = false, HelpText = "Delete all crowdsec firewall rules and exit")]
            public bool RemoveAll { get; set; }
            [Option('d', "debug", Required = false, Default = false, HelpText = "Enable debug logging")]
            public bool Debug { get; set; }
            //[Option('s', "service", Required = false, Default = "", HelpText = "Manage ")]

        }

        static private NLog.LogLevel GetLogLevel(string name)
        {
            switch (name)
            {
                case "trace":
                    return NLog.LogLevel.Trace;
                case "debug":
                    return NLog.LogLevel.Debug;
                case "info":
                    return NLog.LogLevel.Info;
                case "warn":
                    return NLog.LogLevel.Warn;
                case "error":
                    return NLog.LogLevel.Error;
                case "fatal":
                    return NLog.LogLevel.Fatal;
                default:
                    return NLog.LogLevel.Info;
            }
        }

        static async Task Main(string[] args)
        {
            BouncerConfig config;
            Options opts;

            var result = Parser.Default.ParseArguments<Options>(args).WithNotParsed(errors =>
            {
                foreach (var err in errors)
                {
                    Console.WriteLine("Error while parsing arguments: {0}", err.ToString());
                }
            }
            );

            opts = (result as Parsed<Options>)?.Value;
            if (opts == null)
            {
                return;
            }
            try
            {
                config = new(opts.Config);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Could not load configuration: {0}", ex.Message);
                return;
            }


            var loggerConfig = new NLog.Config.LoggingConfiguration();
            var logLevel = NLog.LogLevel.Info;

            if (config.config.LogLevel != "")
            {
                logLevel = GetLogLevel(config.config.LogLevel);
            }

            if (opts.Debug)
            {
                logLevel = NLog.LogLevel.Debug;
            }

            if (config.config.LogMedia == "file" || !Environment.UserInteractive)
            {
                if (config.config.LogDir == "")
                {
                    config.config.LogDir = "C:\\ProgramData\\CrowdSec\\log";
                }
                var logfile = new NLog.Targets.FileTarget("logfile") { FileName = System.IO.Path.Combine(config.config.LogDir, "cs_windows_firewall_bouncer.log")  };
                loggerConfig.AddRule(logLevel, NLog.LogLevel.Fatal, logfile);
            }
            else if (config.config.LogMedia == "console")
            {
                var logconsole = new NLog.Targets.ConsoleTarget("logconsole");
                loggerConfig.AddRule(logLevel, NLog.LogLevel.Fatal, logconsole);
            }
            else
            {
                Console.WriteLine("Unknown value for log_media: {0}", config.config.LogMedia);
                return;
            }
            
            NLog.LogManager.Configuration = loggerConfig; 

            if (opts.RemoveAll)
            {
                Firewall firewall = new();
                Console.WriteLine("Deleting all firewall rules.");
                firewall.DeleteAllRules();
                Console.WriteLine("Done deleting all firewall rules.");
                return;
            }

            DecisionsManager mgr = new(config);

            await mgr.Run();
        }
    }
}
