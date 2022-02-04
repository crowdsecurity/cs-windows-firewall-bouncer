using System;
using System.Threading.Tasks;

using CommandLine;

namespace cs_windows_firewall_bouncer
{
    class Program
    {
        public class Options
        {
            [Option('c', "config", Required = false, Default = "C:\\Program Files\\CrowdSec\\bouncers\\cs-windows-firewall-bouncer.yaml", HelpText = "Path to the config file")]
            public string Config { get; set; }
            [Option('r', "remove", Required = false, Default = false, HelpText = "Delete all crowdsec firewall rules and exit")]
            public bool RemoveAll { get; set; }
            [Option('d', "debug", Required = false, Default = false, HelpText = "Enable debug logging")]
            public bool Debug { get; set; }
            //[Option('s', "service", Required = false, Default = "", HelpText = "Manage ")]

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
