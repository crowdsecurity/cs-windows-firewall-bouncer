using System;
using System.Threading.Tasks;

namespace cs_windows_firewall_bouncer
{
    class Program
    {

        static async Task Main(string[] args)
        {
            Firewall firewall = new();
            BouncerConfig config;
            

            try
            {
                config = new("C:\\Temp\\config.yaml");
            }
            catch (Exception ex)
            {
                Console.WriteLine("Could not load configuration: {0}", ex.Message);
                return;
            }

            
            DecisionsManager mgr = new(config);
            //Task decisionManagerTask = new( () => );

            //apiClient = new(config.config.ApiKey, config.config.ApiEndpoint);

            //var decisions = await apiClient.GetDecisions(true);

            /*firewall.DeleteRule();
            try
            {
                firewall.CreateRule();
            }
            catch (Exception ex)
            {
                Console.WriteLine("Could not create firewall rule : {0}", ex.Message);
            }*/
            await mgr.Run();
            //await decisionManagerTask;
            //decisionManagerTask.Start();
            //decisionManagerTask.Wait();

            //firewall.DeleteRule();
        }
    }
}
