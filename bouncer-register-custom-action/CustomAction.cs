using Microsoft.Deployment.WindowsInstaller;
using System;
using System.Diagnostics;
using System.IO;

namespace bouncer_register_custom_action
{
    public class CustomActions
    {
        private static string registerBouncer(string bouncerPrefix)
        {
            string suffix = DateTime.Now.ToString("yyyyMMddHHmmssffff");
            Process p = new Process();
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.FileName = "C:\\Program Files\\CrowdSec\\cscli.exe";
            p.StartInfo.Arguments = string.Format("-oraw bouncers add {0}{1}", bouncerPrefix, suffix);
            p.StartInfo.CreateNoWindow = true;
            p.Start();
            string output = p.StandardOutput.ReadToEnd();
            p.WaitForExit();
            return output;
        }

        private static void updateBouncerConfig(string apiKey, string configPath)
        {
            string content = File.ReadAllText(configPath);
            content = content.Replace("${API_KEY}", apiKey);
            File.WriteAllText(configPath, content);
        }

        private static bool alreadyRegistered(string configPath)
        {
            string content = File.ReadAllText(configPath);
            return !content.Contains("${API_KEY}");
        }

        [CustomAction]
        public static ActionResult RegisterBouncer(Session session)
        {
            string bouncerPrefix;
            string bouncerConfigPath;
            session.Log("Begin bouncer registration custom action");
            
            if (session.CustomActionData == null)
            {
                session.Log("BouncerRegistration: no custom data passed, exiting.");
                return ActionResult.Failure;
            }

            try
            {
                bouncerPrefix = session.CustomActionData["bouncerPrefix"];
            }
            catch (Exception)
            {
                session.Log("missing bouncerSuffix param, exiting.");
                return ActionResult.Failure;
            }

            try
            {
                bouncerConfigPath = session.CustomActionData["bouncerConfigPath"];
            }
            catch (Exception)
            {
                session.Log("missing bouncerConfigPath param, exiting.");
                return ActionResult.Failure;
            }

            if (alreadyRegistered(bouncerConfigPath))
            {
                session.Log("Seems like a bouncer {0} is already registered.", bouncerPrefix);
                return ActionResult.Success;
            }

            string apiKey = registerBouncer(bouncerPrefix);
            updateBouncerConfig(apiKey, bouncerConfigPath);
            
            session.Log("End of bouncer registration custom action");
            return ActionResult.Success;
        }
    }
}
