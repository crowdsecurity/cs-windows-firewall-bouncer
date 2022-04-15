using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Linq;
using System.ServiceProcess;
using System.Text;
using System.Threading.Tasks;

using Cfg;
using Fw;
using Manager;

namespace cs_windows_firewall_bouncer
{
    partial class Service : ServiceBase
    {

        private readonly NLog.Logger Logger = NLog.LogManager.GetCurrentClassLogger();

        BouncerConfig config;
        DecisionsManager mgr;
        public Service(BouncerConfig config)
        {
            Logger.Debug("Creating new service object");
            this.config = config;
            CanPauseAndContinue = false;
            InitializeComponent();
        }

        protected override void OnStart(string[] args)
        {
            Logger.Debug("Onstart service");
            mgr = new(config);
            var _ = mgr.Run();
            base.OnStart(args);
            Logger.Debug("Onstart service end");

        }

        protected override void OnStop()
        {
            Logger.Debug("Onstop service");
            Firewall firewall = new(null);
            firewall.DeleteAllRules();
            Logger.Debug("Onstop service end");
        }
    }
}
