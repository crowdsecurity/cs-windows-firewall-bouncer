﻿using System;
using NetFwTypeLib;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Linq;

using Api;

namespace Fw
{
    public class FirewallRule
    {
        public int Capacity { get; } = 1000;
        public int Length { get; set; }
        private List<string> content = new();
        private readonly string ruleName;
        private bool stale;

        private readonly NLog.Logger Logger = NLog.LogManager.GetCurrentClassLogger();

        public FirewallRule()
        {
            ruleName = "crowdsec-blocklist" + Guid.NewGuid().ToString();
            stale = false;
        }

        public override string ToString()
        {
            return string.Join(",", content);
        }

        public void AddIP(string ip)
        {
            content.Add(ip);
            Length++;
            stale = true;
        }
        public bool RemoveIP(string ip)
        {
            Logger.Trace("Removing IP {0} from rule {1}", ip, ruleName);
            var r = content.Remove(ip);
            if (r)
            {
                Length--;
                stale = true;
            }
            return r;
        }

        public bool HasIp(string ip)
        {
            return content.Contains(ip);
        }

        public string GetName()
        {
            return ruleName;
        }

        public bool IsStale()
        {
            return stale;
        }
        public void SetStale(bool s)
        {
            stale = s;
        }
    }

    public class Firewall
    {
        private readonly NLog.Logger Logger = NLog.LogManager.GetCurrentClassLogger();

        private readonly INetFwMgr fwManager;
        private readonly INetFwPolicy2 policy;
        private readonly List<FirewallRule> rulesBucket = new();
        private readonly int profiles;

        private readonly Dictionary<string, int> profilesDict = new Dictionary<string, int> { { "domain", 1 }, { "private", 2 }, { "public", 4 } };



        public Firewall(List<string> fwprofiles)
        {
            fwManager = (INetFwMgr)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwMgr"));
            policy = (INetFwPolicy2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
            if (fwprofiles == null || fwprofiles.Count == 0)
            {
                profiles = policy.CurrentProfileTypes;
            } 
            else
            {
                Logger.Info("Enabling rules for profiles {0}", string.Join(',', fwprofiles));
                foreach (string p in fwprofiles)
                {
                    profiles |= profilesDict[p];
                }
            }
            DeleteAllRules();
        }

        public bool IsEnabled()
        {
            return fwManager.LocalPolicy.CurrentProfile.FirewallEnabled;
        }

        public string GetCurrentProfile()
        {
            return policy.CurrentProfileTypes.ToString();
        }

        public void DeleteRule(string name)
        {
            Logger.Info("Deleting FW rule {0}", name);
            policy.Rules.Remove(name);
        }

        public void DeleteAllRules()
        {
            foreach (INetFwRule rule in policy.Rules)
            {
                if (rule.Name.StartsWith("crowdsec-blocklist"))
                {
                    Logger.Debug("Deleting rule {0}", rule.Name);
                    policy.Rules.Remove(rule.Name);
                }
            }
        }

        private INetFwRule getRule(string name)
        {
            Logger.Trace("in get rule for {0}", name);
            INetFwRule rule;
            try
            {
                rule = policy.Rules.Item(name);
                return rule;
            }
            catch (Exception ex)
            {
                Logger.Debug("Could not find rule {0}: {1}", name, ex.Message);
            }
            return null;
        }

        public bool RuleExists(string name)
        {
            return getRule(name) != null;
        }

        public bool RuleIsEnabled(string name)
        {
            Logger.Trace("checking if rule {0} is enabled");
            var rule = getRule(name);

            if (rule != null)
            {
                return rule.Enabled;
            }
            return false;
        }

        private FirewallRule findBucketForIp(string ip)
        {
            Logger.Trace("Trying to find bucket for ip {0}", ip);
            return rulesBucket.FirstOrDefault(x => x.HasIp(ip));
        }

        private FirewallRule findAvailableBucket()
        {
            var rule = rulesBucket.FirstOrDefault(x => x.Length < x.Capacity);
            if (rule != null)
            {
                return rule;
            }
            var newRule = new FirewallRule();
            Logger.Info("Creating new rule {0}", newRule.GetName());
            CreateRule(newRule.GetName());
            rulesBucket.Add(newRule);
            return newRule;
        }


        public void UpdateRule(DecisionStreamResponse decisions)
        {
            foreach (var decision in decisions.Deleted)
            {
                var bucket = findBucketForIp(decision.value);
                if (bucket == null)
                {
                    Logger.Trace("was not able to find a bucket for deleting {0}", decision.value);
                    continue;
                }
                bucket.RemoveIP(decision.value);
            }

            foreach (var decision in decisions.New)
            {
                if (findBucketForIp(decision.value) != null)
                {
                    Logger.Trace("{0} already exists in a bucket", decision.value);
                    continue;
                }
                var bucket = findAvailableBucket();
                bucket.AddIP(decision.value);
            }

            List<FirewallRule> toDelete = new();
            foreach (var rule in rulesBucket)
            {
                var content = rule.ToString();
                if (!rule.IsStale() && content.Length != 0)
                {
                    continue;
                }
                if (content.Length == 0)
                {
                    Logger.Debug("Adding bucket {0} to delete list", rule.GetName());
                    toDelete.Add(rule);
                    DeleteRule(rule.GetName());
                }
                else
                {
                    var fwRule = getRule(rule.GetName());
                    fwRule.RemoteAddresses = content;
                    fwRule.Enabled = true;
                    rule.SetStale(false);
                }
            }
            foreach (var fwRule in toDelete)
            {
                rulesBucket.Remove(fwRule);
            }
        }

        public void CreateRule(string name)
        {
            if (RuleExists(name))
            {
                Logger.Debug("Rule {0} already exists, not doing anything", name);
                return;
            }
            Logger.Debug("Creating FW rule");
            INetFwRule2 rule = (INetFwRule2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwRule"));
            rule.Name = name;
            rule.Description = "CrowdSec Managed rule";
            rule.Enabled = false;
            rule.Profiles = profiles;
            rule.Action = NET_FW_ACTION_.NET_FW_ACTION_BLOCK;
            policy.Rules.Add(rule);
        }
    }
}