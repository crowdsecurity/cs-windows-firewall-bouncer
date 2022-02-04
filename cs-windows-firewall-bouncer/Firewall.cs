using System;
using NetFwTypeLib;
using System.Runtime.InteropServices;
using System.Collections.Generic;

public class FirewallRule
{
	public int Capacity { get; } = 1000;
	public int Length { get; set; }
	private List<string> content = new();
	private string ruleName;
	public FirewallRule()
    {
		ruleName = "crowdsec-blocklist" + Guid.NewGuid().ToString();
	}

	public override string ToString()
    {
		return string.Join(",", content);
    }

	public void AddIP(string ip)
    {
		content.Add(ip);
		Length++;
    }
	public bool RemoveIP(string ip)
    {
		var r = content.Remove(ip);
		if (r)
        {
			Length--;
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
}

public class Firewall
{
	private INetFwMgr fwManager;
	private INetFwPolicy2 policy;
	private List<FirewallRule> rulesBucket = new();


	public Firewall()
	{
        fwManager = (INetFwMgr)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwMgr"));
		policy = (INetFwPolicy2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
		DeleteAllRules();
		//rules.Add(new FirewallRule());
		//CurrentProfileTypes
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
		Console.WriteLine("Deleting FW rule");
		policy.Rules.Remove(name);
    }

	private void DeleteAllRules()
    {
		foreach (INetFwRule rule in policy.Rules)
        {
			if (rule.Name.StartsWith("crowdsec-blocklist"))
            {
				policy.Rules.Remove(rule.Name);
            }
        }
    }

	private INetFwRule getRule(string name)
    {
		INetFwRule rule;
		try
        {
			rule = policy.Rules.Item(name);
			return rule;
		}
		catch (Exception ex)
        {
			Console.WriteLine("Exception: {0}", ex.Message);
        }
		return null;
	}

	public bool RuleExists(string name)
    {
		return getRule(name) != null;
    }

	public bool RuleIsEnabled(string name)
    {
		var rule = getRule(name);
		
		if (rule != null)
        {
			return rule.Enabled;
        }
		return false;
	}

	private bool isLocalIP(string ip)
    {
		return false;
    }

	private bool isLocalRange(string range)
    {
		return false;
    }

	private string expandCIDR(string range)
    {
		return string.Empty;
    }

	private FirewallRule findBucketForIp(string ip)
    {
		foreach (FirewallRule rule in rulesBucket)
        {
			if (rule.HasIp(ip))
            {
				return rule;
            }
        }
		return null;
    }

	private FirewallRule findAvailableBucket()
    {
		foreach (var rule in rulesBucket)
        {
			if (rule.Length < rule.Capacity)
            {
				return rule;
            }
        }
		var newRule = new FirewallRule();
		CreateRule(newRule.GetName());
		rulesBucket.Add(newRule);
		return newRule;
    }


	public void UpdateRule(DecisionStreamResponse decisions)
    {
		foreach (var decision in decisions.Deleted)
        {
			/*if (decision.scope != "Ip")
			{
				continue;
			}*/
			var bucket = findBucketForIp(decision.value);
			if (bucket == null)
            {
				continue;
            }
			bucket.RemoveIP(decision.value);
        }

		foreach (var decision in decisions.New)
        {
			/*if (decision.scope != "Ip")
            {
				continue;
            }*/
			var bucket = findAvailableBucket();
			bucket.AddIP(decision.value);
        }

		List<FirewallRule> toDelete = new();
		foreach (var rule in rulesBucket)
        {
			var fwRule = getRule(rule.GetName());
			var content = rule.ToString();
			if (content.Length == 0)
			{
				toDelete.Add(rule);
				DeleteRule(rule.GetName());
			}
			else
			{
				fwRule.RemoteAddresses = content;
				fwRule.Enabled = true;
			}
		}
		foreach (var fwRule in toDelete)
        {
			rulesBucket.Remove(fwRule);
		}
		//Console.WriteLine(ruleContent);
		//rule.RemoteAddresses = ruleContent;
		//rule.Enabled = true;
	}

	public void CreateRule(string name)
    {
		if (RuleExists(name))
        {
			Console.WriteLine("Rule already exists, not doing anything");
			return;
        }
		Console.WriteLine("Creating FW rule");
		INetFwRule2 rule = (INetFwRule2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwRule"));
		rule.Name = name;
		rule.Description = "CrowdSec Managed rule";
		rule.Enabled = false;
		rule.Profiles = policy.CurrentProfileTypes;
		rule.Action = NET_FW_ACTION_.NET_FW_ACTION_BLOCK;
		policy.Rules.Add(rule);
	}
}