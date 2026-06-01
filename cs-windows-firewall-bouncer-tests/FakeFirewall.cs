using System.Collections.Generic;
using Api;
using Fw;

namespace cs_windows_firewall_bouncer_tests
{
    public class FakeFirewall : IFirewall
    {
        public bool Enabled { get; set; } = true;
        public string CurrentProfile { get; set; } = "test";
        public List<DecisionStreamResponse> Updates { get; } = new();
        public int DeleteAllRulesCallCount { get; private set; }

        public bool IsEnabled() => Enabled;
        public string GetCurrentProfile() => CurrentProfile;
        public void UpdateRule(DecisionStreamResponse decisions) => Updates.Add(decisions);
        public void DeleteAllRules() => DeleteAllRulesCallCount++;
    }
}
