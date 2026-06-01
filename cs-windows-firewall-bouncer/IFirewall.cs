using Api;

namespace Fw
{
    public interface IFirewall
    {
        bool IsEnabled();
        string GetCurrentProfile();
        void UpdateRule(DecisionStreamResponse decisions);
        void DeleteAllRules();
    }
}
