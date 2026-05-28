using System.Collections.Generic;
using System.Linq;

using Api;

namespace Manager
{
    internal static class DecisionFilter
    {
        public static DecisionStreamResponse KeepSupportedTypes(DecisionStreamResponse decisions, ISet<string> supportedDecisionTypes)
        {
            decisions.New = KeepSupportedTypes(decisions.New, supportedDecisionTypes);
            decisions.Deleted = KeepSupportedTypes(decisions.Deleted, supportedDecisionTypes);
            return decisions;
        }

        private static List<Decision> KeepSupportedTypes(List<Decision> decisions, ISet<string> supportedDecisionTypes)
        {
            if (decisions == null)
            {
                return new List<Decision>();
            }

            if (supportedDecisionTypes == null || supportedDecisionTypes.Count == 0)
            {
                return decisions;
            }

            return decisions
                .Where(decision => IsSupported(decision, supportedDecisionTypes))
                .ToList();
        }

        private static bool IsSupported(Decision decision, ISet<string> supportedDecisionTypes)
        {
            if (decision?.type == null)
            {
                return false;
            }

            return supportedDecisionTypes.Contains(decision.type.Trim());
        }
    }
}
