// Copyright 2026 Patrick T. Dwyer
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

using PackageWarden.Core.Domain;
using PackageWarden.Core.Interfaces;

namespace PackageWarden.Core.Policy;

public class PolicyEngine : IPolicyEngine
{
    private readonly IReadOnlyList<PolicyRule> _rules;

    public PolicyEngine(IReadOnlyList<PolicyRule> rules)
    {
        _rules = rules;
    }

    public Task<PolicyDecision> EvaluateAsync(
        IReadOnlyList<Finding> findings,
        PackageRiskScore riskScore,
        CancellationToken ct = default)
    {
        foreach (var rule in _rules)
        {
            if (!Enum.TryParse<PolicyBlockMode>(rule.BlockMode, ignoreCase: true, out var blockMode))
                continue;

            var (fired, matchedCount, threshold, scoreThreshold) = EvaluateCondition(rule.Conditions, findings, riskScore);
            if (fired)
            {
                return Task.FromResult(new PolicyDecision(
                    IsBlocked: true,
                    BlockMode: blockMode,
                    MatchedPolicyName: rule.Name,
                    MatchedCount: matchedCount,
                    Threshold: threshold,
                    RiskScoreThreshold: scoreThreshold,
                    RiskScore: riskScore));
            }
        }

        return Task.FromResult(new PolicyDecision(
            IsBlocked: false,
            BlockMode: null,
            MatchedPolicyName: null,
            MatchedCount: null,
            Threshold: null,
            RiskScoreThreshold: null,
            RiskScore: riskScore));
    }

    private static (bool fired, int? matchedCount, int? threshold, decimal? scoreThreshold) EvaluateCondition(
        PolicyCondition condition,
        IReadOnlyList<Finding> findings,
        PackageRiskScore riskScore)
    {
        if (condition.AnyOf is { Count: > 0 })
        {
            var fired = condition.AnyOf.Any(matcher => findings.Any(f => FindingMatcherEvaluator.Matches(f, matcher)));
            return (fired, null, null, null);
        }

        if (condition.NoneOf is { Count: > 0 })
        {
            var fired = !condition.NoneOf.Any(matcher => findings.Any(f => FindingMatcherEvaluator.Matches(f, matcher)));
            return (fired, null, null, null);
        }

        if (condition.CountOf is not null)
        {
            var cof = condition.CountOf;
            var matched = findings.Where(f =>
            {
                if (cof.FindingType is not null &&
                    !string.Equals(cof.FindingType, f.Type.ToString(), StringComparison.OrdinalIgnoreCase))
                    return false;

                if (cof.Severity is not null)
                {
                    var severities = cof.Severity switch
                    {
                        string s => [s],
                        System.Collections.IEnumerable list => list.Cast<object>().Select(o => o.ToString()!).ToArray(),
                        _ => [cof.Severity.ToString()!]
                    };
                    if (!severities.Any(s => string.Equals(s, f.Severity.ToString(), StringComparison.OrdinalIgnoreCase)))
                        return false;
                }

                return true;
            }).Count();

            return (matched >= cof.Threshold, matched, cof.Threshold, null);
        }

        if (condition.ScoreExceeds is not null)
        {
            var se = condition.ScoreExceeds;
            decimal score;

            if (se.FindingType is not null)
            {
                score = riskScore.ByFindingType
                    .Where(t => string.Equals(t.FindingType.ToString(), se.FindingType, StringComparison.OrdinalIgnoreCase))
                    .Sum(t => t.Score);
            }
            else
            {
                score = riskScore.TotalScore;
            }

            return (score > se.Threshold, null, null, se.Threshold);
        }

        if (condition.AllOf is { Count: > 0 })
        {
            var allFired = condition.AllOf.All(sub =>
            {
                var (f, _, _, _) = EvaluateCondition(sub, findings, riskScore);
                return f;
            });
            return (allFired, null, null, null);
        }

        return (false, null, null, null);
    }
}