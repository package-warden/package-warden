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

namespace PackageWarden.Core.Policy;

public static class FindingMatcherEvaluator
{
    public static bool Matches(Finding finding, FindingMatcher matcher)
    {
        if (!MatchesFindingType(finding, matcher.FindingType)) return false;
        if (!MatchesSeverity(finding, matcher.Severity)) return false;
        if (!PredicateParser.EvaluateString(matcher.Id, finding.Id)) return false;

        if (matcher.CvssScore is not null && finding is VulnerabilityFinding vuln)
        {
            if (!PredicateParser.EvaluateNumeric(matcher.CvssScore, vuln.CvssScore)) return false;
        }

        if (matcher.Properties is not null)
        {
            foreach (var (key, expr) in matcher.Properties)
            {
                finding.Properties.TryGetValue(key, out var propValue);
                if (!PredicateParser.EvaluateString(expr, propValue)) return false;
            }
        }

        return true;
    }

    private static bool MatchesFindingType(Finding finding, object? typeSpec)
    {
        if (typeSpec is null) return true;

        var typeStrings = typeSpec switch
        {
            string s => [s],
            System.Collections.IEnumerable list => list.Cast<object>().Select(o => o.ToString()!).ToArray(),
            _ => [typeSpec.ToString()!]
        };

        return typeStrings.Any(t => string.Equals(t, finding.Type.ToString(), StringComparison.OrdinalIgnoreCase));
    }

    private static bool MatchesSeverity(Finding finding, object? severitySpec)
    {
        if (severitySpec is null) return true;

        var severityStrings = severitySpec switch
        {
            string s => [s],
            System.Collections.IEnumerable list => list.Cast<object>().Select(o => o.ToString()!).ToArray(),
            _ => [severitySpec.ToString()!]
        };

        return severityStrings.Any(s => string.Equals(s, finding.Severity.ToString(), StringComparison.OrdinalIgnoreCase));
    }
}