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

using System.Collections.Immutable;
using PackageWarden.Core.Domain;
using PackageWarden.Core.Interfaces;

namespace PackageWarden.Core.Policy;

public class FindingAggregator : IFindingAggregator
{
    public IReadOnlyList<Finding> Aggregate(IReadOnlyList<AnalyzerResult> results)
    {
        // Group by (type, canonical-id) — for vulnerabilities, resolve aliases
        var allFindings = results.SelectMany(r =>
            r.Findings.Select(f => (AnalyzerName: r.AnalyzerName, Finding: f)));

        var groups = new Dictionary<(FindingType, string), List<(string Analyzer, Finding Finding)>>(
            StringComparer.OrdinalIgnoreCase.Equals(default, default)
                ? null
                : EqualityComparer<(FindingType, string)>.Create(
                    (a, b) => a.Item1 == b.Item1 && string.Equals(a.Item2, b.Item2, StringComparison.OrdinalIgnoreCase),
                    o => HashCode.Combine(o.Item1, o.Item2.ToLowerInvariant())));

        foreach (var (analyzerName, finding) in allFindings)
        {
            var key = ResolveKey(finding);
            if (!groups.TryGetValue(key, out var group))
            {
                group = [];
                groups[key] = group;
            }
            group.Add((analyzerName, finding));
        }

        return groups.Values.Select(Merge).ToList();
    }

    private static (FindingType, string) ResolveKey(Finding finding)
    {
        // For vulnerabilities, prefer CVE id if available for cross-analyzer dedup
        if (finding is VulnerabilityFinding vuln)
        {
            var cve = vuln.Aliases?.FirstOrDefault(a => a.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase))
                ?? vuln.VulnerabilityId;
            return (FindingType.Vulnerability, cve);
        }
        return (finding.Type, finding.Id);
    }

    private static Finding Merge(List<(string Analyzer, Finding Finding)> entries)
    {
        var primary = entries
            .OrderByDescending(e => e.Finding.Severity)
            .ThenByDescending(e => e.Finding is VulnerabilityFinding v ? v.CvssScore ?? 0 : 0)
            .First().Finding;

        var reportedBy = entries.Select(e => e.Analyzer).Distinct().OrderBy(s => s).ToList();

        var mergedProperties = entries
            .SelectMany(e => e.Finding.Properties)
            .GroupBy(kv => kv.Key)
            .ToDictionary(g => g.Key, g => g.Last().Value)
            .ToImmutableDictionary();

        return primary switch
        {
            VulnerabilityFinding vuln => vuln with
            {
                ReportedBy = reportedBy,
                Properties = mergedProperties,
                Severity = entries.Max(e => e.Finding.Severity),
                CvssScore = entries
                    .OfType<(string, VulnerabilityFinding)>()
                    .Select(e => e.Item2.CvssScore)
                    .Where(s => s.HasValue)
                    .Select(s => s!.Value)
                    .DefaultIfEmpty(vuln.CvssScore ?? 0)
                    .Max() is decimal m and > 0 ? m : vuln.CvssScore,
                Aliases = entries
                    .SelectMany(e => e.Finding is VulnerabilityFinding v2 ? v2.Aliases ?? [] : [])
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToArray()
            },
            _ => primary switch
            {
                LicenseFinding lf => lf with { ReportedBy = reportedBy, Properties = mergedProperties },
                MalwareFinding mf => mf with { ReportedBy = reportedBy, Properties = mergedProperties },
                DependencyConfusionFinding dc => dc with { ReportedBy = reportedBy, Properties = mergedProperties },
                _ => primary
            }
        };
    }
}