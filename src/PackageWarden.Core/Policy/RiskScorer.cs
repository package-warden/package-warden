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

public class RiskScorer : IRiskScorer
{
    private readonly ScoringConfig _config;

    public RiskScorer(ScoringConfig config)
    {
        _config = config;
    }

    public PackageRiskScore Score(IReadOnlyList<Finding> findings)
    {
        var byType = findings
            .GroupBy(f => f.Type)
            .Select(g =>
            {
                var scored = g.Select(f => new ScoredFinding(f, ComputeScore(f))).ToList();
                return new FindingTypeScore(g.Key, scored.Sum(s => s.Score), scored);
            })
            .ToList();

        return new PackageRiskScore(byType.Sum(t => t.Score), byType);
    }

    private decimal ComputeScore(Finding finding)
    {
        if (finding.AnalyzerScore.HasValue)
            return finding.AnalyzerScore.Value;

        var typeName = finding.Type.ToString();
        _config.ByFindingType.TryGetValue(typeName, out var typeConfig);

        if (typeConfig?.ScoreFromCvss == true && finding is VulnerabilityFinding vuln && vuln.CvssScore.HasValue)
            return vuln.CvssScore.Value * typeConfig.CvssScale;

        var weights = typeConfig?.BySeverity ?? _config.Defaults;
        return finding.Severity switch
        {
            Severity.Critical => weights.Critical,
            Severity.High => weights.High,
            Severity.Medium => weights.Medium,
            Severity.Low => weights.Low,
            Severity.Info => weights.Info,
            _ => 0
        };
    }
}