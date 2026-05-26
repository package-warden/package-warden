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

using FluentAssertions;
using PackageWarden.Core.Domain;
using PackageWarden.Core.Policy;

namespace PackageWarden.Core.Tests.Policy;

public class RiskScorerTests
{
    private static ScoringConfig DefaultConfig() => PolicyFileLoader.LoadFromString("""
        scoring:
          aggregation: Sum
          defaults:
            bySeverity:
              Critical: 50
              High: 20
              Medium: 5
              Low: 1
              Info: 0
          byFindingType:
            Vulnerability:
              scoreFromCvss: true
              cvssScale: 10
              bySeverity:
                Critical: 50
                High: 20
                Medium: 5
                Low: 1
        """).Scoring;

    [Fact]
    public void NoFindings_ZeroScore()
    {
        var scorer = new RiskScorer(DefaultConfig());
        var result = scorer.Score([]);
        result.TotalScore.Should().Be(0);
    }

    [Fact]
    public void VulnWithCvss_UsesCvssTimesScale()
    {
        var scorer = new RiskScorer(DefaultConfig());
        var findings = new List<Finding>
        {
            new VulnerabilityFinding
            {
                VulnerabilityId = "CVE-2024-1",
                Severity = Severity.High,
                CvssScore = 8.1m,
                Summary = "High CVE"
            }
        };

        var result = scorer.Score(findings);
        result.TotalScore.Should().Be(81m); // 8.1 * 10
    }

    [Fact]
    public void VulnWithoutCvss_UsesSeverityWeight()
    {
        var scorer = new RiskScorer(DefaultConfig());
        var findings = new List<Finding>
        {
            new VulnerabilityFinding
            {
                VulnerabilityId = "CVE-2024-2",
                Severity = Severity.High,
                CvssScore = null,
                Summary = "High CVE no CVSS"
            }
        };

        var result = scorer.Score(findings);
        result.TotalScore.Should().Be(20m);
    }

    [Fact]
    public void AnalyzerScoreOverridesTakePrecedence()
    {
        var scorer = new RiskScorer(DefaultConfig());
        var findings = new List<Finding>
        {
            new VulnerabilityFinding
            {
                VulnerabilityId = "CVE-2024-3",
                Severity = Severity.Critical,
                CvssScore = 9.8m,
                AnalyzerScore = 999m,
                Summary = "Override"
            }
        };

        var result = scorer.Score(findings);
        result.TotalScore.Should().Be(999m);
    }

    [Fact]
    public void MultipleFindings_SummedCorrectly()
    {
        var scorer = new RiskScorer(DefaultConfig());
        var findings = new List<Finding>
        {
            new VulnerabilityFinding { VulnerabilityId = "CVE-1", Severity = Severity.High, CvssScore = 8.0m, Summary = "A" },
            new VulnerabilityFinding { VulnerabilityId = "CVE-2", Severity = Severity.Medium, CvssScore = 5.0m, Summary = "B" },
            new MalwareFinding { IndicatorId = "h1", IndicatorType = "t", Severity = Severity.Critical, Summary = "M" }
        };

        var result = scorer.Score(findings);
        result.TotalScore.Should().Be(80m + 50m + 50m); // 80 + 50 (CVSS) + 50 (default Critical)
    }
}