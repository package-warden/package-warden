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

public class PolicyEngineTests
{
    private static PackageRiskScore EmptyScore() => new(0, []);

    private static PackageRiskScore ScoreOf(decimal total) =>
        new(total, [new FindingTypeScore(FindingType.Vulnerability, total, [])]);

    [Fact]
    public async Task NoRules_AllowsEverything()
    {
        var engine = new PolicyEngine([]);
        var result = await engine.EvaluateAsync([], EmptyScore());
        result.IsBlocked.Should().BeFalse();
    }

    [Fact]
    public async Task HardBlock_MalwareFinding_Blocks()
    {
        var rules = PolicyFileLoader.LoadFromString("""
            policies:
              - name: block-malware
                blockMode: Hard
                conditions:
                  anyOf:
                    - findingType: Malware
            """).Policies;

        var engine = new PolicyEngine(rules);
        var findings = new List<Finding>
        {
            new MalwareFinding
            {
                IndicatorId = "hash:abc123",
                IndicatorType = "KnownMaliciousHash",
                Severity = Severity.Critical,
                Summary = "Known malware"
            }
        };

        var result = await engine.EvaluateAsync(findings, EmptyScore());
        result.IsBlocked.Should().BeTrue();
        result.BlockMode.Should().Be(PolicyBlockMode.Hard);
        result.MatchedPolicyName.Should().Be("block-malware");
    }

    [Fact]
    public async Task HardBlock_NoMatchingFinding_Allows()
    {
        var rules = PolicyFileLoader.LoadFromString("""
            policies:
              - name: block-malware
                blockMode: Hard
                conditions:
                  anyOf:
                    - findingType: Malware
            """).Policies;

        var engine = new PolicyEngine(rules);
        var findings = new List<Finding>
        {
            new VulnerabilityFinding
            {
                VulnerabilityId = "CVE-2024-0001",
                Severity = Severity.High,
                Summary = "Some vuln"
            }
        };

        var result = await engine.EvaluateAsync(findings, EmptyScore());
        result.IsBlocked.Should().BeFalse();
    }

    [Fact]
    public async Task ThresholdBlock_ReacheThreshold_Blocks()
    {
        var rules = PolicyFileLoader.LoadFromString("""
            policies:
              - name: medium-flood
                blockMode: Threshold
                conditions:
                  countOf:
                    findingType: Vulnerability
                    severity:
                      - Medium
                    threshold: 3
            """).Policies;

        var engine = new PolicyEngine(rules);
        var findings = Enumerable.Range(1, 3).Select(i =>
            (Finding)new VulnerabilityFinding
            {
                VulnerabilityId = $"CVE-2024-{i:0000}",
                Severity = Severity.Medium,
                Summary = $"Vuln {i}"
            }).ToList();

        var result = await engine.EvaluateAsync(findings, EmptyScore());
        result.IsBlocked.Should().BeTrue();
        result.BlockMode.Should().Be(PolicyBlockMode.Threshold);
        result.MatchedCount.Should().Be(3);
    }

    [Fact]
    public async Task ThresholdBlock_BelowThreshold_Allows()
    {
        var rules = PolicyFileLoader.LoadFromString("""
            policies:
              - name: medium-flood
                blockMode: Threshold
                conditions:
                  countOf:
                    findingType: Vulnerability
                    severity:
                      - Medium
                    threshold: 3
            """).Policies;

        var engine = new PolicyEngine(rules);
        var findings = Enumerable.Range(1, 2).Select(i =>
            (Finding)new VulnerabilityFinding
            {
                VulnerabilityId = $"CVE-2024-{i:0000}",
                Severity = Severity.Medium,
                Summary = $"Vuln {i}"
            }).ToList();

        var result = await engine.EvaluateAsync(findings, EmptyScore());
        result.IsBlocked.Should().BeFalse();
    }

    [Fact]
    public async Task ScoreBlock_ExceedsThreshold_Blocks()
    {
        var rules = PolicyFileLoader.LoadFromString("""
            policies:
              - name: high-score
                blockMode: Score
                conditions:
                  scoreExceeds:
                    threshold: 50
            """).Policies;

        var engine = new PolicyEngine(rules);
        var result = await engine.EvaluateAsync([], ScoreOf(51));
        result.IsBlocked.Should().BeTrue();
        result.BlockMode.Should().Be(PolicyBlockMode.Score);
        result.RiskScoreThreshold.Should().Be(50);
    }

    [Fact]
    public async Task ScoreBlock_ExactlyAtThreshold_Allows()
    {
        var rules = PolicyFileLoader.LoadFromString("""
            policies:
              - name: high-score
                blockMode: Score
                conditions:
                  scoreExceeds:
                    threshold: 50
            """).Policies;

        var engine = new PolicyEngine(rules);
        var result = await engine.EvaluateAsync([], ScoreOf(50));
        result.IsBlocked.Should().BeFalse();
    }

    [Fact]
    public async Task CvssScorePredicate_Blocks()
    {
        var rules = PolicyFileLoader.LoadFromString("""
            policies:
              - name: block-high-cvss
                blockMode: Hard
                conditions:
                  anyOf:
                    - findingType: Vulnerability
                      cvssScore: ">= 9.0"
            """).Policies;

        var engine = new PolicyEngine(rules);
        var findings = new List<Finding>
        {
            new VulnerabilityFinding
            {
                VulnerabilityId = "CVE-2024-9999",
                Severity = Severity.Critical,
                CvssScore = 9.8m,
                Summary = "Critical RCE"
            }
        };

        var result = await engine.EvaluateAsync(findings, EmptyScore());
        result.IsBlocked.Should().BeTrue();
    }

    [Fact]
    public async Task AllOfCondition_BothMatch_Blocks()
    {
        var rules = PolicyFileLoader.LoadFromString("""
            policies:
              - name: confusion-plus-vuln
                blockMode: Hard
                conditions:
                  allOf:
                    - anyOf:
                        - findingType: DependencyConfusion
                    - anyOf:
                        - findingType: Vulnerability
            """).Policies;

        var engine = new PolicyEngine(rules);
        var findings = new List<Finding>
        {
            new DependencyConfusionFinding { PackageName = "acme-internal", Severity = Severity.High, Summary = "Dep confusion" },
            new VulnerabilityFinding { VulnerabilityId = "CVE-2024-1111", Severity = Severity.Low, Summary = "Low vuln" }
        };

        var result = await engine.EvaluateAsync(findings, EmptyScore());
        result.IsBlocked.Should().BeTrue();
    }

    [Fact]
    public async Task AllOfCondition_OnlyOneMatch_Allows()
    {
        var rules = PolicyFileLoader.LoadFromString("""
            policies:
              - name: confusion-plus-vuln
                blockMode: Hard
                conditions:
                  allOf:
                    - anyOf:
                        - findingType: DependencyConfusion
                    - anyOf:
                        - findingType: Vulnerability
            """).Policies;

        var engine = new PolicyEngine(rules);
        var findings = new List<Finding>
        {
            new DependencyConfusionFinding { PackageName = "acme-internal", Severity = Severity.High, Summary = "Dep confusion" }
        };

        var result = await engine.EvaluateAsync(findings, EmptyScore());
        result.IsBlocked.Should().BeFalse();
    }
}