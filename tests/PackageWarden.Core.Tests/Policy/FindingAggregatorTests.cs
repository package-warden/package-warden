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

public class FindingAggregatorTests
{
    private readonly FindingAggregator _aggregator = new();

    [Fact]
    public void SingleAnalyzer_NoDedup_ReturnsSameCount()
    {
        var results = new List<AnalyzerResult>
        {
            new("A", [
                new VulnerabilityFinding { VulnerabilityId = "CVE-1", Severity = Severity.High, Summary = "V1" },
                new VulnerabilityFinding { VulnerabilityId = "CVE-2", Severity = Severity.Medium, Summary = "V2" }
            ])
        };

        var findings = _aggregator.Aggregate(results);
        findings.Should().HaveCount(2);
    }

    [Fact]
    public void TwoAnalyzers_SameVuln_DedupedToOne()
    {
        var results = new List<AnalyzerResult>
        {
            new("OsvDev", [
                new VulnerabilityFinding { VulnerabilityId = "GHSA-xxxx", Aliases = ["CVE-2024-1111"], Severity = Severity.High, CvssScore = 7.5m, Summary = "Vuln from OsvDev" }
            ]),
            new("NvdAnalyzer", [
                new VulnerabilityFinding { VulnerabilityId = "CVE-2024-1111", Severity = Severity.Critical, CvssScore = 9.0m, Summary = "Vuln from NVD" }
            ])
        };

        var findings = _aggregator.Aggregate(results);
        findings.Should().HaveCount(1);

        var vuln = (VulnerabilityFinding)findings[0];
        vuln.Severity.Should().Be(Severity.Critical); // highest
        vuln.ReportedBy.Should().Contain("OsvDev");
        vuln.ReportedBy.Should().Contain("NvdAnalyzer");
    }

    [Fact]
    public void DifferentFindingTypes_NotDeduped()
    {
        var results = new List<AnalyzerResult>
        {
            new("A", [
                new VulnerabilityFinding { VulnerabilityId = "CVE-1", Severity = Severity.High, Summary = "V" },
                new LicenseFinding { SpdxId = "GPL-3.0-only", LicenseName = "GPL v3", Severity = Severity.High, Summary = "License" }
            ])
        };

        var findings = _aggregator.Aggregate(results);
        findings.Should().HaveCount(2);
    }

    [Fact]
    public void ReportedBy_PopulatedWithAnalyzerName()
    {
        var results = new List<AnalyzerResult>
        {
            new("OsvDev", [
                new VulnerabilityFinding { VulnerabilityId = "CVE-1", Severity = Severity.Low, Summary = "V" }
            ])
        };

        var findings = _aggregator.Aggregate(results);
        findings[0].ReportedBy.Should().Contain("OsvDev");
    }
}