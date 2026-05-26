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

public class FindingMatcherEvaluatorTests
{
    private static VulnerabilityFinding Vuln(string id = "CVE-2024-1", Severity severity = Severity.High, decimal? cvss = null)
        => new() { VulnerabilityId = id, Severity = severity, CvssScore = cvss, Summary = "test" };

    private static MalwareFinding Malware(string id = "hash:abc", Severity severity = Severity.Critical)
        => new() { IndicatorId = id, IndicatorType = "hash", Severity = severity, Summary = "test" };

    // ---- FindingType matching ----

    [Fact]
    public void NullFindingType_MatchesAnyFinding()
    {
        var matcher = new FindingMatcher { FindingType = null };
        FindingMatcherEvaluator.Matches(Vuln(), matcher).Should().BeTrue();
        FindingMatcherEvaluator.Matches(Malware(), matcher).Should().BeTrue();
    }

    [Fact]
    public void SingleFindingType_Match_ReturnsTrue()
    {
        var matcher = new FindingMatcher { FindingType = "Vulnerability" };
        FindingMatcherEvaluator.Matches(Vuln(), matcher).Should().BeTrue();
    }

    [Fact]
    public void SingleFindingType_NoMatch_ReturnsFalse()
    {
        var matcher = new FindingMatcher { FindingType = "Malware" };
        FindingMatcherEvaluator.Matches(Vuln(), matcher).Should().BeFalse();
    }

    [Fact]
    public void FindingType_CaseInsensitive()
    {
        var matcher = new FindingMatcher { FindingType = "vulnerability" };
        FindingMatcherEvaluator.Matches(Vuln(), matcher).Should().BeTrue();
    }

    [Fact]
    public void EnumerableFindingType_AnyMatch_ReturnsTrue()
    {
        var matcher = new FindingMatcher { FindingType = new List<string> { "Malware", "Vulnerability" } };
        FindingMatcherEvaluator.Matches(Vuln(), matcher).Should().BeTrue();
    }

    [Fact]
    public void EnumerableFindingType_NoMatch_ReturnsFalse()
    {
        var matcher = new FindingMatcher { FindingType = new List<string> { "Malware", "License" } };
        FindingMatcherEvaluator.Matches(Vuln(), matcher).Should().BeFalse();
    }

    // ---- Severity matching ----

    [Fact]
    public void NullSeverity_MatchesAnySeverity()
    {
        var matcher = new FindingMatcher { Severity = null };
        FindingMatcherEvaluator.Matches(Vuln(severity: Severity.Low), matcher).Should().BeTrue();
    }

    [Fact]
    public void SingleSeverity_Match_ReturnsTrue()
    {
        var matcher = new FindingMatcher { Severity = "High" };
        FindingMatcherEvaluator.Matches(Vuln(severity: Severity.High), matcher).Should().BeTrue();
    }

    [Fact]
    public void SingleSeverity_NoMatch_ReturnsFalse()
    {
        var matcher = new FindingMatcher { Severity = "Critical" };
        FindingMatcherEvaluator.Matches(Vuln(severity: Severity.High), matcher).Should().BeFalse();
    }

    [Fact]
    public void EnumerableSeverity_AnyMatch_ReturnsTrue()
    {
        var matcher = new FindingMatcher { Severity = new List<string> { "High", "Critical" } };
        FindingMatcherEvaluator.Matches(Vuln(severity: Severity.High), matcher).Should().BeTrue();
    }

    [Fact]
    public void EnumerableSeverity_NoMatch_ReturnsFalse()
    {
        var matcher = new FindingMatcher { Severity = new List<string> { "Critical", "Medium" } };
        FindingMatcherEvaluator.Matches(Vuln(severity: Severity.High), matcher).Should().BeFalse();
    }

    // ---- Id predicate ----

    [Fact]
    public void IdPredicate_InList_Match_ReturnsTrue()
    {
        var matcher = new FindingMatcher { Id = "in [CVE-2024-1, CVE-2024-2]" };
        FindingMatcherEvaluator.Matches(Vuln("CVE-2024-1"), matcher).Should().BeTrue();
    }

    [Fact]
    public void IdPredicate_InList_NoMatch_ReturnsFalse()
    {
        var matcher = new FindingMatcher { Id = "in [CVE-2024-1, CVE-2024-2]" };
        FindingMatcherEvaluator.Matches(Vuln("CVE-2024-99"), matcher).Should().BeFalse();
    }

    // ---- CvssScore matching ----

    [Fact]
    public void CvssScore_VulnAboveThreshold_ReturnsTrue()
    {
        var matcher = new FindingMatcher { CvssScore = ">= 9.0" };
        FindingMatcherEvaluator.Matches(Vuln(cvss: 9.8m), matcher).Should().BeTrue();
    }

    [Fact]
    public void CvssScore_VulnBelowThreshold_ReturnsFalse()
    {
        var matcher = new FindingMatcher { CvssScore = ">= 9.0" };
        FindingMatcherEvaluator.Matches(Vuln(cvss: 7.5m), matcher).Should().BeFalse();
    }

    [Fact]
    public void CvssScore_NonVulnFinding_MatcherSkipped_ReturnsTrue()
    {
        // CvssScore condition is only evaluated for VulnerabilityFinding; ignored for others
        var matcher = new FindingMatcher { CvssScore = ">= 9.0" };
        FindingMatcherEvaluator.Matches(Malware(), matcher).Should().BeTrue();
    }

    // ---- Properties matching ----

    [Fact]
    public void Properties_Match_ReturnsTrue()
    {
        var vuln = Vuln() with { Properties = new Dictionary<string, string> { ["ecosystem"] = "npm" } };
        var matcher = new FindingMatcher { Properties = new Dictionary<string, string> { ["ecosystem"] = "npm" } };
        FindingMatcherEvaluator.Matches(vuln, matcher).Should().BeTrue();
    }

    [Fact]
    public void Properties_NoMatch_ReturnsFalse()
    {
        var vuln = Vuln() with { Properties = new Dictionary<string, string> { ["ecosystem"] = "npm" } };
        var matcher = new FindingMatcher { Properties = new Dictionary<string, string> { ["ecosystem"] = "pypi" } };
        FindingMatcherEvaluator.Matches(vuln, matcher).Should().BeFalse();
    }

    [Fact]
    public void Properties_MissingKey_ReturnsFalse()
    {
        var matcher = new FindingMatcher { Properties = new Dictionary<string, string> { ["ecosystem"] = "npm" } };
        FindingMatcherEvaluator.Matches(Vuln(), matcher).Should().BeFalse();
    }

    // ---- Combined conditions ----

    [Fact]
    public void AllConditions_OneFails_ReturnsFalse()
    {
        var matcher = new FindingMatcher { FindingType = "Vulnerability", Severity = "Critical" };
        FindingMatcherEvaluator.Matches(Vuln(severity: Severity.High), matcher).Should().BeFalse();
    }

    [Fact]
    public void AllConditions_AllMatch_ReturnsTrue()
    {
        var matcher = new FindingMatcher
        {
            FindingType = "Vulnerability",
            Severity = "High",
            CvssScore = ">= 7.0"
        };
        FindingMatcherEvaluator.Matches(Vuln(severity: Severity.High, cvss: 8.1m), matcher).Should().BeTrue();
    }
}
