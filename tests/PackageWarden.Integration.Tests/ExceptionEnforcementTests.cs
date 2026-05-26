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

using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using FluentAssertions;
using PackageWarden.Core.Domain;
using PackageWarden.Integration.Tests.Infrastructure;

namespace PackageWarden.Integration.Tests;

[Collection("Integration")]
public class ExceptionEnforcementTests
{
    private readonly FakeRegistryContainer _registry;
    private static string BlockPolicyPath => Path.Combine(AppContext.BaseDirectory, "Fixtures", "block-policy.yaml");

    public ExceptionEnforcementTests(FakeRegistryContainer registry)
    {
        _registry = registry;
    }

    [Fact]
    public async Task Exception_AllowsBlockedPackage_WhenFindingsUnchanged()
    {
        var vuln = new VulnerabilityFinding
        {
            VulnerabilityId = "CVE-2024-ENFORCE-A",
            Severity = Severity.Critical,
            Summary = "Vulnerability present at exception grant time"
        };

        using var factory = new PackageWardenFactory(_registry.BaseUrl)
        {
            ExtraAnalyzer = new StubAnalyzer([vuln]),
            PolicyFilePath = BlockPolicyPath
        };
        using var client = factory.CreateClient();

        // First request is blocked
        var blocked = await client.GetAsync("/v1/proxy/npm/test-package/-/test-package-1.0.0.tgz");
        blocked.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        var requestId = (await blocked.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("requestId").GetString();

        // Grant exception covering the known finding
        var grantResponse = await client.PostAsJsonAsync("/api/v1/exceptions", new { requestId });
        grantResponse.StatusCode.Should().Be(HttpStatusCode.Created);

        // Subsequent request with identical findings is now allowed
        var allowed = await client.GetAsync("/v1/proxy/npm/test-package/-/test-package-1.0.0.tgz");
        allowed.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task Exception_DoesNotApply_WhenNewFindingAppearsAfterGrant()
    {
        var initialVuln = new VulnerabilityFinding
        {
            VulnerabilityId = "CVE-2024-ENFORCE-B",
            Severity = Severity.Critical,
            Summary = "Known vulnerability at grant time"
        };
        var newVuln = new VulnerabilityFinding
        {
            VulnerabilityId = "CVE-2024-ENFORCE-C",
            Severity = Severity.Critical,
            Summary = "New vulnerability discovered after exception was granted"
        };

        var analyzer = new MutableStubAnalyzer([initialVuln]);

        using var factory = new PackageWardenFactory(_registry.BaseUrl)
        {
            ExtraAnalyzer = analyzer,
            PolicyFilePath = BlockPolicyPath
        };
        using var client = factory.CreateClient();

        // Initial request is blocked on the known finding
        var blocked = await client.GetAsync("/v1/proxy/npm/test-package/-/test-package-1.0.0.tgz");
        blocked.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        var requestId = (await blocked.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("requestId").GetString();

        // Grant exception for the known finding
        await client.PostAsJsonAsync("/api/v1/exceptions", new { requestId });

        // Simulate new finding being discovered
        analyzer.SetFindings([initialVuln, newVuln]);

        // Request now has a finding not covered by the exception — still blocked
        var stillBlocked = await client.GetAsync("/v1/proxy/npm/test-package/-/test-package-1.0.0.tgz");
        stillBlocked.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task Exception_StillApplies_WhenKnownFindingDisappears()
    {
        // A finding being fixed (disappearing) should not void the exception —
        // fewer findings is strictly safer than what was accepted.
        var vuln = new VulnerabilityFinding
        {
            VulnerabilityId = "CVE-2024-ENFORCE-D",
            Severity = Severity.Critical,
            Summary = "Vulnerability that will be resolved"
        };

        var analyzer = new MutableStubAnalyzer([vuln]);

        using var factory = new PackageWardenFactory(_registry.BaseUrl)
        {
            ExtraAnalyzer = analyzer,
            PolicyFilePath = BlockPolicyPath
        };
        using var client = factory.CreateClient();

        // Block and grant exception
        var blocked = await client.GetAsync("/v1/proxy/npm/test-package/-/test-package-1.0.0.tgz");
        blocked.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        var requestId = (await blocked.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("requestId").GetString();
        await client.PostAsJsonAsync("/api/v1/exceptions", new { requestId });

        // Simulate the vulnerability being resolved (finding disappears)
        analyzer.SetFindings([]);

        // No findings → empty set is a subset of anything → exception still applies
        var allowed = await client.GetAsync("/v1/proxy/npm/test-package/-/test-package-1.0.0.tgz");
        allowed.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task RevokedException_NoLongerAllowsBlockedPackage()
    {
        var vuln = new VulnerabilityFinding
        {
            VulnerabilityId = "CVE-2024-ENFORCE-E",
            Severity = Severity.Critical,
            Summary = "Vulnerability for revocation test"
        };

        using var factory = new PackageWardenFactory(_registry.BaseUrl)
        {
            ExtraAnalyzer = new StubAnalyzer([vuln]),
            PolicyFilePath = BlockPolicyPath
        };
        using var client = factory.CreateClient();

        // Block and grant exception
        var blocked = await client.GetAsync("/v1/proxy/npm/test-package/-/test-package-1.0.0.tgz");
        blocked.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        var requestId = (await blocked.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("requestId").GetString();

        var granted = await (await client.PostAsJsonAsync("/api/v1/exceptions", new { requestId }))
            .Content.ReadFromJsonAsync<JsonElement>();
        var exceptionId = granted.GetProperty("exceptionId").GetString();

        // Verify exception is working
        var allowed = await client.GetAsync("/v1/proxy/npm/test-package/-/test-package-1.0.0.tgz");
        allowed.StatusCode.Should().Be(HttpStatusCode.OK);

        // Revoke the exception
        await client.DeleteAsync($"/api/v1/exceptions/{exceptionId}");

        // Package is blocked again
        var blockedAgain = await client.GetAsync("/v1/proxy/npm/test-package/-/test-package-1.0.0.tgz");
        blockedAgain.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }
}
