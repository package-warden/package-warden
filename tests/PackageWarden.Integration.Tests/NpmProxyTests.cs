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
public class NpmProxyTests
{
    private readonly FakeRegistryContainer _registry;

    public NpmProxyTests(FakeRegistryContainer registry)
    {
        _registry = registry;
    }

    [Fact]
    public async Task PackageManifest_Returns200_WithJsonBody()
    {
        using var factory = new PackageWardenFactory(_registry.BaseUrl);
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/v1/proxy/npm/test-package");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await response.Content.ReadAsStringAsync();
        body.Should().Contain("test-package");
        body.Should().Contain("1.0.0");
    }

    [Fact]
    public async Task TarballDownload_Returns200_WhenNoBlockingPolicy()
    {
        using var factory = new PackageWardenFactory(_registry.BaseUrl);
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/v1/proxy/npm/test-package/-/test-package-1.0.0.tgz");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task TarballDownload_Returns403_WhenCriticalVulnerabilityFound()
    {
        var blockPolicyPath = Path.Combine(AppContext.BaseDirectory, "Fixtures", "block-policy.yaml");
        var criticalVuln = new VulnerabilityFinding
        {
            VulnerabilityId = "OSV-2024-TEST",
            Severity = Severity.Critical,
            Summary = "Test critical vulnerability"
        };

        using var factory = new PackageWardenFactory(_registry.BaseUrl)
        {
            ExtraAnalyzer = new StubAnalyzer([criticalVuln]),
            PolicyFilePath = blockPolicyPath,
        };
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/v1/proxy/npm/test-package/-/test-package-1.0.0.tgz");

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        body.GetProperty("blocked").GetBoolean().Should().BeTrue();
        body.GetProperty("policy").GetString().Should().Be("block-critical-vulns");
    }

    [Fact]
    public async Task ScopedPackageManifest_WithPercentEncodedSlash_Returns200()
    {
        using var factory = new PackageWardenFactory(_registry.BaseUrl);
        using var client = factory.CreateClient();

        // npm encodes the '/' in scoped package names as '%2f', producing a single path segment
        using var request = new HttpRequestMessage(HttpMethod.Get,
            new Uri(client.BaseAddress!, "v1/proxy/npm/@test-scope%2ftest-package"));
        var response = await client.SendAsync(request);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await response.Content.ReadAsStringAsync();
        body.Should().Contain("@test-scope/test-package");
        body.Should().Contain("1.0.0");
    }

    [Fact]
    public async Task ScopedTarballDownload_WithPercentEncodedSlash_Returns200()
    {
        using var factory = new PackageWardenFactory(_registry.BaseUrl);
        using var client = factory.CreateClient();

        using var request = new HttpRequestMessage(HttpMethod.Get,
            new Uri(client.BaseAddress!, "v1/proxy/npm/@test-scope%2ftest-package/-/test-package-1.0.0.tgz"));
        var response = await client.SendAsync(request);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task ScopedPackageManifest_Returns200_WithJsonBody()
    {
        using var factory = new PackageWardenFactory(_registry.BaseUrl);
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/v1/proxy/npm/@test-scope/test-package");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await response.Content.ReadAsStringAsync();
        body.Should().Contain("@test-scope/test-package");
        body.Should().Contain("1.0.0");
    }

    [Fact]
    public async Task ScopedTarballDownload_Returns200_WhenNoBlockingPolicy()
    {
        using var factory = new PackageWardenFactory(_registry.BaseUrl);
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/v1/proxy/npm/@test-scope/test-package/-/test-package-1.0.0.tgz");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task ScopedTarballDownload_Returns403_WhenCriticalVulnerabilityFound()
    {
        var blockPolicyPath = Path.Combine(AppContext.BaseDirectory, "Fixtures", "block-policy.yaml");
        var criticalVuln = new VulnerabilityFinding
        {
            VulnerabilityId = "OSV-2024-TEST",
            Severity = Severity.Critical,
            Summary = "Test critical vulnerability"
        };

        using var factory = new PackageWardenFactory(_registry.BaseUrl)
        {
            ExtraAnalyzer = new StubAnalyzer([criticalVuln]),
            PolicyFilePath = blockPolicyPath,
        };
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/v1/proxy/npm/@test-scope/test-package/-/test-package-1.0.0.tgz");

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        body.GetProperty("blocked").GetBoolean().Should().BeTrue();
    }

    [Fact]
    public async Task TarballDownload_RecordsAllowedRequest_InStateStore()
    {
        using var factory = new PackageWardenFactory(_registry.BaseUrl);
        using var client = factory.CreateClient();

        await client.GetAsync("/v1/proxy/npm/test-package/-/test-package-1.0.0.tgz");

        var statsResponse = await client.GetAsync("/api/v1/stats");
        statsResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        var stats = await statsResponse.Content.ReadFromJsonAsync<JsonElement>();
        stats.GetProperty("totalRequests").GetInt32().Should().Be(1);
        stats.GetProperty("allowedRequests").GetInt32().Should().Be(1);
        stats.GetProperty("blockedRequests").GetInt32().Should().Be(0);
    }
}