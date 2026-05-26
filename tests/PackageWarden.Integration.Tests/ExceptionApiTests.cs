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
public class ExceptionApiTests
{
    private readonly FakeRegistryContainer _registry;
    private static string BlockPolicyPath => Path.Combine(AppContext.BaseDirectory, "Fixtures", "block-policy.yaml");

    private static VulnerabilityFinding CriticalVuln => new()
    {
        VulnerabilityId = "CVE-2024-EXCEPT-TEST",
        Severity = Severity.Critical,
        Summary = "Test critical vulnerability for exception tests"
    };

    public ExceptionApiTests(FakeRegistryContainer registry)
    {
        _registry = registry;
    }

    private async Task<string> BlockAndGetRequestId(HttpClient client)
    {
        var response = await client.GetAsync("/v1/proxy/npm/test-package/-/test-package-1.0.0.tgz");
        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        return body.GetProperty("requestId").GetString()!;
    }

    [Fact]
    public async Task GrantException_Returns201_WithCorrectPayload_ForBlockedRequest()
    {
        using var factory = new PackageWardenFactory(_registry.BaseUrl)
        {
            ExtraAnalyzer = new StubAnalyzer([CriticalVuln]),
            PolicyFilePath = BlockPolicyPath
        };
        using var client = factory.CreateClient();

        var requestId = await BlockAndGetRequestId(client);

        var response = await client.PostAsJsonAsync("/api/v1/exceptions", new { requestId, notes = "approved by security team" });

        response.StatusCode.Should().Be(HttpStatusCode.Created);
        var exc = await response.Content.ReadFromJsonAsync<JsonElement>();
        exc.GetProperty("isActive").GetBoolean().Should().BeTrue();
        exc.GetProperty("ecosystem").GetString().Should().Be("npm");
        exc.GetProperty("packageName").GetString().Should().Be("test-package");
        exc.GetProperty("packageVersion").GetString().Should().Be("1.0.0");
        exc.GetProperty("notes").GetString().Should().Be("approved by security team");
        exc.GetProperty("findingIds").GetArrayLength().Should().Be(1);
        exc.GetProperty("findingIds")[0].GetString().Should().Be("Vulnerability:CVE-2024-EXCEPT-TEST");
    }

    [Fact]
    public async Task GrantException_Returns404_ForUnknownRequestId()
    {
        using var factory = new PackageWardenFactory(_registry.BaseUrl);
        using var client = factory.CreateClient();

        var response = await client.PostAsJsonAsync("/api/v1/exceptions", new { requestId = Guid.NewGuid() });

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task GrantException_Returns400_ForAllowedRequest()
    {
        using var factory = new PackageWardenFactory(_registry.BaseUrl);
        using var client = factory.CreateClient();

        // Make an allowed request, then try to create an exception for it
        await client.GetAsync("/v1/proxy/npm/test-package/-/test-package-1.0.0.tgz");
        var requestsBody = await (await client.GetAsync("/api/v1/requests")).Content.ReadFromJsonAsync<JsonElement>();
        var requestId = requestsBody.GetProperty("items")[0].GetProperty("requestId").GetString();

        var response = await client.PostAsJsonAsync("/api/v1/exceptions", new { requestId });

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task ListExceptions_ReturnsEmpty_OnFreshInstance()
    {
        using var factory = new PackageWardenFactory(_registry.BaseUrl);
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/api/v1/exceptions");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        body.GetProperty("items").GetArrayLength().Should().Be(0);
        body.GetProperty("totalCount").GetInt32().Should().Be(0);
    }

    [Fact]
    public async Task ListExceptions_ReturnsGrantedException()
    {
        using var factory = new PackageWardenFactory(_registry.BaseUrl)
        {
            ExtraAnalyzer = new StubAnalyzer([CriticalVuln]),
            PolicyFilePath = BlockPolicyPath
        };
        using var client = factory.CreateClient();

        var requestId = await BlockAndGetRequestId(client);
        await client.PostAsJsonAsync("/api/v1/exceptions", new { requestId });

        var response = await client.GetAsync("/api/v1/exceptions");
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();

        body.GetProperty("totalCount").GetInt32().Should().Be(1);
        var item = body.GetProperty("items")[0];
        item.GetProperty("isActive").GetBoolean().Should().BeTrue();
        item.GetProperty("packageName").GetString().Should().Be("test-package");
    }

    [Fact]
    public async Task ListExceptions_ActiveFilter_ExcludesRevokedExceptions()
    {
        using var factory = new PackageWardenFactory(_registry.BaseUrl)
        {
            ExtraAnalyzer = new StubAnalyzer([CriticalVuln]),
            PolicyFilePath = BlockPolicyPath
        };
        using var client = factory.CreateClient();

        // Grant an exception then revoke it
        var requestId = await BlockAndGetRequestId(client);
        var granted = await (await client.PostAsJsonAsync("/api/v1/exceptions", new { requestId }))
            .Content.ReadFromJsonAsync<JsonElement>();
        var exceptionId = granted.GetProperty("exceptionId").GetString();

        await client.DeleteAsync($"/api/v1/exceptions/{exceptionId}");

        var activeResult = await (await client.GetAsync("/api/v1/exceptions?active=true")).Content.ReadFromJsonAsync<JsonElement>();
        var revokedResult = await (await client.GetAsync("/api/v1/exceptions?active=false")).Content.ReadFromJsonAsync<JsonElement>();
        var allResult = await (await client.GetAsync("/api/v1/exceptions")).Content.ReadFromJsonAsync<JsonElement>();

        activeResult.GetProperty("totalCount").GetInt32().Should().Be(0);
        revokedResult.GetProperty("totalCount").GetInt32().Should().Be(1);
        allResult.GetProperty("totalCount").GetInt32().Should().Be(1);
    }

    [Fact]
    public async Task RevokeException_Returns204_AndExceptionBecomesInactive()
    {
        using var factory = new PackageWardenFactory(_registry.BaseUrl)
        {
            ExtraAnalyzer = new StubAnalyzer([CriticalVuln]),
            PolicyFilePath = BlockPolicyPath
        };
        using var client = factory.CreateClient();

        var requestId = await BlockAndGetRequestId(client);
        var granted = await (await client.PostAsJsonAsync("/api/v1/exceptions", new { requestId }))
            .Content.ReadFromJsonAsync<JsonElement>();
        var exceptionId = granted.GetProperty("exceptionId").GetString();

        var revokeResponse = await client.DeleteAsync($"/api/v1/exceptions/{exceptionId}");
        revokeResponse.StatusCode.Should().Be(HttpStatusCode.NoContent);

        var listed = await (await client.GetAsync("/api/v1/exceptions")).Content.ReadFromJsonAsync<JsonElement>();
        listed.GetProperty("items")[0].GetProperty("isActive").GetBoolean().Should().BeFalse();
    }

    [Fact]
    public async Task RevokeException_IsIdempotent()
    {
        using var factory = new PackageWardenFactory(_registry.BaseUrl)
        {
            ExtraAnalyzer = new StubAnalyzer([CriticalVuln]),
            PolicyFilePath = BlockPolicyPath
        };
        using var client = factory.CreateClient();

        var requestId = await BlockAndGetRequestId(client);
        var granted = await (await client.PostAsJsonAsync("/api/v1/exceptions", new { requestId }))
            .Content.ReadFromJsonAsync<JsonElement>();
        var exceptionId = granted.GetProperty("exceptionId").GetString();

        await client.DeleteAsync($"/api/v1/exceptions/{exceptionId}");
        var secondRevoke = await client.DeleteAsync($"/api/v1/exceptions/{exceptionId}");

        secondRevoke.StatusCode.Should().Be(HttpStatusCode.NoContent);
    }
}
