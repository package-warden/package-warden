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
using PackageWarden.Integration.Tests.Infrastructure;

namespace PackageWarden.Integration.Tests;

public class ManagementApiTests : IDisposable
{
    private readonly PackageWardenFactory _factory;
    private readonly HttpClient _client;

    public ManagementApiTests()
    {
        _factory = new PackageWardenFactory("http://localhost:1");
        _client = _factory.CreateClient();
    }

    public void Dispose()
    {
        _client.Dispose();
        _factory.Dispose();
    }

    [Fact]
    public async Task SystemStatus_Returns200AndOk()
    {
        var response = await _client.GetAsync("/api/v1/system/status");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        body.GetProperty("status").GetString().Should().Be("ok");
    }

    [Fact]
    public async Task Stats_ReturnsZeroCounts_OnFreshInstance()
    {
        var response = await _client.GetAsync("/api/v1/stats");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        body.GetProperty("totalRequests").GetInt32().Should().Be(0);
        body.GetProperty("blockedRequests").GetInt32().Should().Be(0);
        body.GetProperty("allowedRequests").GetInt32().Should().Be(0);
    }

    [Fact]
    public async Task Requests_ReturnsEmptyPagedResult_OnFreshInstance()
    {
        var response = await _client.GetAsync("/api/v1/requests");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        body.GetProperty("items").GetArrayLength().Should().Be(0);
        body.GetProperty("totalCount").GetInt32().Should().Be(0);
        body.GetProperty("page").GetInt32().Should().Be(1);
    }
}