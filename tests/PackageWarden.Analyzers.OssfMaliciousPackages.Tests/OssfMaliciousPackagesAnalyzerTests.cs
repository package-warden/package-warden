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
using System.Text;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using PackageWarden.Analyzers.OssfMaliciousPackages;
using PackageWarden.Core.Domain;
using PackageWarden.Core.Interfaces;

namespace PackageWarden.Analyzers.OssfMaliciousPackages.Tests;

public class OssfMaliciousPackagesAnalyzerTests
{
    // ─── Enabled guard ───────────────────────────────────────────────────────

    [Fact]
    public async Task WhenDisabled_ReturnsNoFindings()
    {
        var (analyzer, _) = Build(enabled: false);
        var result = await analyzer.AnalyzeAsync(MakeContext("npm", "lodash", "4.17.21"));
        result.Findings.Should().BeEmpty();
    }

    // ─── Ecosystem filtering ─────────────────────────────────────────────────

    [Theory]
    [InlineData("npm")]
    [InlineData("pypi")]
    [InlineData("nuget")]
    [InlineData("maven")]
    [InlineData("cargo")]
    [InlineData("gem")]
    [InlineData("golang")]
    [InlineData("NPM")]
    [InlineData("PyPI")]
    public async Task WhenSupportedEcosystem_CallsGitHubApi(string ecosystem)
    {
        var (analyzer, getRequests) = Build(apiResponse: () => OkJson(DirectoryListingJson(["MAL-2024-1"])));
        await analyzer.AnalyzeAsync(MakeContext(ecosystem, "some-pkg", "1.0.0"));
        getRequests().Should().Contain(r => r.RequestUri!.Host == "api.github.com");
    }

    // ─── Not in database ─────────────────────────────────────────────────────

    [Fact]
    public async Task WhenPackageNotInDatabase_ReturnsNoFindings()
    {
        var (analyzer, _) = Build(apiResponse: () => new HttpResponseMessage(HttpStatusCode.NotFound));
        var result = await analyzer.AnalyzeAsync(MakeContext("npm", "lodash", "4.17.21"));
        result.Findings.Should().BeEmpty();
    }

    // ─── Malicious package ───────────────────────────────────────────────────

    [Fact]
    public async Task WhenInDatabase_ReturnsCriticalMalwareFinding()
    {
        var (analyzer, _) = Build(
            apiResponse: () => OkJson(DirectoryListingJson(["MAL-2024-1"])),
            rawResponse: () => OkJson(OsvJson("MAL-2024-1", "evil-pkg", ["1.0.0"], "Malicious package steals credentials")));

        var result = await analyzer.AnalyzeAsync(MakeContext("npm", "evil-pkg", "1.0.0"));

        result.Findings.Should().HaveCount(1);
        var finding = result.Findings[0].Should().BeOfType<MalwareFinding>().Subject;
        finding.Severity.Should().Be(Severity.Critical);
        finding.IndicatorId.Should().Be("MAL-2024-1");
        finding.IndicatorType.Should().Be("malware");
    }

    [Fact]
    public async Task WhenInDatabase_SummaryContainsOsvSummary()
    {
        var (analyzer, _) = Build(
            apiResponse: () => OkJson(DirectoryListingJson(["MAL-2024-1"])),
            rawResponse: () => OkJson(OsvJson("MAL-2024-1", "evil-pkg", ["1.0.0"], "Exfiltrates environment variables")));

        var result = await analyzer.AnalyzeAsync(MakeContext("npm", "evil-pkg", "1.0.0"));

        result.Findings[0].Summary.Should().Contain("Exfiltrates environment variables");
    }

    [Fact]
    public async Task WhenInDatabase_ReferenceLinksToOssfRepo()
    {
        var (analyzer, _) = Build(
            apiResponse: () => OkJson(DirectoryListingJson(["MAL-2024-1"])),
            rawResponse: () => OkJson(OsvJson("MAL-2024-1", "evil-pkg", ["1.0.0"], "malware")));

        var result = await analyzer.AnalyzeAsync(MakeContext("npm", "evil-pkg", "1.0.0"));

        result.Findings[0].Reference.Should().Contain("github.com/ossf/malicious-packages");
        result.Findings[0].Reference.Should().Contain("evil-pkg");
    }

    [Fact]
    public async Task WhenInDatabase_NoReports_StillReturnsFinding()
    {
        // Package directory exists but no report dirs inside it
        var (analyzer, _) = Build(apiResponse: () => OkJson("[]"));

        var result = await analyzer.AnalyzeAsync(MakeContext("npm", "evil-pkg", "1.0.0"));

        result.Findings.Should().HaveCount(1);
        result.Findings[0].Should().BeOfType<MalwareFinding>()
            .Which.IndicatorId.Should().Be("evil-pkg", "falls back to package name when no report ID is available");
    }

    // ─── Summary content ──────────────────────────────────────────────────────

    [Fact]
    public async Task WhenRequestedVersionIsInAffectedList_SummaryDoesNotAppendVersionList()
    {
        var (analyzer, _) = Build(
            apiResponse: () => OkJson(DirectoryListingJson(["MAL-2024-1"])),
            rawResponse: () => OkJson(OsvJson("MAL-2024-1", "evil-pkg", ["1.0.0", "1.0.1"], "Credential stealer")));

        var result = await analyzer.AnalyzeAsync(MakeContext("npm", "evil-pkg", "1.0.0"));

        result.Findings[0].Summary.Should().Be("Credential stealer",
            "the OSV summary is used verbatim when the exact version is confirmed");
    }

    [Fact]
    public async Task WhenRequestedVersionIsNotInAffectedList_SummaryIncludesConfirmedVersions()
    {
        var (analyzer, _) = Build(
            apiResponse: () => OkJson(DirectoryListingJson(["MAL-2024-1"])),
            rawResponse: () => OkJson(OsvJson("MAL-2024-1", "evil-pkg", ["1.0.1"], "Credential stealer")));

        var result = await analyzer.AnalyzeAsync(MakeContext("npm", "evil-pkg", "1.0.0"));

        result.Findings[0].Summary.Should().Contain("1.0.1");
    }

    // ─── Ecosystem mapping ────────────────────────────────────────────────────

    [Theory]
    [InlineData("npm", "npm")]
    [InlineData("pypi", "pypi")]
    [InlineData("nuget", "nuget")]
    [InlineData("maven", "maven")]
    [InlineData("cargo", "crates.io")]
    [InlineData("gem", "rubygems")]
    [InlineData("golang", "go")]
    public async Task EcosystemIsMappedCorrectlyInApiUrl(string ecosystem, string expectedOssfEcosystem)
    {
        var (analyzer, getRequests) = Build(apiResponse: () => OkJson(DirectoryListingJson(["MAL-2024-1"])));
        await analyzer.AnalyzeAsync(MakeContext(ecosystem, "some-pkg", "1.0.0"));

        getRequests()
            .Where(r => r.RequestUri!.Host == "api.github.com")
            .Should().Contain(r => r.RequestUri!.PathAndQuery.Contains($"/packages/{expectedOssfEcosystem}/"));
    }

    // ─── PyPI name normalisation ──────────────────────────────────────────────

    [Fact]
    public async Task PyPI_NormalizesUnderscoresToHyphens()
    {
        var (analyzer, getRequests) = Build(apiResponse: () => OkJson(DirectoryListingJson(["MAL-2024-1"])));
        await analyzer.AnalyzeAsync(MakeContext("pypi", "my_evil_pkg", "1.0.0"));

        getRequests()
            .Where(r => r.RequestUri!.Host == "api.github.com")
            .Should().Contain(r => r.RequestUri!.PathAndQuery.Contains("my-evil-pkg"));
    }

    // ─── Rate limiting ────────────────────────────────────────────────────────

    [Theory]
    [InlineData(HttpStatusCode.Forbidden)]
    [InlineData(HttpStatusCode.TooManyRequests)]
    public async Task WhenRateLimited_ReturnsNoFindings(HttpStatusCode statusCode)
    {
        var (analyzer, _) = Build(apiResponse: () => new HttpResponseMessage(statusCode));
        var result = await analyzer.AnalyzeAsync(MakeContext("npm", "lodash", "4.17.21"));
        result.Findings.Should().BeEmpty();
    }

    [Fact]
    public async Task WhenApiThrows_ReturnsNoFindings()
    {
        var (analyzer, _) = Build(apiResponse: () => throw new HttpRequestException("network failure"));
        var result = await analyzer.AnalyzeAsync(MakeContext("npm", "lodash", "4.17.21"));
        result.Findings.Should().BeEmpty();
    }

    // ─── Caching ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task Result_IsCachedAfterFirstCall()
    {
        var cache = Substitute.For<IKeyValueCache>();
        cache.GetAsync<OssfCacheResult>(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns((CacheEntry<OssfCacheResult>?)null);

        var (analyzer, _) = Build(
            apiResponse: () => OkJson(DirectoryListingJson(["MAL-2024-1"])),
            rawResponse: () => OkJson(OsvJson("MAL-2024-1", "evil-pkg", ["1.0.0"], "malware")),
            cache: cache);

        await analyzer.AnalyzeAsync(MakeContext("npm", "evil-pkg", "1.0.0"));

        await cache.Received(1).SetAsync(
            Arg.Any<string>(),
            Arg.Is<OssfCacheResult>(r => r.InDatabase),
            Arg.Any<TimeSpan>(),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task WhenCacheHit_DoesNotCallApi()
    {
        var cached = new OssfCacheResult
        {
            InDatabase = true,
            Reports =
            [
                new OsvReport
                {
                    Id = "MAL-2024-cached",
                    Summary = "cached malware",
                    Affected = [new OsvAffected { Versions = ["1.0.0"] }]
                }
            ]
        };

        var cache = Substitute.For<IKeyValueCache>();
        cache.GetAsync<OssfCacheResult>(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(new CacheEntry<OssfCacheResult>(cached, DateTimeOffset.UtcNow.AddHours(1)));

        var (analyzer, getRequests) = Build(cache: cache);
        var result = await analyzer.AnalyzeAsync(MakeContext("npm", "evil-pkg", "1.0.0"));

        getRequests().Should().BeEmpty("API should not be called on a cache hit");
        result.Findings.Should().HaveCount(1);
        result.Findings[0].Should().BeOfType<MalwareFinding>()
            .Which.IndicatorId.Should().Be("MAL-2024-cached");
    }

    [Fact]
    public async Task CacheKey_IncludesEcosystemAndPackageName()
    {
        var cache = Substitute.For<IKeyValueCache>();
        cache.GetAsync<OssfCacheResult>(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns((CacheEntry<OssfCacheResult>?)null);

        var (analyzer, _) = Build(
            apiResponse: () => new HttpResponseMessage(HttpStatusCode.NotFound),
            cache: cache);

        await analyzer.AnalyzeAsync(MakeContext("npm", "lodash", "4.17.21"));

        await cache.Received().GetAsync<OssfCacheResult>(
            Arg.Is<string>(k => k.Contains("npm") && k.Contains("lodash")),
            Arg.Any<CancellationToken>());
    }

    // ─── Helpers ─────────────────────────────────────────────────────────────

    private static (OssfMaliciousPackagesAnalyzer analyzer, Func<IReadOnlyList<HttpRequestMessage>> getRequests)
        Build(
            bool enabled = true,
            Func<HttpResponseMessage>? apiResponse = null,
            Func<HttpResponseMessage>? rawResponse = null,
            IKeyValueCache? cache = null)
    {
        var captured = new List<HttpRequestMessage>();

        var handler = new CapturingHandler(req =>
        {
            lock (captured) captured.Add(req);

            if (req.RequestUri?.Host == "api.github.com")
                return Task.FromResult(apiResponse?.Invoke() ?? new HttpResponseMessage(HttpStatusCode.NotFound));

            // raw.githubusercontent.com calls
            return Task.FromResult(rawResponse?.Invoke() ?? OkJson(OsvJson("MAL-2024-default", "pkg", [], "default")));
        });

        var factory = Substitute.For<IHttpClientFactory>();
        factory.CreateClient("ossf-malicious-packages").Returns(new HttpClient(handler)
        {
            BaseAddress = null
        });

        var opts = Options.Create(new OssfMaliciousPackagesOptions
        {
            Enabled = enabled,
            GitHubApiUrl = "https://api.github.com",
            GitHubRawUrl = "https://raw.githubusercontent.com",
            CacheTtlMinutes = 60
        });

        var analyzer = new OssfMaliciousPackagesAnalyzer(
            cache ?? Substitute.For<IKeyValueCache>(),
            factory,
            opts,
            NullLogger<OssfMaliciousPackagesAnalyzer>.Instance);

        return (analyzer, () => { lock (captured) return [.. captured]; });
    }

    private static AnalysisContext MakeContext(string ecosystem, string name, string? version) =>
        new(ecosystem, name, version, null, new Dictionary<string, string>());

    private static HttpResponseMessage OkJson(string json) =>
        new(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };

    private static string DirectoryListingJson(IEnumerable<string> reportIds) =>
        "[" + string.Join(",", reportIds.Select(id => $$"""{"name":"{{id}}","type":"dir"}""")) + "]";

    private static string OsvJson(string id, string packageName, IEnumerable<string> versions, string summary)
    {
        var versionArray = "[" + string.Join(",", versions.Select(v => $"\"{v}\"")) + "]";
        return $$"""
            {
              "id": "{{id}}",
              "summary": "{{summary}}",
              "details": "{{summary}}",
              "affected": [
                {
                  "package": { "ecosystem": "npm", "name": "{{packageName}}" },
                  "versions": {{versionArray}}
                }
              ],
              "references": []
            }
            """;
    }

    private sealed class CapturingHandler(Func<HttpRequestMessage, Task<HttpResponseMessage>> send)
        : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage req, CancellationToken ct)
            => send(req);
    }
}
