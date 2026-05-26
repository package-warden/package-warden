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
using System.Text.Json;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using PackageWarden.Analyzers.SourceRepository;
using PackageWarden.Core.Domain;
using PackageWarden.Core.Interfaces;

namespace PackageWarden.Analyzers.SourceRepository.Tests;

public class SourceRepositoryAnalyzerTests
{
    // ─── ParseGitHubUrl ──────────────────────────────────────────────────────

    [Theory]
    [InlineData("https://github.com/owner/repo", "owner", "repo")]
    [InlineData("https://github.com/owner/repo.git", "owner", "repo")]
    [InlineData("git+https://github.com/owner/repo.git", "owner", "repo")]
    [InlineData("git://github.com/owner/repo.git", "owner", "repo")]
    [InlineData("git+ssh://git@github.com/owner/repo.git", "owner", "repo")]
    [InlineData("github.com/owner/repo", "owner", "repo")]
    [InlineData("https://github.com/JamesNK/Newtonsoft.Json", "JamesNK", "Newtonsoft.Json")]
    [InlineData("https://github.com/JamesNK/Newtonsoft.Json.git", "JamesNK", "Newtonsoft.Json")]
    public void ParseGitHubUrl_RecognisesVariousFormats(string url, string expectedOwner, string expectedRepo)
    {
        var result = SourceRepositoryAnalyzer.ParseGitHubUrl(url);

        result.Should().NotBeNull();
        result!.Value.Owner.Should().Be(expectedOwner);
        result!.Value.Repo.Should().Be(expectedRepo);
    }

    [Theory]
    [InlineData("https://gitlab.com/owner/repo")]
    [InlineData("https://bitbucket.org/owner/repo")]
    [InlineData("https://example.com/code")]
    public void ParseGitHubUrl_ReturnsNull_ForNonGitHub(string url)
    {
        SourceRepositoryAnalyzer.ParseGitHubUrl(url).Should().BeNull();
    }

    // ─── MatchesVersion ──────────────────────────────────────────────────────

    [Theory]
    [InlineData("v1.2.3", "1.2.3", "mylib")]
    [InlineData("1.2.3", "1.2.3", "mylib")]
    [InlineData("mylib-v1.2.3", "1.2.3", "mylib")]
    [InlineData("mylib-1.2.3", "1.2.3", "mylib")]
    [InlineData("mylib@v1.2.3", "1.2.3", "mylib")]
    [InlineData("mylib@1.2.3", "1.2.3", "mylib")]
    [InlineData("mylib/v1.2.3", "1.2.3", "mylib")]
    public void MatchesVersion_ReturnsTrueForKnownFormats(string tag, string version, string packageName)
    {
        SourceRepositoryAnalyzer.MatchesVersion(tag, version, packageName).Should().BeTrue();
    }

    [Theory]
    [InlineData("v2.0.0", "1.2.3", "mylib")]
    [InlineData("other-v1.2.3", "1.2.3", "mylib")]
    [InlineData("release-1.2.3", "1.2.3", "mylib")]
    public void MatchesVersion_ReturnsFalseForNonMatchingTags(string tag, string version, string packageName)
    {
        SourceRepositoryAnalyzer.MatchesVersion(tag, version, packageName).Should().BeFalse();
    }

    // ─── AnalyzeAsync — disabled ──────────────────────────────────────────────

    [Fact]
    public async Task AnalyzeAsync_ReturnsEmpty_WhenDisabled()
    {
        var (analyzer, _) = BuildAnalyzer(enabled: false, registryJson: null, releasesJson: null);

        var result = await analyzer.AnalyzeAsync(NpmContext("lodash", "4.17.21"));

        result.Findings.Should().BeEmpty();
    }

    [Fact]
    public async Task AnalyzeAsync_ReturnsEmpty_WhenNoVersion()
    {
        var (analyzer, _) = BuildAnalyzer(enabled: true, registryJson: null, releasesJson: null);

        var result = await analyzer.AnalyzeAsync(NpmContext("lodash", version: null));

        result.Findings.Should().BeEmpty();
    }

    // ─── AnalyzeAsync — medium (no repo) ────────────────────────────────────

    [Fact]
    public async Task AnalyzeAsync_ReturnsMedium_WhenRegistryReturns404()
    {
        var (analyzer, _) = BuildAnalyzer(enabled: true, registryStatusCode: HttpStatusCode.NotFound,
            registryJson: null, releasesJson: null);

        var result = await analyzer.AnalyzeAsync(NpmContext("nonexistent-pkg", "1.0.0"));

        result.Findings.Should().ContainSingle()
            .Which.Severity.Should().Be(Severity.Medium);
    }

    [Fact]
    public async Task AnalyzeAsync_ReturnsMedium_WhenRepositoryFieldIsNull()
    {
        var (analyzer, _) = BuildAnalyzer(enabled: true,
            registryJson: """{"name":"lodash"}""",
            releasesJson: null);

        var result = await analyzer.AnalyzeAsync(NpmContext("lodash", "4.17.21"));

        result.Findings.Should().ContainSingle()
            .Which.Severity.Should().Be(Severity.Medium);
    }

    // ─── AnalyzeAsync — medium (non-GitHub) ─────────────────────────────────

    [Fact]
    public async Task AnalyzeAsync_ReturnsMedium_WhenRepoIsNotGitHub()
    {
        var (analyzer, _) = BuildAnalyzer(enabled: true,
            registryJson: """{"repository":{"url":"https://gitlab.com/owner/repo"}}""",
            releasesJson: null);

        var result = await analyzer.AnalyzeAsync(NpmContext("mylib", "1.0.0"));

        result.Findings.Should().ContainSingle()
            .Which.Severity.Should().Be(Severity.Medium);
    }

    // ─── AnalyzeAsync — medium (tags API unreachable) ───────────────────────

    [Fact]
    public async Task AnalyzeAsync_ReturnsMedium_WhenReleasesEmptyAndTagsApiFails()
    {
        var (analyzer, _) = BuildAnalyzer(enabled: true,
            registryJson: """{"repository":{"url":"https://github.com/owner/repo"}}""",
            releasesJson: "[]",
            tagsJson: null,
            tagsStatusCode: HttpStatusCode.InternalServerError);

        var result = await analyzer.AnalyzeAsync(NpmContext("mylib", "1.0.0"));

        result.Findings.Should().ContainSingle()
            .Which.Severity.Should().Be(Severity.Medium);
    }

    // ─── AnalyzeAsync — critical (no matching release or tag) ────────────────

    [Fact]
    public async Task AnalyzeAsync_ReturnsCritical_WhenNoReleaseOrTagMatchesVersion()
    {
        var (analyzer, _) = BuildAnalyzer(enabled: true,
            registryJson: """{"repository":{"url":"https://github.com/owner/repo"}}""",
            releasesJson: """[{"tag_name":"v2.0.0"},{"tag_name":"v1.0.0"}]""",
            tagsJson: """[{"name":"v2.0.0"},{"name":"v1.0.0"}]""");

        var result = await analyzer.AnalyzeAsync(NpmContext("mylib", "1.5.0"));

        result.Findings.Should().ContainSingle()
            .Which.Severity.Should().Be(Severity.Critical);
    }

    // ─── AnalyzeAsync — info via tag fallback ────────────────────────────────

    [Fact]
    public async Task AnalyzeAsync_ReturnsInfo_WhenMatchingTagExistsButNoRelease()
    {
        var (analyzer, _) = BuildAnalyzer(enabled: true,
            registryJson: """{"repository":{"url":"https://github.com/owner/repo"}}""",
            releasesJson: """[{"tag_name":"v2.0.0"}]""",
            tagsJson: """[{"name":"v2.0.0"},{"name":"4.17.21"}]""");

        var result = await analyzer.AnalyzeAsync(NpmContext("lodash", "4.17.21"));

        var finding = result.Findings.Should().ContainSingle().Which;
        finding.Severity.Should().Be(Severity.Info);
        finding.Should().BeOfType<SourceRepositoryFinding>();
        finding.Summary.Should().Contain("tags");
    }

    // ─── AnalyzeAsync — clean (matching release found) ───────────────────────

    [Fact]
    public async Task AnalyzeAsync_ReturnsInfoFinding_WhenMatchingReleaseExists()
    {
        var (analyzer, _) = BuildAnalyzer(enabled: true,
            registryJson: """{"repository":{"url":"https://github.com/owner/repo"}}""",
            releasesJson: """[{"tag_name":"v4.17.21"},{"tag_name":"v4.17.20"}]""");

        var result = await analyzer.AnalyzeAsync(NpmContext("lodash", "4.17.21"));

        var finding = result.Findings.Should().ContainSingle().Which;
        finding.Severity.Should().Be(Severity.Info);
        finding.Should().BeOfType<SourceRepositoryFinding>();
    }

    // ─── helpers ─────────────────────────────────────────────────────────────

    private static AnalysisContext NpmContext(string name, string? version) =>
        new("npm", name, version, null, new Dictionary<string, string>());

    private static (SourceRepositoryAnalyzer Analyzer, IKeyValueCache Cache) BuildAnalyzer(
        bool enabled,
        string? registryJson,
        string? releasesJson,
        string? tagsJson = "[]",
        HttpStatusCode registryStatusCode = HttpStatusCode.OK,
        HttpStatusCode tagsStatusCode = HttpStatusCode.OK)
    {
        var cache = Substitute.For<IKeyValueCache>();
        // Default NSubstitute behaviour returns null for reference types — cache always misses

        var factory = Substitute.For<IHttpClientFactory>();

        var registryHandler = new FakeHttpHandler(registryStatusCode,
            registryJson is not null ? new StringContent(registryJson, Encoding.UTF8, "application/json") : null);
        factory.CreateClient("sourcerepo").Returns(new HttpClient(registryHandler));

        var githubHandler = new GitHubFakeHandler(releasesJson, tagsJson, tagsStatusCode);
        factory.CreateClient("sourcerepo-github").Returns(new HttpClient(githubHandler));

        var opts = Options.Create(new SourceRepositoryOptions { Enabled = enabled });
        var analyzer = new SourceRepositoryAnalyzer(cache, factory, opts, NullLogger<SourceRepositoryAnalyzer>.Instance);
        return (analyzer, cache);
    }

    private sealed class FakeHttpHandler(HttpStatusCode status, HttpContent? content) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var response = new HttpResponseMessage(status)
            {
                Content = content ?? new StringContent("{}", Encoding.UTF8, "application/json")
            };
            return Task.FromResult(response);
        }
    }

    private sealed class GitHubFakeHandler(
        string? releasesJson,
        string? tagsJson,
        HttpStatusCode tagsStatusCode = HttpStatusCode.OK) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var url = request.RequestUri?.ToString() ?? "";
            if (url.Contains("/tags"))
            {
                var body = tagsJson is not null
                    ? new StringContent(tagsJson, Encoding.UTF8, "application/json")
                    : new StringContent("[]", Encoding.UTF8, "application/json");
                return Task.FromResult(new HttpResponseMessage(tagsStatusCode) { Content = body });
            }

            // releases
            var releasesBody = new StringContent(
                releasesJson ?? "[]", Encoding.UTF8, "application/json");
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = releasesBody });
        }
    }
}
