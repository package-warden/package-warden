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

using System.IO.Compression;
using System.Net;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using PackageWarden.Analyzers.OsvDev;
using PackageWarden.Core.Domain;
using PackageWarden.Core.Interfaces;

namespace PackageWarden.Analyzers.OsvDev.Tests;

public class OsvDevAnalyzerTests
{
    // ─── NuGet canonical name ────────────────────────────────────────────────

    [Fact]
    public async Task NuGet_OsvQuery_UsesCanonicalNameFromNuspec()
    {
        // NuGet flat-container URLs are always lowercase, but OSV is case-sensitive.
        // The canonical ID lives in the .nuspec inside the .nupkg.
        var nupkg = CreateNupkg("Newtonsoft.Json");
        var (analyzer, getLastBody) = BuildAnalyzer();

        await analyzer.AnalyzeAsync(new AnalysisContext(
            Ecosystem: "nuget",
            PackageName: "newtonsoft.json",
            PackageVersion: "9.0.1",
            PackageContent: new MemoryStream(nupkg),
            Metadata: new Dictionary<string, string>()));

        QueryPackageName(getLastBody()).Should().Be("Newtonsoft.Json");
    }

    [Fact]
    public async Task NuGet_OsvQuery_FallsBackToUrlName_WhenContentIsNull()
    {
        var (analyzer, getLastBody) = BuildAnalyzer();

        await analyzer.AnalyzeAsync(new AnalysisContext(
            Ecosystem: "nuget",
            PackageName: "my-package",
            PackageVersion: "1.0.0",
            PackageContent: null,
            Metadata: new Dictionary<string, string>()));

        QueryPackageName(getLastBody()).Should().Be("my-package");
    }

    [Fact]
    public async Task NuGet_OsvQuery_FallsBackToUrlName_WhenContentIsNotValidNupkg()
    {
        var (analyzer, getLastBody) = BuildAnalyzer();

        await analyzer.AnalyzeAsync(new AnalysisContext(
            Ecosystem: "nuget",
            PackageName: "my-package",
            PackageVersion: "1.0.0",
            PackageContent: new MemoryStream([0x00, 0x01, 0x02, 0x03]),
            Metadata: new Dictionary<string, string>()));

        QueryPackageName(getLastBody()).Should().Be("my-package");
    }

    // ─── Golang module path decoding ────────────────────────────────────────

    [Fact]
    public async Task Golang_OsvQuery_DecodesEscapedUppercaseLetters()
    {
        // Go module proxy encodes uppercase as !lowercase: BurntSushi -> !burnt!sushi
        var (analyzer, getLastBody) = BuildAnalyzer();

        await analyzer.AnalyzeAsync(new AnalysisContext(
            Ecosystem: "golang",
            PackageName: "github.com/!burnt!sushi/toml",
            PackageVersion: "v0.4.1",
            PackageContent: null,
            Metadata: new Dictionary<string, string>()));

        QueryPackageName(getLastBody()).Should().Be("github.com/BurntSushi/toml");
    }

    [Fact]
    public async Task Golang_OsvQuery_LeavesAllLowercasePath_Unchanged()
    {
        var (analyzer, getLastBody) = BuildAnalyzer();

        await analyzer.AnalyzeAsync(new AnalysisContext(
            Ecosystem: "golang",
            PackageName: "golang.org/x/net",
            PackageVersion: "v0.10.0",
            PackageContent: null,
            Metadata: new Dictionary<string, string>()));

        QueryPackageName(getLastBody()).Should().Be("golang.org/x/net");
    }

    // ─── Other ecosystems are unaffected ────────────────────────────────────

    [Theory]
    [InlineData("npm",   "lodash",       "4.17.20")]
    [InlineData("pypi",  "requests",     "2.28.0")]
    [InlineData("cargo", "serde",        "1.0.0")]
    [InlineData("gem",   "rails",        "7.0.4")]
    [InlineData("maven", "org.foo:mylib","1.0.0")]
    public async Task OtherEcosystems_OsvQuery_PassesNameThrough_Unchanged(
        string ecosystem, string packageName, string version)
    {
        var (analyzer, getLastBody) = BuildAnalyzer();

        await analyzer.AnalyzeAsync(new AnalysisContext(
            Ecosystem: ecosystem,
            PackageName: packageName,
            PackageVersion: version,
            PackageContent: null,
            Metadata: new Dictionary<string, string>()));

        QueryPackageName(getLastBody()).Should().Be(packageName);
    }

    // ─── querybatch → per-vuln detail fetch ─────────────────────────────────

    [Fact]
    public async Task Analyze_FetchesFullVulnDetails_AfterBatchReturnsIds()
    {
        // The querybatch API only returns IDs; severity/CVSS come from a separate GET per vuln.
        var (analyzer, getRequests) = BuildRoutingAnalyzer(req => Task.FromResult(
            req.RequestUri!.AbsolutePath.EndsWith("/querybatch")
                ? OkJson("""{"results":[{"vulns":[{"id":"GHSA-0001-TEST"}]}]}""")
                : OkJson("""{"id":"GHSA-0001-TEST","severity":[{"type":"CVSS_V3","score":"9.8"}]}""")
        ));

        await analyzer.AnalyzeAsync(MakeContext("npm", "bad-pkg", "1.0.0"));

        var requests = getRequests();
        requests.Should().HaveCount(2);
        requests[0].Method.Should().Be(HttpMethod.Post);
        requests[0].RequestUri!.AbsolutePath.Should().EndWith("/querybatch");
        requests[1].Method.Should().Be(HttpMethod.Get);
        requests[1].RequestUri!.AbsolutePath.Should().EndWith("/vulns/GHSA-0001-TEST");
    }

    [Fact]
    public async Task Analyze_MapsCvssVectorToHighSeverity_WhenVulnDetailHasCvssVector()
    {
        // Regression: querybatch returned sparse records (id only, severity null) which
        // fell back to Medium and never matched the block-high-cves policy.
        // After the fix the per-vuln GET carries the full CVSS vector → High.
        var (analyzer, _) = BuildRoutingAnalyzer(req => Task.FromResult(
            req.RequestUri!.AbsolutePath.EndsWith("/querybatch")
                ? OkJson("""{"results":[{"vulns":[{"id":"GHSA-5crp-9r3c-p9vr"}]}]}""")
                : OkJson("""
                  {
                    "id": "GHSA-5crp-9r3c-p9vr",
                    "aliases": ["CVE-2024-21907"],
                    "summary": "Improper Handling of Exceptional Conditions in Newtonsoft.Json",
                    "references": [{"type":"WEB","url":"https://github.com/advisories/GHSA-5crp-9r3c-p9vr"}],
                    "severity": [{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}],
                    "affected": [{"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"13.0.1"}]}]}]
                  }
                  """)
        ));

        var result = await analyzer.AnalyzeAsync(MakeContext("nuget", "newtonsoft.json", "9.0.1"));

        result.Findings.Should().HaveCount(1);
        var finding = result.Findings[0].Should().BeOfType<VulnerabilityFinding>().Subject;
        finding.VulnerabilityId.Should().Be("GHSA-5crp-9r3c-p9vr");
        finding.Severity.Should().Be(Severity.High);
        finding.CvssScore.Should().Be(7.5m);
        finding.Aliases.Should().Contain("CVE-2024-21907");
        finding.Summary.Should().Contain("Newtonsoft.Json");
        finding.FixedVersion.Should().Be("13.0.1");
        finding.Reference.Should().Contain("GHSA-5crp-9r3c-p9vr");
    }

    [Fact]
    public async Task Analyze_NoDetailFetches_WhenBatchReturnsNoVulns()
    {
        var (analyzer, getRequests) = BuildRoutingAnalyzer(_ =>
            Task.FromResult(OkJson("""{"results":[{}]}""")));

        await analyzer.AnalyzeAsync(MakeContext("npm", "safe-pkg", "1.0.0"));

        var requests = getRequests();
        requests.Should().HaveCount(1, "only querybatch; no per-vuln fetches when there are no matches");
        requests[0].RequestUri!.AbsolutePath.Should().EndWith("/querybatch");
    }

    [Fact]
    public async Task Analyze_FetchesDetailsForEachId_WhenBatchReturnsMultiple()
    {
        var (analyzer, getRequests) = BuildRoutingAnalyzer(req => Task.FromResult(
            req.RequestUri!.AbsolutePath.EndsWith("/querybatch")
                ? OkJson("""{"results":[{"vulns":[{"id":"GHSA-AAAA"},{"id":"GHSA-BBBB"}]}]}""")
                : OkJson("""{"id":"stub","severity":[{"type":"CVSS_V3","score":"9.8"}]}""")
        ));

        var result = await analyzer.AnalyzeAsync(MakeContext("npm", "bad-pkg", "1.0.0"));

        var detailPaths = getRequests().Skip(1).Select(r => r.RequestUri!.AbsolutePath).ToList();
        detailPaths.Should().HaveCount(2);
        detailPaths.Should().Contain(p => p.EndsWith("/GHSA-AAAA"));
        detailPaths.Should().Contain(p => p.EndsWith("/GHSA-BBBB"));
        result.Findings.Should().HaveCount(2);
    }

    [Fact]
    public async Task Analyze_SkipsFailedDetailFetch_ReturnsRemainingFindings()
    {
        var (analyzer, _) = BuildRoutingAnalyzer(req =>
        {
            if (req.RequestUri!.AbsolutePath.EndsWith("/querybatch"))
                return Task.FromResult(OkJson("""{"results":[{"vulns":[{"id":"GHSA-GOOD"},{"id":"GHSA-FAIL"}]}]}"""));
            if (req.RequestUri.AbsolutePath.EndsWith("/GHSA-GOOD"))
                return Task.FromResult(OkJson("""{"id":"GHSA-GOOD","severity":[{"type":"CVSS_V3","score":"9.8"}]}"""));
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.InternalServerError));
        });

        var result = await analyzer.AnalyzeAsync(MakeContext("npm", "mixed-pkg", "1.0.0"));

        result.Findings.Should().HaveCount(1);
        result.Findings[0].Should().BeOfType<VulnerabilityFinding>()
            .Which.VulnerabilityId.Should().Be("GHSA-GOOD");
    }

    // ─── Helpers ────────────────────────────────────────────────────────────

    private static string? QueryPackageName(string? body)
    {
        if (body is null) return null;
        var doc = JsonDocument.Parse(body);
        return doc.RootElement
            .GetProperty("queries")[0]
            .GetProperty("package")
            .GetProperty("name")
            .GetString();
    }

    private static (OsvDevAnalyzer analyzer, Func<string?> getLastBody) BuildAnalyzer()
    {
        string? lastBody = null;

        var handler = new CapturingHandler(async req =>
        {
            lastBody = await req.Content!.ReadAsStringAsync();
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""{"results":[{}]}""", Encoding.UTF8, "application/json")
            };
        });

        var factory = Substitute.For<IHttpClientFactory>();
        factory.CreateClient("osv").Returns(new HttpClient(handler));

        var opts = Options.Create(new OsvDevOptions
        {
            Enabled = true,
            ApiUrl = "https://api.osv.dev/v1",
            CacheTtlMinutes = 60
        });

        var analyzer = new OsvDevAnalyzer(
            Substitute.For<IKeyValueCache>(),
            factory,
            opts,
            NullLogger<OsvDevAnalyzer>.Instance);

        return (analyzer, () => lastBody);
    }

    private static (OsvDevAnalyzer, Func<IReadOnlyList<HttpRequestMessage>>) BuildRoutingAnalyzer(
        Func<HttpRequestMessage, Task<HttpResponseMessage>> route)
    {
        var captured = new List<HttpRequestMessage>();
        var handler = new CapturingHandler(async req =>
        {
            lock (captured) captured.Add(req);
            return await route(req);
        });

        var factory = Substitute.For<IHttpClientFactory>();
        factory.CreateClient("osv").Returns(new HttpClient(handler));

        var opts = Options.Create(new OsvDevOptions
        {
            Enabled = true,
            ApiUrl = "https://api.osv.dev/v1",
            CacheTtlMinutes = 60
        });

        var analyzer = new OsvDevAnalyzer(
            Substitute.For<IKeyValueCache>(),
            factory,
            opts,
            NullLogger<OsvDevAnalyzer>.Instance);

        return (analyzer, () => { lock (captured) return [.. captured]; });
    }

    private static AnalysisContext MakeContext(string ecosystem, string name, string version) =>
        new(ecosystem, name, version, null, new Dictionary<string, string>());

    private static HttpResponseMessage OkJson(string json) =>
        new(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };

    private static byte[] CreateNupkg(string packageId)
    {
        var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            var entry = zip.CreateEntry($"{packageId}.nuspec");
            using var writer = new StreamWriter(entry.Open());
            writer.Write($"""
                <?xml version="1.0" encoding="utf-8"?>
                <package>
                  <metadata>
                    <id>{packageId}</id>
                    <version>1.0.0</version>
                  </metadata>
                </package>
                """);
        }
        return ms.ToArray();
    }

    private sealed class CapturingHandler(Func<HttpRequestMessage, Task<HttpResponseMessage>> send)
        : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage req, CancellationToken ct)
            => send(req);
    }
}
