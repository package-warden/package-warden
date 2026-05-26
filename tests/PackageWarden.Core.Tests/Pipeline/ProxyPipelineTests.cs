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
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using NSubstitute.ExceptionExtensions;
using PackageWarden.Core.Domain;
using PackageWarden.Core.Interfaces;
using PackageWarden.Core.Pipeline;

namespace PackageWarden.Core.Tests.Pipeline;

public class ProxyPipelineTests
{
    private sealed class TestHttpMessageHandler(
        Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken) => send(request, cancellationToken);
    }

    private sealed class ThrowingHttpMessageHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
            => throw new HttpRequestException("Connection refused");
    }

    private static readonly PackageRiskScore EmptyScore = new(0, []);
    private static readonly PolicyDecision AllowDecision =
        new(false, null, null, null, null, null, EmptyScore);

    private static DefaultHttpContext MakeHttpContext()
    {
        var ctx = new DefaultHttpContext();
        ctx.Response.Body = new MemoryStream();
        return ctx;
    }

    private static ProxyPipelineRequest MakeRequest(
        HttpContext httpContext,
        bool evaluatePolicy = true,
        string upstream = "http://registry.test/pkg.tgz")
        => new("npm", "test-pkg", "1.0.0", upstream, httpContext, evaluatePolicy);

    private static ProxyPipeline BuildPipeline(
        IStateStore? stateStore = null,
        IEnumerable<IPackageAnalyzer>? analyzers = null,
        IFindingAggregator? aggregator = null,
        IRiskScorer? scorer = null,
        IPolicyEngine? policyEngine = null,
        IHttpClientFactory? httpClientFactory = null)
    {
        var sa = stateStore ?? Substitute.For<IStateStore>();
        var agg = aggregator ?? DefaultAggregator([]);
        var sc = scorer ?? DefaultScorer();
        var pe = policyEngine ?? DefaultPolicyEngine(AllowDecision);
        var hcf = httpClientFactory ?? DefaultHttpClientFactory(HttpStatusCode.OK, Array.Empty<byte>());
        return new ProxyPipeline(sa, Substitute.For<IKeyValueCache>(), analyzers ?? [],
            agg, sc, pe, hcf, NullLogger<ProxyPipeline>.Instance);
    }

    private static IFindingAggregator DefaultAggregator(IReadOnlyList<Finding> findings)
    {
        var agg = Substitute.For<IFindingAggregator>();
        agg.Aggregate(Arg.Any<IReadOnlyList<AnalyzerResult>>()).Returns(findings);
        return agg;
    }

    private static IRiskScorer DefaultScorer(PackageRiskScore? score = null)
    {
        var sc = Substitute.For<IRiskScorer>();
        sc.Score(Arg.Any<IReadOnlyList<Finding>>()).Returns(score ?? EmptyScore);
        return sc;
    }

    private static IPolicyEngine DefaultPolicyEngine(PolicyDecision decision)
    {
        var pe = Substitute.For<IPolicyEngine>();
        pe.EvaluateAsync(
            Arg.Any<IReadOnlyList<Finding>>(),
            Arg.Any<PackageRiskScore>(),
            Arg.Any<CancellationToken>()).Returns(decision);
        return pe;
    }

    private static IHttpClientFactory DefaultHttpClientFactory(HttpStatusCode status, byte[] content)
    {
        var handler = new TestHttpMessageHandler((_, _) =>
            Task.FromResult(new HttpResponseMessage(status)
            {
                Content = new ByteArrayContent(content)
            }));
        var hcf = Substitute.For<IHttpClientFactory>();
        hcf.CreateClient("upstream").Returns(new HttpClient(handler));
        return hcf;
    }

    // ---- Pass-through ----

    [Fact]
    public async Task PassThrough_EvaluatePolicyFalse_StreamsUpstreamDirectly()
    {
        var responseBytes = "pkg-bytes"u8.ToArray();
        var httpContext = MakeHttpContext();

        var pipeline = BuildPipeline(
            httpClientFactory: DefaultHttpClientFactory(HttpStatusCode.OK, responseBytes));

        await pipeline.HandleAsync(MakeRequest(httpContext, evaluatePolicy: false));

        httpContext.Response.StatusCode.Should().Be(200);
        httpContext.Response.Body.Seek(0, SeekOrigin.Begin);
        var body = await new MemoryStream().CopyFromAsync(httpContext.Response.Body);
        body.Should().BeEquivalentTo(responseBytes);
    }

    // ---- Upstream failures ----

    [Fact]
    public async Task UpstreamThrows_Returns502AndRecordsRequest()
    {
        var stateStore = Substitute.For<IStateStore>();
        var throwingHandler = new ThrowingHttpMessageHandler();
        var hcf = Substitute.For<IHttpClientFactory>();
        hcf.CreateClient("upstream").Returns(new HttpClient(throwingHandler));

        var httpContext = MakeHttpContext();
        var pipeline = BuildPipeline(stateStore: stateStore, httpClientFactory: hcf);

        await pipeline.HandleAsync(MakeRequest(httpContext));

        httpContext.Response.StatusCode.Should().Be(502);
        await stateStore.Received(1).RecordRequestAsync(
            Arg.Is<ProxyRequest>(r => r.Blocked && r.BlockReason == "UpstreamUnavailable"),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task UpstreamNonSuccess_ProxiesStatusCode()
    {
        var stateStore = Substitute.For<IStateStore>();
        var httpContext = MakeHttpContext();

        var pipeline = BuildPipeline(
            stateStore: stateStore,
            httpClientFactory: DefaultHttpClientFactory(HttpStatusCode.NotFound, Array.Empty<byte>()));

        await pipeline.HandleAsync(MakeRequest(httpContext));

        httpContext.Response.StatusCode.Should().Be(404);
        await stateStore.DidNotReceive().RecordRequestAsync(Arg.Any<ProxyRequest>(), Arg.Any<CancellationToken>());
    }

    // ---- Policy allow/block ----

    [Fact]
    public async Task PolicyAllows_Returns200WithContentAndRecordsRequest()
    {
        var contentBytes = "tarball"u8.ToArray();
        var stateStore = Substitute.For<IStateStore>();
        var httpContext = MakeHttpContext();

        var pipeline = BuildPipeline(
            stateStore: stateStore,
            httpClientFactory: DefaultHttpClientFactory(HttpStatusCode.OK, contentBytes));

        await pipeline.HandleAsync(MakeRequest(httpContext));

        httpContext.Response.StatusCode.Should().Be(200);
        httpContext.Response.Body.Seek(0, SeekOrigin.Begin);
        var written = new byte[contentBytes.Length];
        _ = await httpContext.Response.Body.ReadAsync(written);
        written.Should().Equal(contentBytes);
        await stateStore.Received(1).RecordRequestAsync(
            Arg.Is<ProxyRequest>(r => !r.Blocked),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task PolicyBlocks_Returns403AndRecordsRequest()
    {
        var stateStore = Substitute.For<IStateStore>();
        var httpContext = MakeHttpContext();
        var blockDecision = new PolicyDecision(true, PolicyBlockMode.Hard, "block-all", 1, null, null, EmptyScore);

        var pipeline = BuildPipeline(
            stateStore: stateStore,
            policyEngine: DefaultPolicyEngine(blockDecision),
            httpClientFactory: DefaultHttpClientFactory(HttpStatusCode.OK, Array.Empty<byte>()));

        await pipeline.HandleAsync(MakeRequest(httpContext));

        httpContext.Response.StatusCode.Should().Be(403);
        await stateStore.Received(1).RecordRequestAsync(
            Arg.Is<ProxyRequest>(r => r.Blocked && r.BlockReason == "block-all"),
            Arg.Any<CancellationToken>());
    }

    // ---- Exception enforcement ----

    [Fact]
    public async Task ActiveException_SubsetFindings_BypassesPolicyEngine()
    {
        var vuln = new VulnerabilityFinding { VulnerabilityId = "CVE-2024-1", Severity = Severity.High, Summary = "v" };
        var exception = new PackageException
        {
            ExceptionId = Guid.NewGuid(),
            Ecosystem = "npm",
            PackageName = "test-pkg",
            PackageVersion = "1.0.0",
            GrantedAt = DateTimeOffset.UtcNow,
            FindingIds = ["Vulnerability:CVE-2024-1"]
        };

        var stateStore = Substitute.For<IStateStore>();
        stateStore.GetActiveExceptionAsync("npm", "test-pkg", "1.0.0", Arg.Any<CancellationToken>())
            .Returns(exception);

        var policyEngine = DefaultPolicyEngine(AllowDecision);
        var httpContext = MakeHttpContext();

        var pipeline = BuildPipeline(
            stateStore: stateStore,
            aggregator: DefaultAggregator([vuln]),
            policyEngine: policyEngine,
            httpClientFactory: DefaultHttpClientFactory(HttpStatusCode.OK, "data"u8.ToArray()));

        await pipeline.HandleAsync(MakeRequest(httpContext));

        httpContext.Response.StatusCode.Should().Be(200);
        await policyEngine.DidNotReceive().EvaluateAsync(
            Arg.Any<IReadOnlyList<Finding>>(),
            Arg.Any<PackageRiskScore>(),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task ActiveException_NewFindings_ProceedsToPolicyAndBlocks()
    {
        var knownVuln = new VulnerabilityFinding { VulnerabilityId = "CVE-2024-1", Severity = Severity.High, Summary = "v1" };
        var newVuln = new VulnerabilityFinding { VulnerabilityId = "CVE-2024-2", Severity = Severity.Critical, Summary = "v2" };

        var exception = new PackageException
        {
            ExceptionId = Guid.NewGuid(),
            Ecosystem = "npm",
            PackageName = "test-pkg",
            PackageVersion = "1.0.0",
            GrantedAt = DateTimeOffset.UtcNow,
            FindingIds = ["Vulnerability:CVE-2024-1"]
        };

        var stateStore = Substitute.For<IStateStore>();
        stateStore.GetActiveExceptionAsync("npm", "test-pkg", "1.0.0", Arg.Any<CancellationToken>())
            .Returns(exception);

        var blockDecision = new PolicyDecision(true, PolicyBlockMode.Hard, "block-all", 2, null, null, EmptyScore);
        var httpContext = MakeHttpContext();

        var pipeline = BuildPipeline(
            stateStore: stateStore,
            aggregator: DefaultAggregator([knownVuln, newVuln]),
            policyEngine: DefaultPolicyEngine(blockDecision),
            httpClientFactory: DefaultHttpClientFactory(HttpStatusCode.OK, Array.Empty<byte>()));

        await pipeline.HandleAsync(MakeRequest(httpContext));

        httpContext.Response.StatusCode.Should().Be(403);
    }

    // ---- Analyzer fault tolerance ----

    [Fact]
    public async Task AnalyzerThrows_PipelineContinuesAndResponds200()
    {
        var throwingAnalyzer = Substitute.For<IPackageAnalyzer>();
        throwingAnalyzer.Name.Returns("FaultyAnalyzer");
        throwingAnalyzer
            .AnalyzeAsync(Arg.Any<AnalysisContext>(), Arg.Any<CancellationToken>())
            .ThrowsAsync(new InvalidOperationException("analyzer exploded"));

        var httpContext = MakeHttpContext();

        var pipeline = BuildPipeline(
            analyzers: [throwingAnalyzer],
            httpClientFactory: DefaultHttpClientFactory(HttpStatusCode.OK, "data"u8.ToArray()));

        await pipeline.HandleAsync(MakeRequest(httpContext));

        httpContext.Response.StatusCode.Should().Be(200);
    }
}

file static class StreamExtensions
{
    public static async Task<byte[]> CopyFromAsync(this MemoryStream dest, Stream source)
    {
        await source.CopyToAsync(dest);
        return dest.ToArray();
    }
}
