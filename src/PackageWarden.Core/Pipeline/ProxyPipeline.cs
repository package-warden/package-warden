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

using System.Diagnostics;
using System.Net;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using PackageWarden.Core.Domain;
using PackageWarden.Core.Interfaces;

namespace PackageWarden.Core.Pipeline;

public class ProxyPipeline : IProxyPipeline
{
    private readonly IStateStore _stateStore;
    private readonly IKeyValueCache _cache;
    private readonly IEnumerable<IPackageAnalyzer> _analyzers;
    private readonly IFindingAggregator _aggregator;
    private readonly IRiskScorer _scorer;
    private readonly IPolicyEngine _policyEngine;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<ProxyPipeline> _logger;

    public ProxyPipeline(
        IStateStore stateStore,
        IKeyValueCache cache,
        IEnumerable<IPackageAnalyzer> analyzers,
        IFindingAggregator aggregator,
        IRiskScorer scorer,
        IPolicyEngine policyEngine,
        IHttpClientFactory httpClientFactory,
        ILogger<ProxyPipeline> logger)
    {
        _stateStore = stateStore;
        _cache = cache;
        _analyzers = analyzers;
        _aggregator = aggregator;
        _scorer = scorer;
        _policyEngine = policyEngine;
        _httpClientFactory = httpClientFactory;
        _logger = logger;
    }

    public async Task HandleAsync(ProxyPipelineRequest pipelineReq, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var httpCtx = pipelineReq.HttpContext;
        var clientIp = httpCtx.Connection.RemoteIpAddress?.ToString() ?? "unknown";

        var request = new ProxyRequest
        {
            RequestId = Guid.NewGuid(),
            Timestamp = DateTimeOffset.UtcNow,
            Ecosystem = pipelineReq.Ecosystem,
            PackageName = pipelineReq.PackageName,
            PackageVersion = pipelineReq.PackageVersion,
            UpstreamUrl = pipelineReq.UpstreamUrl,
            ClientIp = clientIp
        };

        try
        {
            var cacheKey = $"upstream:{pipelineReq.Ecosystem}:{pipelineReq.PackageName}:{pipelineReq.PackageVersion}:{pipelineReq.UpstreamUrl.GetHashCode()}";

            // Pass-through requests (no policy evaluation)
            if (!pipelineReq.EvaluatePolicy)
            {
                await StreamUpstreamAsync(httpCtx, pipelineReq.UpstreamUrl, ct);
                return;
            }

            var http = _httpClientFactory.CreateClient("upstream");
            HttpResponseMessage upstreamResponse;

            try
            {
                upstreamResponse = await http.GetAsync(pipelineReq.UpstreamUrl, HttpCompletionOption.ResponseHeadersRead, ct);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Upstream fetch failed for {Url}", pipelineReq.UpstreamUrl);
                request.Blocked = true;
                request.BlockReason = "UpstreamUnavailable";
                request.Duration = sw.Elapsed;
                await _stateStore.RecordRequestAsync(request, ct);
                httpCtx.Response.StatusCode = 502;
                await httpCtx.Response.WriteAsJsonAsync(new { error = "upstream_unavailable", message = "Upstream registry unreachable" }, ct);
                return;
            }

            if (!upstreamResponse.IsSuccessStatusCode)
            {
                httpCtx.Response.StatusCode = (int)upstreamResponse.StatusCode;
                await upstreamResponse.Content.CopyToAsync(httpCtx.Response.Body, ct);
                return;
            }

            // Read content for analysis
            var contentBytes = await upstreamResponse.Content.ReadAsByteArrayAsync(ct);
            var metadata = new Dictionary<string, string>(pipelineReq.Metadata ?? new Dictionary<string, string>());
            var analysisCtx = new AnalysisContext(
                pipelineReq.Ecosystem,
                pipelineReq.PackageName,
                pipelineReq.PackageVersion,
                new MemoryStream(contentBytes),
                metadata);

            // Run analyzers
            var analyzerTasks = _analyzers.Select(async a =>
            {
                try
                {
                    return await a.AnalyzeAsync(analysisCtx, ct);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Analyzer {Name} threw an exception", a.Name);
                    return new AnalyzerResult(a.Name, []);
                }
            });

            var analyzerResults = await Task.WhenAll(analyzerTasks);
            var findings = _aggregator.Aggregate(analyzerResults);

            // Check for an active exception before policy evaluation.
            // An exception applies only when the current finding set is a subset of the
            // finding IDs that were recorded when the exception was granted (no new findings).
            var activeException = await _stateStore.GetActiveExceptionAsync(
                pipelineReq.Ecosystem, pipelineReq.PackageName, pipelineReq.PackageVersion, ct);
            if (activeException is not null)
            {
                var currentIds = findings.Select(f => $"{f.Type}:{f.Id}").ToHashSet();
                if (currentIds.IsSubsetOf(activeException.FindingIds))
                {
                    _logger.LogInformation(
                        "Exception {ExceptionId} applied for {Ecosystem}/{Package}@{Version}; allowing",
                        activeException.ExceptionId, pipelineReq.Ecosystem,
                        pipelineReq.PackageName, pipelineReq.PackageVersion);
                    request.Findings = findings;
                    request.RiskScore = _scorer.Score(findings);
                    request.Duration = sw.Elapsed;
                    await _stateStore.RecordRequestAsync(request, ct);
                    CopyUpstreamHeaders(upstreamResponse, httpCtx.Response);
                    httpCtx.Response.StatusCode = (int)upstreamResponse.StatusCode;
                    await httpCtx.Response.Body.WriteAsync(contentBytes, ct);
                    return;
                }

                _logger.LogInformation(
                    "Exception {ExceptionId} for {Ecosystem}/{Package}@{Version} has new findings; proceeding to policy evaluation",
                    activeException.ExceptionId, pipelineReq.Ecosystem,
                    pipelineReq.PackageName, pipelineReq.PackageVersion);
            }

            var riskScore = _scorer.Score(findings);
            var decision = await _policyEngine.EvaluateAsync(findings, riskScore, ct);

            request.Findings = findings;
            request.RiskScore = riskScore;

            if (decision.IsBlocked)
            {
                request.Blocked = true;
                request.BlockReason = decision.MatchedPolicyName;
                request.BlockMode = decision.BlockMode;
                request.MatchedCount = decision.MatchedCount;
                request.Threshold = decision.Threshold;
                request.RiskScoreThreshold = decision.RiskScoreThreshold;
                request.Duration = sw.Elapsed;

                await _stateStore.RecordRequestAsync(request, ct);

                httpCtx.Response.StatusCode = 403;
                await httpCtx.Response.WriteAsJsonAsync(BuildBlockResponse(request, riskScore), ct);
                return;
            }

            // Serve
            request.Duration = sw.Elapsed;
            await _stateStore.RecordRequestAsync(request, ct);

            CopyUpstreamHeaders(upstreamResponse, httpCtx.Response);
            httpCtx.Response.StatusCode = (int)upstreamResponse.StatusCode;
            await httpCtx.Response.Body.WriteAsync(contentBytes, ct);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unhandled error in proxy pipeline");
            request.Duration = sw.Elapsed;
            if (!httpCtx.Response.HasStarted)
            {
                httpCtx.Response.StatusCode = 500;
            }
        }
    }

    private async Task StreamUpstreamAsync(HttpContext httpCtx, string upstreamUrl, CancellationToken ct)
    {
        var http = _httpClientFactory.CreateClient("upstream");
        try
        {
            var upstream = await http.GetAsync(upstreamUrl, HttpCompletionOption.ResponseHeadersRead, ct);
            CopyUpstreamHeaders(upstream, httpCtx.Response);
            httpCtx.Response.StatusCode = (int)upstream.StatusCode;
            await upstream.Content.CopyToAsync(httpCtx.Response.Body, ct);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Upstream passthrough failed for {Url}", upstreamUrl);
            if (!httpCtx.Response.HasStarted)
            {
                httpCtx.Response.StatusCode = 502;
            }
        }
    }

    private static void CopyUpstreamHeaders(HttpResponseMessage upstream, HttpResponse response)
    {
        var passHeaders = new[] { "Content-Type", "Content-Length", "Last-Modified", "ETag", "Cache-Control" };
        foreach (var header in passHeaders)
        {
            if (upstream.Content.Headers.TryGetValues(header, out var values))
                response.Headers[header] = values.ToArray();
            else if (upstream.Headers.TryGetValues(header, out values))
                response.Headers[header] = values.ToArray();
        }
    }

    private static object BuildBlockResponse(ProxyRequest req, PackageRiskScore riskScore)
    {
        return new
        {
            blocked = true,
            blockMode = req.BlockMode?.ToString(),
            requestId = req.RequestId,
            policy = req.BlockReason,
            matchedCount = req.MatchedCount,
            threshold = req.Threshold,
            riskScoreThreshold = req.RiskScoreThreshold,
            riskScore = new
            {
                total = riskScore.TotalScore,
                byFindingType = riskScore.ByFindingType.Select(ft => new
                {
                    findingType = ft.FindingType.ToString(),
                    score = ft.Score,
                    findings = ft.Findings.Select(sf => BuildFindingResponse(sf.Finding, sf.Score))
                })
            }
        };
    }

    private static object BuildFindingResponse(Finding finding, decimal score)
    {
        return finding switch
        {
            VulnerabilityFinding v => new
            {
                findingType = "Vulnerability",
                id = v.VulnerabilityId,
                aliases = v.Aliases,
                severity = v.Severity.ToString(),
                cvssScore = v.CvssScore,
                score,
                summary = v.Summary,
                reference = v.Reference,
                fixedVersion = v.FixedVersion,
                reportedBy = v.ReportedBy
            } as object,
            LicenseFinding l => new
            {
                findingType = "License",
                id = l.SpdxId,
                severity = l.Severity.ToString(),
                score,
                summary = l.Summary,
                licenseName = l.LicenseName,
                reportedBy = l.ReportedBy
            },
            MalwareFinding m => new
            {
                findingType = "Malware",
                id = m.IndicatorId,
                indicatorType = m.IndicatorType,
                severity = m.Severity.ToString(),
                score,
                summary = m.Summary,
                reportedBy = m.ReportedBy
            },
            DependencyConfusionFinding dc => new
            {
                findingType = "DependencyConfusion",
                id = dc.Id,
                severity = dc.Severity.ToString(),
                score,
                summary = dc.Summary,
                reportedBy = dc.ReportedBy
            },
            _ => new { findingType = finding.Type.ToString(), id = finding.Id, severity = finding.Severity.ToString(), score, summary = finding.Summary }
        };
    }
}