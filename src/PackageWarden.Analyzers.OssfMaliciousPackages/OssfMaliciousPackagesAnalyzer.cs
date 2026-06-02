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
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using PackageWarden.Core.Domain;
using PackageWarden.Core.Interfaces;

namespace PackageWarden.Analyzers.OssfMaliciousPackages;

public class OssfMaliciousPackagesAnalyzer : IPackageAnalyzer
{
    public string Name => "OssfMaliciousPackages";

    private static readonly Dictionary<string, string> EcosystemMap = new(StringComparer.OrdinalIgnoreCase)
    {
        { "npm",    "npm" },
        { "pypi",   "pypi" },
        { "nuget",  "nuget" },
        { "maven",  "maven" },
        { "cargo",  "crates.io" },
        { "gem",    "rubygems" },
        { "golang", "go" }
    };

    private static readonly JsonSerializerOptions JsonOpts = new() { PropertyNameCaseInsensitive = true };

    private readonly IKeyValueCache _cache;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly OssfMaliciousPackagesOptions _options;
    private readonly ILogger<OssfMaliciousPackagesAnalyzer> _logger;

    public OssfMaliciousPackagesAnalyzer(
        IKeyValueCache cache,
        IHttpClientFactory httpClientFactory,
        IOptions<OssfMaliciousPackagesOptions> opts,
        ILogger<OssfMaliciousPackagesAnalyzer> logger)
    {
        _cache = cache;
        _httpClientFactory = httpClientFactory;
        _options = opts.Value;
        _logger = logger;
    }

    public async Task<AnalyzerResult> AnalyzeAsync(AnalysisContext context, CancellationToken ct = default)
    {
        if (!_options.Enabled) return new AnalyzerResult(Name, []);

        if (!EcosystemMap.TryGetValue(context.Ecosystem, out var ossfEcosystem))
        {
            _logger.LogDebug("OssfMaliciousPackages: no support for ecosystem {Ecosystem}", context.Ecosystem);
            return new AnalyzerResult(Name, []);
        }

        var packageName = NormalizePackageName(context.Ecosystem, context.PackageName);
        var cacheKey = $"ossf:{ossfEcosystem}:{packageName}";
        var cacheTtl = TimeSpan.FromMinutes(_options.CacheTtlMinutes);

        var cached = await _cache.GetAsync<OssfCacheResult>(cacheKey, ct);
        OssfCacheResult result;

        if (cached is not null)
        {
            result = cached.Value;
        }
        else
        {
            result = await FetchPackageReportsAsync(ossfEcosystem, packageName, ct);
            await _cache.SetAsync(cacheKey, result, cacheTtl, ct);
        }

        if (!result.InDatabase) return new AnalyzerResult(Name, []);

        var finding = MapToFinding(result, ossfEcosystem, packageName, context.PackageVersion);
        return new AnalyzerResult(Name, [finding]);
    }

    private static string NormalizePackageName(string ecosystem, string name) =>
        ecosystem.Equals("pypi", StringComparison.OrdinalIgnoreCase)
            ? name.ToLowerInvariant().Replace('_', '-')
            : name;

    private async Task<OssfCacheResult> FetchPackageReportsAsync(
        string ossfEcosystem, string packageName, CancellationToken ct)
    {
        try
        {
            var http = _httpClientFactory.CreateClient("ossf-malicious-packages");
            var encodedName = Uri.EscapeDataString(packageName);
            var apiUrl = $"{_options.GitHubApiUrl.TrimEnd('/')}/repos/ossf/malicious-packages/contents/packages/{ossfEcosystem}/{encodedName}";

            using var request = new HttpRequestMessage(HttpMethod.Get, apiUrl);
            request.Headers.Accept.ParseAdd("application/vnd.github+json");
            request.Headers.Add("X-GitHub-Api-Version", "2022-11-28");

            using var response = await http.SendAsync(request, ct);

            if (response.StatusCode == HttpStatusCode.NotFound)
                return new OssfCacheResult { InDatabase = false };

            if (response.StatusCode is HttpStatusCode.Forbidden or HttpStatusCode.TooManyRequests)
            {
                _logger.LogWarning("OssfMaliciousPackages: rate limited checking {Ecosystem}/{Package}", ossfEcosystem, packageName);
                return new OssfCacheResult { InDatabase = false };
            }

            response.EnsureSuccessStatusCode();

            var entries = await response.Content.ReadFromJsonAsync<List<GitHubContentsEntry>>(JsonOpts, ct) ?? [];
            var reportIds = entries
                .Where(e => e.Type == "dir" && e.Name != null)
                .Select(e => e.Name!)
                .ToList();

            if (reportIds.Count == 0)
                return new OssfCacheResult { InDatabase = true, Reports = [] };

            var reports = await FetchReportsAsync(ossfEcosystem, encodedName, reportIds, ct);
            return new OssfCacheResult { InDatabase = true, Reports = reports };
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "OssfMaliciousPackages: failed to check {Ecosystem}/{Package}", ossfEcosystem, packageName);
            return new OssfCacheResult { InDatabase = false };
        }
    }

    private async Task<List<OsvReport>> FetchReportsAsync(
        string ossfEcosystem, string encodedPackageName, List<string> reportIds, CancellationToken ct)
    {
        var http = _httpClientFactory.CreateClient("ossf-malicious-packages");
        var reports = new List<OsvReport>();

        foreach (var reportId in reportIds.Take(10))
        {
            var rawUrl = $"{_options.GitHubRawUrl.TrimEnd('/')}/ossf/malicious-packages/main/packages/{ossfEcosystem}/{encodedPackageName}/{Uri.EscapeDataString(reportId)}/osv.json";
            try
            {
                var report = await http.GetFromJsonAsync<OsvReport>(rawUrl, JsonOpts, ct);
                if (report is not null) reports.Add(report);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "OssfMaliciousPackages: failed to fetch report {ReportId}", reportId);
            }
        }

        return reports;
    }

    private static MalwareFinding MapToFinding(
        OssfCacheResult result, string ossfEcosystem, string packageName, string? requestedVersion)
    {
        var reports = result.Reports ?? [];
        var primaryReport = reports.FirstOrDefault();
        var reportId = primaryReport?.Id ?? packageName;

        var allAffectedVersions = reports
            .SelectMany(r => r.Affected ?? [])
            .SelectMany(a => a.Versions ?? [])
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var summary = BuildSummary(primaryReport, packageName, requestedVersion, allAffectedVersions);
        var reference = $"https://github.com/ossf/malicious-packages/tree/main/packages/{ossfEcosystem}/{Uri.EscapeDataString(packageName)}";

        return new MalwareFinding
        {
            IndicatorId = reportId,
            IndicatorType = "malware",
            Severity = Severity.Critical,
            Summary = summary,
            Reference = reference
        };
    }

    private static string BuildSummary(
        OsvReport? primaryReport, string packageName, string? requestedVersion, List<string> allAffectedVersions)
    {
        if (requestedVersion != null &&
            allAffectedVersions.Contains(requestedVersion, StringComparer.OrdinalIgnoreCase))
        {
            return primaryReport?.Summary
                ?? $"Package {packageName} version {requestedVersion} is listed as malicious in the OSSF Malicious Packages database";
        }

        if (allAffectedVersions.Count > 0)
        {
            var shown = allAffectedVersions.Take(5).ToList();
            var versionList = string.Join(", ", shown);
            var more = allAffectedVersions.Count > 5 ? $" (+{allAffectedVersions.Count - 5} more)" : "";
            var baseSummary = primaryReport?.Summary ?? $"Package {packageName} has been identified as malicious";
            return $"{baseSummary} — confirmed malicious versions: {versionList}{more}";
        }

        return primaryReport?.Summary
            ?? $"Package {packageName} is listed in the OSSF Malicious Packages database";
    }
}
