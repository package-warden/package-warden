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

using System.Collections.Immutable;
using System.Globalization;
using System.IO.Compression;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using PackageWarden.Core.Domain;
using PackageWarden.Core.Interfaces;

namespace PackageWarden.Analyzers.OsvDev;

public class OsvDevAnalyzer : IPackageAnalyzer
{
    public string Name => "OsvDev";

    private static readonly Dictionary<string, string> EcosystemMap = new(StringComparer.OrdinalIgnoreCase)
    {
        ["npm"] = "npm",
        ["nuget"] = "NuGet",
        ["pypi"] = "PyPI",
        ["maven"] = "Maven",
        ["cargo"] = "crates.io",
        ["gem"] = "RubyGems",
        ["golang"] = "Go"
    };

    private readonly IKeyValueCache _cache;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly OsvDevOptions _options;
    private readonly ILogger<OsvDevAnalyzer> _logger;

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNameCaseInsensitive = true
    };

    public OsvDevAnalyzer(
        IKeyValueCache cache,
        IHttpClientFactory httpClientFactory,
        IOptions<OsvDevOptions> opts,
        ILogger<OsvDevAnalyzer> logger)
    {
        _cache = cache;
        _httpClientFactory = httpClientFactory;
        _options = opts.Value;
        _logger = logger;
    }

    public async Task<AnalyzerResult> AnalyzeAsync(AnalysisContext context, CancellationToken ct = default)
    {
        if (!_options.Enabled) return new AnalyzerResult(Name, []);

        if (!EcosystemMap.TryGetValue(context.Ecosystem, out var osvEcosystem))
        {
            _logger.LogDebug("OsvDev: no ecosystem mapping for {Ecosystem}", context.Ecosystem);
            return new AnalyzerResult(Name, []);
        }

        // NuGet flat-container URLs are always lowercase; OSV lookups are case-sensitive.
        // Extract the canonical ID from the nuspec inside the .nupkg to get the proper casing.
        var packageName = context.Ecosystem.Equals("nuget", StringComparison.OrdinalIgnoreCase)
                          && context.PackageContent is MemoryStream ms
            ? ExtractNuGetPackageId(ms.ToArray()) ?? context.PackageName
            : context.PackageName;

        // Golang module proxy protocol encodes uppercase letters as !lowercase (e.g. BurntSushi -> !burnt!sushi).
        // OSV expects the canonical unescaped module path.
        if (context.Ecosystem.Equals("golang", StringComparison.OrdinalIgnoreCase))
            packageName = DecodeGoModulePath(packageName);

        var cacheKey = $"osv:{context.Ecosystem}:{packageName}:{context.PackageVersion}";
        var cacheTtl = TimeSpan.FromMinutes(_options.CacheTtlMinutes);

        var cached = await _cache.GetAsync<List<OsvVulnerability>>(cacheKey, ct);
        List<OsvVulnerability> vulns;

        if (cached is not null)
        {
            vulns = cached.Value;
        }
        else
        {
            vulns = await FetchVulnerabilitiesAsync(packageName, context.PackageVersion, osvEcosystem, ct);
            await _cache.SetAsync(cacheKey, vulns, cacheTtl, ct);
        }

        var findings = vulns.Select(MapVulnerability).ToList<Finding>();

        if (findings.Count == 0)
            findings.Add(new HealthCheckFinding
            {
                Source = "OSV.dev",
                Severity = Severity.Info,
                Summary = "No known vulnerabilities found on OSV.dev"
            });

        return new AnalyzerResult(Name, findings);
    }

    private async Task<List<OsvVulnerability>> FetchVulnerabilitiesAsync(
        string packageName, string? version, string ecosystem, CancellationToken ct)
    {
        var request = new OsvBatchRequest
        {
            Queries =
            [
                new OsvQuery
                {
                    Version = version,
                    Package = new OsvPackage { Name = packageName, Ecosystem = ecosystem }
                }
            ]
        };

        var http = _httpClientFactory.CreateClient("osv");
        var batchResponse = await http.PostAsJsonAsync($"{_options.ApiUrl}/querybatch", request, JsonOpts, ct);
        batchResponse.EnsureSuccessStatusCode();

        // querybatch only returns IDs — fetch full details (severity, CVSS, affected) per vuln.
        var batchResult = await batchResponse.Content.ReadFromJsonAsync<OsvBatchResponse>(JsonOpts, ct);
        var ids = batchResult?.Results.FirstOrDefault()?.Vulns?.Select(v => v.Id).ToList() ?? [];
        if (ids.Count == 0) return [];

        var detailTasks = ids.Select(id => FetchVulnerabilityAsync(id, http, ct));
        var details = await Task.WhenAll(detailTasks);
        return [.. details.Where(v => v is not null).Cast<OsvVulnerability>()];
    }

    private async Task<OsvVulnerability?> FetchVulnerabilityAsync(string id, HttpClient http, CancellationToken ct)
    {
        try
        {
            var response = await http.GetAsync($"{_options.ApiUrl}/vulns/{id}", ct);
            response.EnsureSuccessStatusCode();
            return await response.Content.ReadFromJsonAsync<OsvVulnerability>(JsonOpts, ct);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "OsvDev: failed to fetch details for {Id}", id);
            return null;
        }
    }

    private static VulnerabilityFinding MapVulnerability(OsvVulnerability vuln)
    {
        var cvssScore = ExtractCvssScore(vuln.Severity);
        var severity = CvssToSeverity(cvssScore);
        var fixedVersion = ExtractFixedVersion(vuln.Affected);
        var reference = vuln.References?.FirstOrDefault(r => r.Type == "WEB")?.Url
                       ?? $"https://osv.dev/vulnerability/{vuln.Id}";

        var aliases = vuln.Aliases?.ToArray() ?? [];
        var cveId = aliases.FirstOrDefault(a => a.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase));

        var props = new Dictionary<string, string> { ["osvId"] = vuln.Id };
        if (cveId is not null) props["cveId"] = cveId;

        return new VulnerabilityFinding
        {
            VulnerabilityId = vuln.Id,
            Aliases = aliases,
            Severity = severity,
            Summary = vuln.Summary ?? vuln.Details ?? $"Vulnerability {vuln.Id}",
            Reference = reference,
            CvssScore = cvssScore,
            FixedVersion = fixedVersion,
            Properties = props.ToImmutableDictionary()
        };
    }

    private static decimal? ExtractCvssScore(List<OsvSeverity>? severities)
    {
        if (severities is null) return null;

        foreach (var s in severities)
        {
            if (s.Score is null) continue;
            var score = ParseCvssScore(s.Score);
            if (score.HasValue) return score;
        }
        return null;
    }

    private static decimal? ParseCvssScore(string scoreString)
    {
        // Plain numeric score
        if (decimal.TryParse(scoreString, NumberStyles.Any, CultureInfo.InvariantCulture, out var direct))
            return direct;

        // CVSS v3.x vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        if (scoreString.StartsWith("CVSS:3", StringComparison.OrdinalIgnoreCase))
            return CalculateCvssV3Score(scoreString);

        return null;
    }

    private static decimal? CalculateCvssV3Score(string vector)
    {
        var metrics = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var part in vector.Split('/').Skip(1))
        {
            var colon = part.IndexOf(':');
            if (colon > 0) metrics[part[..colon]] = part[(colon + 1)..];
        }

        if (!metrics.TryGetValue("AV", out var av) || !metrics.TryGetValue("AC", out var ac) ||
            !metrics.TryGetValue("PR", out var pr) || !metrics.TryGetValue("UI", out var ui) ||
            !metrics.TryGetValue("S",  out var s)  || !metrics.TryGetValue("C",  out var c)  ||
            !metrics.TryGetValue("I",  out var i)  || !metrics.TryGetValue("A",  out var a))
            return null;

        var scopeChanged = s == "C";

        var avW = av switch { "N" => 0.85m, "A" => 0.62m, "L" => 0.55m, "P" => 0.20m, _ => 0m };
        var acW = ac switch { "L" => 0.77m, "H" => 0.44m, _ => 0m };
        var prW = (pr, scopeChanged) switch
        {
            ("N", _)     => 0.85m,
            ("L", false) => 0.62m, ("L", true) => 0.68m,
            ("H", false) => 0.27m, ("H", true) => 0.50m,
            _            => 0m
        };
        var uiW = ui switch { "N" => 0.85m, "R" => 0.62m, _ => 0m };
        var cW  = c  switch { "H" => 0.56m, "L" => 0.22m, _ => 0m };
        var iW  = i  switch { "H" => 0.56m, "L" => 0.22m, _ => 0m };
        var aW  = a  switch { "H" => 0.56m, "L" => 0.22m, _ => 0m };

        var iscBase = 1m - (1m - cW) * (1m - iW) * (1m - aW);
        if (iscBase == 0m) return 0m;

        var isc = scopeChanged
            ? 7.52m * (iscBase - 0.029m) - 3.25m * (decimal)Math.Pow((double)(iscBase - 0.02m), 15)
            : 6.42m * iscBase;

        var exploitability = 8.22m * avW * acW * prW * uiW;
        var raw = scopeChanged
            ? Math.Min(1.08m * (isc + exploitability), 10m)
            : Math.Min(isc + exploitability, 10m);

        return Math.Ceiling(raw * 10m) / 10m;
    }

    private static Severity CvssToSeverity(decimal? cvss) => cvss switch
    {
        >= 9.0m => Severity.Critical,
        >= 7.0m => Severity.High,
        >= 4.0m => Severity.Medium,
        >= 0.1m => Severity.Low,
        _ => Severity.Medium
    };

    private static string? ExtractFixedVersion(List<OsvAffected>? affected)
    {
        return affected?
            .SelectMany(a => a.Ranges ?? [])
            .SelectMany(r => r.Events ?? [])
            .Where(e => e.Fixed is not null)
            .Select(e => e.Fixed)
            .FirstOrDefault();
    }

    // !b -> B, !u -> U per the Go module proxy escaping spec.
    private static string DecodeGoModulePath(string escaped) =>
        Regex.Replace(escaped, @"!([a-z])", m => char.ToUpperInvariant(m.Groups[1].Value[0]).ToString());

    private static string? ExtractNuGetPackageId(byte[] nupkgBytes)
    {
        try
        {
            using var zip = new ZipArchive(new MemoryStream(nupkgBytes), ZipArchiveMode.Read);
            var entry = zip.Entries.FirstOrDefault(e => e.Name.EndsWith(".nuspec", StringComparison.OrdinalIgnoreCase));
            if (entry is null) return null;
            using var stream = entry.Open();
            var doc = XDocument.Load(stream);
            var ns = doc.Root?.Name.Namespace ?? XNamespace.None;
            return doc.Root
                ?.Element(ns + "metadata")
                ?.Element(ns + "id")
                ?.Value;
        }
        catch
        {
            return null;
        }
    }
}