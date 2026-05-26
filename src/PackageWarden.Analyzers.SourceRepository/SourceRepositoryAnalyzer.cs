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

using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using PackageWarden.Core.Domain;
using PackageWarden.Core.Interfaces;

namespace PackageWarden.Analyzers.SourceRepository;

public class SourceRepositoryAnalyzer : IPackageAnalyzer
{
    public string Name => "SourceRepository";

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNameCaseInsensitive = true
    };

    // Matches github.com/{owner}/{repo} anywhere in a URL string.
    // Repo segment allows dots (e.g. Newtonsoft.Json); .git suffix is stripped in code.
    private static readonly Regex GitHubPattern = new(
        @"github\.com[/:](?<owner>[^/:@\s]+)/(?<repo>[^/:@\s?#""']+)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private readonly IKeyValueCache _cache;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly SourceRepositoryOptions _options;
    private readonly ILogger<SourceRepositoryAnalyzer> _logger;

    public SourceRepositoryAnalyzer(
        IKeyValueCache cache,
        IHttpClientFactory httpClientFactory,
        IOptions<SourceRepositoryOptions> opts,
        ILogger<SourceRepositoryAnalyzer> logger)
    {
        _cache = cache;
        _httpClientFactory = httpClientFactory;
        _options = opts.Value;
        _logger = logger;
    }

    public async Task<AnalyzerResult> AnalyzeAsync(AnalysisContext context, CancellationToken ct = default)
    {
        if (!_options.Enabled) return new AnalyzerResult(Name, []);
        if (string.IsNullOrEmpty(context.PackageVersion)) return new AnalyzerResult(Name, []);

        var packageId = $"{context.Ecosystem}:{context.PackageName}";

        var repoUrl = await FetchSourceRepositoryUrlAsync(context, ct);
        if (repoUrl is null)
        {
            return new AnalyzerResult(Name, [MediumFinding(packageId, repoUrl,
                "Unable to determine source code repository")]);
        }

        var githubInfo = ParseGitHubUrl(repoUrl);
        if (githubInfo is null)
        {
            return new AnalyzerResult(Name, [MediumFinding(packageId, repoUrl,
                "Source code repository is not hosted on GitHub; releases cannot be verified")]);
        }

        var (owner, repo) = githubInfo.Value;
        var repoPageUrl = $"https://github.com/{owner}/{repo}";

        var releases = await FetchGitHubReleasesAsync(owner, repo, ct);
        if (releases is null)
        {
            return new AnalyzerResult(Name, [MediumFinding(packageId, repoPageUrl,
                "Unable to fetch releases from GitHub")]);
        }

        if (releases.Any(tag => MatchesVersion(tag, context.PackageVersion!, context.PackageName)))
        {
            return new AnalyzerResult(Name, [new SourceRepositoryFinding
            {
                PackageIdentifier = packageId,
                RepositoryUrl = $"{repoPageUrl}/releases",
                Severity = Severity.Info,
                Summary = $"Version {context.PackageVersion} verified on GitHub releases"
            }]);
        }

        // No matching release — fall back to checking git tags
        var tags = await FetchGitHubTagsAsync(owner, repo, ct);
        if (tags is null)
        {
            return new AnalyzerResult(Name, [MediumFinding(packageId, repoPageUrl,
                "Unable to fetch tags from GitHub")]);
        }

        if (tags.Any(tag => MatchesVersion(tag, context.PackageVersion!, context.PackageName)))
        {
            return new AnalyzerResult(Name, [new SourceRepositoryFinding
            {
                PackageIdentifier = packageId,
                RepositoryUrl = $"{repoPageUrl}/tags",
                Severity = Severity.Info,
                Summary = $"Version {context.PackageVersion} verified on GitHub tags"
            }]);
        }

        return new AnalyzerResult(Name, [CriticalFinding(packageId, $"{repoPageUrl}/releases",
            $"No GitHub release or tag matches version {context.PackageVersion}")]);
    }

    private async Task<string?> FetchSourceRepositoryUrlAsync(AnalysisContext context, CancellationToken ct)
    {
        // NuGet uses a version-specific nuspec, so the version is part of the cache key
        var cacheKey = context.Ecosystem.Equals("nuget", StringComparison.OrdinalIgnoreCase)
            ? $"srcrepo:registry:{context.Ecosystem}:{context.PackageName}:{context.PackageVersion}"
            : $"srcrepo:registry:{context.Ecosystem}:{context.PackageName}";

        var cached = await _cache.GetAsync<string>(cacheKey, ct);
        if (cached is not null)
            return cached.Value;

        var url = await FetchFromRegistryAsync(context, ct);

        // Only cache successful lookups; null means a transient failure or missing metadata,
        // and we want the next request to retry rather than serve a stale miss.
        if (url is not null)
            await _cache.SetAsync(cacheKey, url, TimeSpan.FromMinutes(_options.RegistryCacheTtlMinutes), ct);

        return url;
    }

    private async Task<string?> FetchFromRegistryAsync(AnalysisContext context, CancellationToken ct)
    {
        try
        {
            return context.Ecosystem.ToLowerInvariant() switch
            {
                "npm"     => await FetchNpmRepoUrlAsync(context.PackageName, ct),
                "pypi"    => await FetchPyPiRepoUrlAsync(context.PackageName, ct),
                "cargo"   => await FetchCargoRepoUrlAsync(context.PackageName, ct),
                "gem"     => await FetchGemRepoUrlAsync(context.PackageName, ct),
                "golang"  => ExtractGolangRepoUrl(context.PackageName),
                "nuget"   => await FetchNuGetRepoUrlAsync(context.PackageName, context.PackageVersion!, ct),
                _ => null
            };
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "SourceRepository: failed to fetch registry info for {Ecosystem}/{Package}",
                context.Ecosystem, context.PackageName);
            return null;
        }
    }

    private async Task<string?> FetchNpmRepoUrlAsync(string packageName, CancellationToken ct)
    {
        var http = _httpClientFactory.CreateClient("sourcerepo");
        var info = await http.GetFromJsonAsync<NpmPackageInfo>(
            $"https://registry.npmjs.org/{Uri.EscapeDataString(packageName)}", JsonOpts, ct);
        return info?.Repository?.Url;
    }

    private async Task<string?> FetchPyPiRepoUrlAsync(string packageName, CancellationToken ct)
    {
        var http = _httpClientFactory.CreateClient("sourcerepo");
        var info = await http.GetFromJsonAsync<PyPiPackageInfo>(
            $"https://pypi.org/pypi/{Uri.EscapeDataString(packageName)}/json", JsonOpts, ct);
        var urls = info?.Info?.ProjectUrls;
        if (urls is not null)
        {
            // PyPI packages use varying key casing (e.g. "Source" vs "source")
            var ci = new Dictionary<string, string>(urls, StringComparer.OrdinalIgnoreCase);
            foreach (var key in new[] { "Source Code", "Source", "Repository", "Code", "Homepage" })
                if (ci.TryGetValue(key, out var u) && !string.IsNullOrWhiteSpace(u))
                    return u;
        }
        return info?.Info?.HomePage;
    }

    private async Task<string?> FetchCargoRepoUrlAsync(string packageName, CancellationToken ct)
    {
        var http = _httpClientFactory.CreateClient("sourcerepo");
        // crates.io requires a User-Agent; the HTTP client is pre-configured with one
        var info = await http.GetFromJsonAsync<CargoPackageInfo>(
            $"https://crates.io/api/v1/crates/{Uri.EscapeDataString(packageName)}", JsonOpts, ct);
        return info?.Crate?.Repository;
    }

    private async Task<string?> FetchGemRepoUrlAsync(string packageName, CancellationToken ct)
    {
        var http = _httpClientFactory.CreateClient("sourcerepo");
        var info = await http.GetFromJsonAsync<GemPackageInfo>(
            $"https://rubygems.org/api/v1/gems/{Uri.EscapeDataString(packageName)}.json", JsonOpts, ct);
        return info?.SourceCodeUri ?? info?.HomepageUri;
    }

    private static string? ExtractGolangRepoUrl(string modulePath)
    {
        // golang module paths beginning with github.com encode the repo in the first 3 segments
        if (!modulePath.StartsWith("github.com/", StringComparison.OrdinalIgnoreCase))
            return null;

        var parts = modulePath.Split('/');
        if (parts.Length < 3) return null;

        return $"https://{parts[0]}/{parts[1]}/{parts[2]}";
    }

    private async Task<string?> FetchNuGetRepoUrlAsync(string packageName, string version, CancellationToken ct)
    {
        // The flat-container nuspec is the most reliable source for <repository url> and <projectUrl>.
        // The registration API omits the repository field for most packages.
        var http = _httpClientFactory.CreateClient("sourcerepo");
        var id = packageName.ToLowerInvariant();
        var url = $"https://api.nuget.org/v3-flatcontainer/{Uri.EscapeDataString(id)}/{Uri.EscapeDataString(version)}/{Uri.EscapeDataString(id)}.nuspec";

        var response = await http.GetAsync(url, ct);
        response.EnsureSuccessStatusCode();

        await using var stream = await response.Content.ReadAsStreamAsync(ct);
        var doc = await XDocument.LoadAsync(stream, LoadOptions.None, ct);
        var ns = doc.Root?.Name.Namespace ?? XNamespace.None;
        var meta = doc.Root?.Element(ns + "metadata");

        // <repository url="..." /> is the canonical source; fall back to <projectUrl>
        var repoUrl = meta?.Element(ns + "repository")?.Attribute("url")?.Value;
        if (!string.IsNullOrWhiteSpace(repoUrl)) return repoUrl;

        return meta?.Element(ns + "projectUrl")?.Value;
    }

    private async Task<List<string>?> FetchGitHubReleasesAsync(string owner, string repo, CancellationToken ct)
    {
        var cacheKey = $"srcrepo:releases:{owner}/{repo}";
        var cached = await _cache.GetAsync<List<string>>(cacheKey, ct);
        if (cached is not null)
            return cached.Value;

        try
        {
            var http = _httpClientFactory.CreateClient("sourcerepo-github");
            var releases = await http.GetFromJsonAsync<List<GitHubRelease>>(
                $"https://api.github.com/repos/{owner}/{repo}/releases?per_page=100",
                JsonOpts, ct);

            var tags = releases?.Select(r => r.TagName ?? "").Where(t => t.Length > 0).ToList() ?? [];
            await _cache.SetAsync(cacheKey, tags, TimeSpan.FromMinutes(_options.ReleaseCacheTtlMinutes), ct);
            return tags;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "SourceRepository: failed to fetch GitHub releases for {Owner}/{Repo}", owner, repo);
            return null;
        }
    }

    private async Task<List<string>?> FetchGitHubTagsAsync(string owner, string repo, CancellationToken ct)
    {
        var cacheKey = $"srcrepo:tags:{owner}/{repo}";
        var cached = await _cache.GetAsync<List<string>>(cacheKey, ct);
        if (cached is not null)
            return cached.Value;

        try
        {
            var http = _httpClientFactory.CreateClient("sourcerepo-github");
            var tags = await http.GetFromJsonAsync<List<GitHubTag>>(
                $"https://api.github.com/repos/{owner}/{repo}/tags?per_page=100",
                JsonOpts, ct);

            var names = tags?.Select(t => t.Name ?? "").Where(n => n.Length > 0).ToList() ?? [];
            await _cache.SetAsync(cacheKey, names, TimeSpan.FromMinutes(_options.ReleaseCacheTtlMinutes), ct);
            return names;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "SourceRepository: failed to fetch GitHub tags for {Owner}/{Repo}", owner, repo);
            return null;
        }
    }

    public static (string Owner, string Repo)? ParseGitHubUrl(string url)
    {
        var m = GitHubPattern.Match(url);
        if (!m.Success) return null;

        var owner = m.Groups["owner"].Value;
        // Strip .git suffix if present
        var repo = m.Groups["repo"].Value.TrimEnd('/');
        if (repo.EndsWith(".git", StringComparison.OrdinalIgnoreCase))
            repo = repo[..^4];

        return (owner, repo);
    }

    public static bool MatchesVersion(string tagName, string version, string packageName)
    {
        // Common tag formats: v1.2.3, 1.2.3, pkg-v1.2.3, pkg/v1.2.3, pkg@v1.2.3
        var candidates = new[]
        {
            version,
            $"v{version}",
            $"{packageName}-{version}",
            $"{packageName}-v{version}",
            $"{packageName}@{version}",
            $"{packageName}@v{version}",
            $"{packageName}/{version}",
            $"{packageName}/v{version}",
        };
        return candidates.Any(c => string.Equals(tagName, c, StringComparison.OrdinalIgnoreCase));
    }

    private SourceRepositoryFinding MediumFinding(string packageId, string? repoUrl, string summary) =>
        new()
        {
            PackageIdentifier = packageId,
            RepositoryUrl = repoUrl,
            Severity = Severity.Medium,
            Summary = summary
        };

    private SourceRepositoryFinding CriticalFinding(string packageId, string? repoUrl, string summary) =>
        new()
        {
            PackageIdentifier = packageId,
            RepositoryUrl = repoUrl,
            Severity = Severity.Critical,
            Summary = summary
        };
}
