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

using System.Runtime.InteropServices;
using Microsoft.Extensions.Options;
using PackageWarden.Analyzers.OpenSourceMalware;
using PackageWarden.Analyzers.OsvDev;
using PackageWarden.Analyzers.SourceRepository;
using PackageWarden.Core.Domain;
using PackageWarden.Core.Extensions;
using PackageWarden.Core.Interfaces;
using PackageWarden.Core.Policy;
using PackageWarden.Host;
using PackageWarden.Kv.Directory;
using PackageWarden.Proxy.Cargo;
using PackageWarden.Proxy.Gem;
using PackageWarden.Proxy.Golang;
using PackageWarden.Proxy.Maven;
using PackageWarden.Proxy.Npm;
using PackageWarden.Proxy.NuGet;
using PackageWarden.Proxy.PyPI;
using PackageWarden.Store.Sqlite;

// Resolve data directory from PW_DATA_DIR env var or platform default, then seed
// appsettings.json and policy.yaml into it on first run.
var dataDir = ResolveDataDir();
Directory.CreateDirectory(dataDir);

var appSettingsPath = Path.Combine(dataDir, "appsettings.json");
if (!File.Exists(appSettingsPath))
{
    using var res = typeof(Program).Assembly
        .GetManifestResourceStream("PackageWarden.Host.appsettings.json");
    if (res is not null)
    {
        var template = new StreamReader(res).ReadToEnd();
        File.WriteAllText(appSettingsPath,
            template.Replace("__DATA_DIR__", dataDir.Replace('\\', '/')));
    }
}

var policyPath = Path.Combine(dataDir, "policy.yaml");
if (!File.Exists(policyPath))
{
    using var res = typeof(Program).Assembly
        .GetManifestResourceStream("PackageWarden.Host.policy.yaml");
    if (res is not null)
    {
        using var dest = File.Create(policyPath);
        res.CopyTo(dest);
    }
}

var builder = WebApplication.CreateBuilder(new WebApplicationOptions
{
    Args = args,
    ContentRootPath = dataDir
});

builder.Services.Configure<PackageWardenOptions>(
    builder.Configuration.GetSection("PackageWarden"));

// Configure SQLite state store
builder.Services.Configure<SqliteStateStoreOptions>(opts =>
{
    var pw = builder.Configuration.GetSection("PackageWarden:StateStore:Sqlite");
    opts.DatabasePath = pw["DatabasePath"] ?? "package-warden.db";
});
builder.Services.AddStateStore<SqliteStateStore>();

// Configure directory KV store
builder.Services.Configure<DirectoryKeyValueStoreOptions>(opts =>
{
    opts.RootPath = builder.Configuration["PackageWarden:KeyValueStore:Directory:RootPath"] ?? "data/kv-store";
});
builder.Services.AddKeyValueStore<DirectoryKeyValueStore>();

// Configure directory KV cache
builder.Services.Configure<DirectoryKeyValueCacheOptions>(opts =>
{
    opts.RootPath = builder.Configuration["PackageWarden:KeyValueCache:Directory:RootPath"] ?? "data/kv-cache";
    opts.EvictionIntervalMinutes = int.TryParse(
        builder.Configuration["PackageWarden:KeyValueCache:EvictionIntervalMinutes"], out var ei) ? ei : 15;
});
builder.Services.AddKeyValueCache<DirectoryKeyValueCache>();
builder.Services.AddHostedService<CacheEvictionService>();
builder.Services.AddHostedService<PackageManagerCacheClearService>();

// Configure OsvDev analyzer
builder.Services.Configure<OsvDevOptions>(
    builder.Configuration.GetSection("PackageWarden:Analyzers:OsvDev"));
builder.Services.AddPackageAnalyzer<OsvDevAnalyzer>();

// Configure OpenSourceMalware analyzer
builder.Services.Configure<OpenSourceMalwareOptions>(
    builder.Configuration.GetSection("PackageWarden:Analyzers:OpenSourceMalware"));
builder.Services.AddPackageAnalyzer<OpenSourceMalwareAnalyzer>();

// Configure SourceRepository analyzer
builder.Services.Configure<SourceRepositoryOptions>(
    builder.Configuration.GetSection("PackageWarden:Analyzers:SourceRepository"));
builder.Services.AddPackageAnalyzer<SourceRepositoryAnalyzer>();

// Configure proxy options
builder.Services.Configure<NpmProxyOptions>(
    builder.Configuration.GetSection("PackageWarden:Proxies:Npm"));
builder.Services.Configure<NuGetProxyOptions>(
    builder.Configuration.GetSection("PackageWarden:Proxies:NuGet"));
builder.Services.Configure<PyPIProxyOptions>(
    builder.Configuration.GetSection("PackageWarden:Proxies:PyPI"));
builder.Services.Configure<MavenProxyOptions>(
    builder.Configuration.GetSection("PackageWarden:Proxies:Maven"));
builder.Services.Configure<CargoProxyOptions>(
    builder.Configuration.GetSection("PackageWarden:Proxies:Cargo"));
builder.Services.Configure<GemProxyOptions>(
    builder.Configuration.GetSection("PackageWarden:Proxies:Gem"));
builder.Services.Configure<GolangProxyOptions>(
    builder.Configuration.GetSection("PackageWarden:Proxies:Golang"));

// Policy engine — path resolved at startup so test overrides via IOptions take effect
builder.Services.AddSingleton<IRiskScorer>(sp =>
{
    var opts = sp.GetRequiredService<IOptions<PackageWardenOptions>>().Value;
    var env = sp.GetRequiredService<IHostEnvironment>();
    var path = Path.IsPathRooted(opts.Policies.FilePath)
        ? opts.Policies.FilePath
        : Path.GetFullPath(opts.Policies.FilePath, env.ContentRootPath);
    return new RiskScorer(LoadPolicyFile(path).Scoring);
});

builder.Services.AddSingleton<IPolicyEngine>(sp =>
{
    var opts = sp.GetRequiredService<IOptions<PackageWardenOptions>>().Value;
    var env = sp.GetRequiredService<IHostEnvironment>();
    var path = Path.IsPathRooted(opts.Policies.FilePath)
        ? opts.Policies.FilePath
        : Path.GetFullPath(opts.Policies.FilePath, env.ContentRootPath);
    return new PolicyEngine(LoadPolicyFile(path).Policies);
});

// HTTP clients
builder.Services.AddHttpClient("upstream")
    .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler
    {
        AllowAutoRedirect = true,
        AutomaticDecompression = System.Net.DecompressionMethods.All
    });

builder.Services.AddHttpClient("osv")
    .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler());

builder.Services.AddHttpClient("opensourcemalware")
    .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler());

builder.Services.AddHttpClient("sourcerepo", client =>
{
    // crates.io requires a descriptive User-Agent
    client.DefaultRequestHeaders.UserAgent.ParseAdd("PackageWarden/1.0 (package-security-proxy)");
}).ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler
{
    AutomaticDecompression = System.Net.DecompressionMethods.All
});

builder.Services.AddHttpClient("sourcerepo-github", client =>
{
    client.DefaultRequestHeaders.UserAgent.ParseAdd("PackageWarden/1.0 (package-security-proxy)");
    client.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json");
    client.DefaultRequestHeaders.Add("X-GitHub-Api-Version", "2022-11-28");
    var token = builder.Configuration["PackageWarden:Analyzers:SourceRepository:GitHubToken"];
    if (!string.IsNullOrWhiteSpace(token))
        client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
});

// Proxy pipeline
builder.Services.AddProxyPipeline();

// Register server paths as singleton (resolved lazily after build)
builder.Services.AddSingleton<ServerPaths>(sp =>
{
    var opts = sp.GetRequiredService<IOptions<PackageWardenOptions>>().Value;
    var env = sp.GetRequiredService<IHostEnvironment>();
    var root = env.ContentRootPath;
    var appSettingsPath = Path.GetFullPath("appsettings.json", root);
    var policyFilePath = Path.IsPathRooted(opts.Policies.FilePath)
        ? opts.Policies.FilePath
        : Path.GetFullPath(opts.Policies.FilePath, root);
    var rawDbPath = opts.StateStore.Sqlite.DatabasePath;
    var absoluteDbPath = Path.IsPathRooted(rawDbPath) ? rawDbPath : Path.GetFullPath(rawDbPath, root);
    var dataDirectory = Path.GetDirectoryName(absoluteDbPath)!;
    return new ServerPaths(appSettingsPath, policyFilePath, dataDirectory);
});

var app = builder.Build();

// Log server paths at startup
var serverPaths = app.Services.GetRequiredService<ServerPaths>();
var startupLogger = app.Logger;
startupLogger.LogInformation("appsettings.json path: {AppSettingsPath}", serverPaths.AppSettingsPath);
startupLogger.LogInformation("policy.yaml path: {PolicyFilePath}", serverPaths.PolicyFilePath);
startupLogger.LogInformation("Data directory: {DataDirectory}", serverPaths.DataDirectory);

// UI redirect
app.MapGet("/", () => Results.Redirect("/ui"));

// Static UI
app.UseStaticFiles();

// Register management API
app.MapManagementApi();

// Register ecosystem proxies
var npmOpts = app.Services.GetRequiredService<IOptions<NpmProxyOptions>>().Value;
var nugetOpts = app.Services.GetRequiredService<IOptions<NuGetProxyOptions>>().Value;
var pypiOpts = app.Services.GetRequiredService<IOptions<PyPIProxyOptions>>().Value;
var mavenOpts = app.Services.GetRequiredService<IOptions<MavenProxyOptions>>().Value;
var cargoOpts = app.Services.GetRequiredService<IOptions<CargoProxyOptions>>().Value;
var gemOpts = app.Services.GetRequiredService<IOptions<GemProxyOptions>>().Value;
var golangOpts = app.Services.GetRequiredService<IOptions<GolangProxyOptions>>().Value;

if (npmOpts.Enabled) app.MapNpmProxy();
if (nugetOpts.Enabled) app.MapNuGetProxy();
if (pypiOpts.Enabled) app.MapPyPIProxy();
if (mavenOpts.Enabled) app.MapMavenProxy();
if (cargoOpts.Enabled) app.MapCargoProxy();
if (gemOpts.Enabled) app.MapGemProxy();
if (golangOpts.Enabled) app.MapGolangProxy();

// UI static assets
app.MapGet("/ui/styles.css", () => Results.Content(ReadUiAsset("styles.css"), "text/css"));
app.MapGet("/ui/styles-detail.css", () => Results.Content(ReadUiAsset("styles-detail.css"), "text/css"));

// UI pages
app.MapGet("/ui", () => Results.Content(ReadUiAsset("dashboard.html"), "text/html"));
app.MapGet("/ui/requests", () => Results.Content(ReadUiAsset("requests.html"), "text/html"));
app.MapGet("/ui/requests/{id:guid}", async (Guid id, IStateStore store) =>
{
    var req = await store.GetRequestAsync(id);
    if (req is null) return Results.NotFound();
    PackageException? exception = req.Blocked && req.Findings.Count > 0
        ? await store.GetActiveExceptionAsync(req.Ecosystem, req.PackageName, req.PackageVersion)
        : null;
    return Results.Content(RequestDetailHtml(req, exception), "text/html");
});
app.MapGet("/ui/exceptions", () => Results.Content(ReadUiAsset("exceptions.html"), "text/html"));
app.MapGet("/ui/server-info", (ServerPaths paths) => Results.Content(ServerInfoHtml(paths), "text/html"));

app.Run();

static string ResolveDataDir()
{
    var envDir = Environment.GetEnvironmentVariable("PW_DATA_DIR");
    if (!string.IsNullOrEmpty(envDir))
        return Path.GetFullPath(envDir);

    if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        return Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "PackageWarden");

    if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        return Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            "Library", "Application Support", "PackageWarden");

    // Linux: honour XDG_DATA_HOME, otherwise ~/.local/share
    var xdg = Environment.GetEnvironmentVariable("XDG_DATA_HOME");
    return !string.IsNullOrEmpty(xdg)
        ? Path.Combine(xdg, "package-warden")
        : Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            ".local", "share", "package-warden");
}

static PackageWarden.Core.Policy.PolicyFile LoadPolicyFile(string path)
{
    if (File.Exists(path))
        return PolicyFileLoader.Load(path);

    // Return empty policy file (allow everything) if no file exists
    return new PackageWarden.Core.Policy.PolicyFile();
}

static string ReadUiAsset(string name)
{
    using var stream = typeof(Program).Assembly
        .GetManifestResourceStream($"PackageWarden.Host.UiAssets.{name}");
    if (stream is null) throw new InvalidOperationException($"UI asset not found: {name}");
    return new StreamReader(stream).ReadToEnd();
}

static string ServerInfoHtml(ServerPaths paths) =>
    ReadUiAsset("server-info.html")
        .Replace("{{APP_SETTINGS_PATH}}", System.Net.WebUtility.HtmlEncode(paths.AppSettingsPath))
        .Replace("{{POLICY_FILE_PATH}}", System.Net.WebUtility.HtmlEncode(paths.PolicyFilePath))
        .Replace("{{DATA_DIRECTORY}}", System.Net.WebUtility.HtmlEncode(paths.DataDirectory));

static string RequestDetailHtml(ProxyRequest req, PackageException? existingException = null)
{
    static string H(string? s) => System.Net.WebUtility.HtmlEncode(s ?? "");
    static string Badge(Severity s) => s switch
    {
        Severity.Critical => """<span class="badge badge-critical">Critical</span>""",
        Severity.High => """<span class="badge badge-high">High</span>""",
        Severity.Medium => """<span class="badge badge-medium">Medium</span>""",
        Severity.Low => """<span class="badge badge-low">Low</span>""",
        _ => """<span class="badge badge-info">Info</span>"""
    };

    var version = req.PackageVersion != null ? $" @ {H(req.PackageVersion)}" : "";
    var durationMs = (long)req.Duration.TotalMilliseconds;
    var timestamp = req.Timestamp.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss zzz");

    var blockModeText = req.BlockMode switch
    {
        PolicyBlockMode.Hard => "Hard Block",
        PolicyBlockMode.Threshold => $"Threshold: {req.MatchedCount}/{req.Threshold} findings",
        PolicyBlockMode.Score => $"Score: {req.RiskScore?.TotalScore:F1} exceeded {req.RiskScoreThreshold:F1}",
        _ => ""
    };
    var blockSuffix = blockModeText.Length > 0 ? $""" <span class="block-mode">({H(blockModeText)})</span>""" : "";
    var statusBannerHtml = req.Blocked
        ? $"""<div class="status-banner status-blocked">&#x26d4; Blocked &mdash; Policy: <strong>{H(req.BlockReason ?? "(none)")}</strong>{blockSuffix}</div>"""
        : """<div class="status-banner status-allowed">&#x2713; Allowed &mdash; this request passed all policy checks</div>""";

    var sb = new System.Text.StringBuilder();

    var vulns = req.Findings.OfType<VulnerabilityFinding>().ToList();
    if (vulns.Count > 0)
    {
        sb.Append($"""<div class="section"><h3>Vulnerabilities ({vulns.Count})</h3>""");
        foreach (var v in vulns)
        {
            var aliasText = v.Aliases is { Length: > 0 }
                ? $"""<span class="alias"> &middot; {H(string.Join(", ", v.Aliases))}</span>"""
                : "";
            sb.Append($"""<div class="card"><div class="card-header">{Badge(v.Severity)} <span class="card-title">{H(v.VulnerabilityId)}</span>{aliasText}</div>""");
            sb.Append($"""<p class="card-summary">{H(v.Summary)}</p><dl class="finding-detail">""");
            if (v.CvssScore.HasValue) sb.Append($"<dt>CVSS Score</dt><dd>{v.CvssScore:F1}</dd>");
            if (v.AffectedVersionRange != null) sb.Append($"<dt>Affected</dt><dd>{H(v.AffectedVersionRange)}</dd>");
            if (v.FixedVersion != null) sb.Append($"<dt>Fixed in</dt><dd>{H(v.FixedVersion)}</dd>");
            if (v.Reference != null) sb.Append($"""<dt>Reference</dt><dd><a class="ref-link" href="{H(v.Reference)}" target="_blank" rel="noopener">{H(v.Reference)}</a></dd>""");
            sb.Append("</dl></div>");
        }
        sb.Append("</div>");
    }

    var licenses = req.Findings.OfType<LicenseFinding>().ToList();
    if (licenses.Count > 0)
    {
        sb.Append($"""<div class="section"><h3>Licenses ({licenses.Count})</h3>""");
        foreach (var l in licenses)
        {
            sb.Append($"""<div class="card"><div class="card-header">{Badge(l.Severity)} <span class="card-title">{H(l.SpdxId)}</span> <span class="card-subtitle">{H(l.LicenseName)}</span></div>""");
            sb.Append($"""<p class="card-summary">{H(l.Summary)}</p>""");
            if (l.Reference != null)
                sb.Append($"""<dl class="finding-detail"><dt>Reference</dt><dd><a class="ref-link" href="{H(l.Reference)}" target="_blank" rel="noopener">{H(l.Reference)}</a></dd></dl>""");
            sb.Append("</div>");
        }
        sb.Append("</div>");
    }

    var malwares = req.Findings.OfType<MalwareFinding>().ToList();
    if (malwares.Count > 0)
    {
        sb.Append($"""<div class="section"><h3>Malware ({malwares.Count})</h3>""");
        foreach (var m in malwares)
        {
            sb.Append($"""<div class="card"><div class="card-header">{Badge(m.Severity)} <span class="card-title">{H(m.IndicatorId)}</span> <span class="card-subtitle">{H(m.IndicatorType)}</span></div>""");
            sb.Append($"""<p class="card-summary">{H(m.Summary)}</p>""");
            if (m.Reference != null)
                sb.Append($"""<dl class="finding-detail"><dt>Reference</dt><dd><a class="ref-link" href="{H(m.Reference)}" target="_blank" rel="noopener">{H(m.Reference)}</a></dd></dl>""");
            sb.Append("</div>");
        }
        sb.Append("</div>");
    }

    var depConfusions = req.Findings.OfType<DependencyConfusionFinding>().ToList();
    if (depConfusions.Count > 0)
    {
        sb.Append($"""<div class="section"><h3>Dependency Confusion ({depConfusions.Count})</h3>""");
        foreach (var d in depConfusions)
        {
            var ns = d.Namespace != null ? $""" <span class="card-subtitle">{H(d.Namespace)}</span>""" : "";
            sb.Append($"""<div class="card"><div class="card-header">{Badge(d.Severity)} <span class="card-title">{H(d.PackageName)}</span>{ns}</div>""");
            sb.Append($"""<p class="card-summary">{H(d.Summary)}</p></div>""");
        }
        sb.Append("</div>");
    }

    var sourceRepos = req.Findings.OfType<SourceRepositoryFinding>().ToList();
    if (sourceRepos.Count > 0)
    {
        sb.Append($"""<div class="section"><h3>Source Repository ({sourceRepos.Count})</h3>""");
        foreach (var sr in sourceRepos)
        {
            sb.Append($"""<div class="card"><div class="card-header">{Badge(sr.Severity)} <span class="card-title">{H(sr.PackageIdentifier)}</span></div>""");
            sb.Append($"""<p class="card-summary">{H(sr.Summary)}</p>""");
            if (sr.RepositoryUrl != null)
                sb.Append($"""<dl class="finding-detail"><dt>Repository</dt><dd><a class="ref-link" href="{H(sr.RepositoryUrl)}" target="_blank" rel="noopener">{H(sr.RepositoryUrl)}</a></dd></dl>""");
            sb.Append("</div>");
        }
        sb.Append("</div>");
    }

    var healthChecks = req.Findings.OfType<HealthCheckFinding>().ToList();
    if (healthChecks.Count > 0)
    {
        sb.Append($"""<div class="section"><h3>Health Checks ({healthChecks.Count})</h3>""");
        foreach (var hc in healthChecks)
        {
            sb.Append($"""<div class="card"><div class="card-header">{Badge(hc.Severity)} <span class="card-title">{H(hc.Source)}</span></div>""");
            sb.Append($"""<p class="card-summary">{H(hc.Summary)}</p>""");
            if (hc.Reference != null)
                sb.Append($"""<dl class="finding-detail"><dt>Reference</dt><dd><a class="ref-link" href="{H(hc.Reference)}" target="_blank" rel="noopener">{H(hc.Reference)}</a></dd></dl>""");
            sb.Append("</div>");
        }
        sb.Append("</div>");
    }

    var findingsHtml = sb.ToString();
    var versionRow = req.PackageVersion != null ? $"<tr><th>Version</th><td>{H(req.PackageVersion)}</td></tr>" : "";
    var riskScoreRow = req.RiskScore != null ? $"<tr><th>Risk Score</th><td>{req.RiskScore.TotalScore:F1}</td></tr>" : "";
    var policyRow = req.BlockReason != null ? $"<tr><th>Policy</th><td>{H(req.BlockReason)}</td></tr>" : "";

    // Exception panel — only shown for blocked requests with findings
    string exceptionPanelHtml;
    if (!req.Blocked || req.Findings.Count == 0)
    {
        exceptionPanelHtml = "";
    }
    else if (existingException is not null)
    {
        var grantedDate = existingException.GrantedAt.ToLocalTime().ToString("yyyy-MM-dd HH:mm");
        var notesHtml = existingException.Notes != null
            ? $"<p class=\"exc-notes\"><em>{H(existingException.Notes)}</em></p>"
            : "";
        var findingList = string.Join(", ", existingException.FindingIds.Select(id =>
        {
            var sep = id.IndexOf(':');
            return sep > 0 ? H(id[(sep + 1)..]) : H(id);
        }));
        var excId = existingException.ExceptionId;
        exceptionPanelHtml = $$"""
            <div class="exc-panel exc-active">
              <div class="exc-header">
                <span class="exc-badge">Exception Active</span>
                <strong>This package is currently excepted from policy checks</strong>
              </div>
              <p>Granted {{H(grantedDate)}}. Future downloads will be allowed unless new findings are discovered.</p>
              {{notesHtml}}
              <p class="exc-findings">Findings at grant time: <span class="exc-ids">{{(findingList.Length > 0 ? findingList : "none")}}</span></p>
              <button class="exc-revoke-btn" onclick="revokeException('{{excId}}')">Revoke Exception</button>
            </div>
            <script>
            async function revokeException(id) {
              if (!confirm('Revoke this exception? Future downloads of this package will be subject to policy checks again.')) return;
              const r = await fetch('/api/v1/exceptions/' + id, { method: 'DELETE' });
              if (r.ok) location.reload();
              else alert('Failed to revoke exception. Please try again.');
            }
            </script>
            """;
    }
    else
    {
        var requestIdJs = H(req.RequestId.ToString());
        exceptionPanelHtml = $$"""
            <div class="exc-panel exc-none">
              <div class="exc-header"><strong>Grant Exception</strong></div>
              <p>Allow this package to bypass policy checks. The exception will be automatically invalidated if new security findings are discovered.</p>
              <div id="exc-form">
                <textarea id="exc-notes" placeholder="Reason for granting this exception (optional)..." rows="2"></textarea>
                <button class="exc-grant-btn" onclick="grantException()">Grant Exception</button>
              </div>
              <div id="exc-result" style="display:none"></div>
            </div>
            <script>
            async function grantException() {
              const notes = document.getElementById('exc-notes').value.trim();
              const r = await fetch('/api/v1/exceptions', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ requestId: '{{requestIdJs}}', notes: notes || null })
              });
              if (r.ok) {
                document.getElementById('exc-form').style.display = 'none';
                const el = document.getElementById('exc-result');
                el.style.display = 'block';
                el.innerHTML = '<p class="exc-success">&#x2713; Exception granted. Future downloads will be allowed unless new findings are discovered.</p><p><a href="/ui/exceptions">View all exceptions &rarr;</a></p>';
              } else {
                alert('Failed to grant exception. Please try again.');
              }
            }
            </script>
            """;
    }

    var content = $"""
        <a class="back" href="/ui/requests">&larr; Request Log</a>
        <div class="page-header">
          <h2>{H(req.Ecosystem)} / {H(req.PackageName)}{version}</h2>
          <div class="meta">{H(timestamp)} &middot; {H(req.ClientIp)} &middot; {durationMs}ms</div>
        </div>
        {statusBannerHtml}
        {exceptionPanelHtml}
        {findingsHtml}
        <div class="section">
          <h3>Request Details</h3>
          <table class="info-table">
            <tbody>
              <tr><th>Request ID</th><td>{H(req.RequestId.ToString())}</td></tr>
              <tr><th>Timestamp</th><td>{H(req.Timestamp.ToString("O"))}</td></tr>
              <tr><th>Ecosystem</th><td>{H(req.Ecosystem)}</td></tr>
              <tr><th>Package</th><td>{H(req.PackageName)}</td></tr>
              {versionRow}
              <tr><th>Client IP</th><td>{H(req.ClientIp)}</td></tr>
              <tr><th>Duration</th><td>{durationMs}ms</td></tr>
              <tr><th>Upstream URL</th><td>{H(req.UpstreamUrl)}</td></tr>
              {riskScoreRow}
              {policyRow}
            </tbody>
          </table>
        </div>
        """;

    return ReadUiAsset("request-detail.html")
        .Replace("{{TITLE}}", $"{H(req.PackageName)} &mdash; Package Warden")
        .Replace("{{CONTENT}}", content);
}

// Makes Program accessible for WebApplicationFactory in integration tests
public partial class Program { }