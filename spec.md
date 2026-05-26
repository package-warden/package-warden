# Package Warden - Specification

## Overview

Package Warden is a security-focused package repository proxy. It sits between developer tooling and upstream package registries, intercepting every package request to run configurable security analysis before serving or blocking the response. All requests are recorded regardless of outcome, providing a full audit trail of package consumption across an organization.

The system is designed around three core concerns:

1. **Intercept** - Receive package requests from standard tooling (npm, dotnet, pip, mvn, cargo, etc.) using each ecosystem's native protocol.
2. **Analyse** - Run the package through a policy-driven set of analysis modules that check for vulnerabilities, malware indicators, license violations, dependency confusion, typosquatting, and other risks.
3. **Record and act** - Log every request with its full analysis record; block or allow based on policy; return an appropriate response to the client.

---

## Technology Stack

- **Runtime**: C# / .NET 10
- **Web framework**: ASP.NET Core (minimal APIs + Razor Pages)
- **ORM / DB access**: Microsoft.Data.Sqlite via EF Core
- **DI / configuration**: `Microsoft.Extensions.*` - `IConfiguration`, `IOptions<T>`, hosted services
- **Serialisation**: `System.Text.Json` (primary), `Newtonsoft.Json` where ecosystem SDKs require it
- **Testing**: xUnit + FluentAssertions + Testcontainers (integration) + NSubstitute (mocks)

---

## Project Layout

```
src/
  PackageWarden.Host/              # ASP.NET Core host - wires everything together
  PackageWarden.Core/              # Domain models, interfaces, policy engine, request pipeline
  PackageWarden.Store.Sqlite/      # SQLite implementation of IStateStore
  PackageWarden.Kv.Directory/      # Local-directory implementations of IKeyValueStore and IKeyValueCache
  PackageWarden.Proxy.Npm/         # npm registry proxy
  PackageWarden.Proxy.NuGet/       # NuGet V3 proxy
  PackageWarden.Proxy.PyPI/        # PyPI simple repository proxy
  PackageWarden.Proxy.Maven/       # Maven 2 repository proxy
  PackageWarden.Proxy.Cargo/       # Cargo sparse registry proxy
  PackageWarden.Proxy.Gem/         # RubyGems proxy
  PackageWarden.Proxy.Golang/      # Go module proxy (GOPROXY protocol)
  PackageWarden.Analyzers.OsvDev/  # OSV.dev vulnerability lookup analyzer
  PackageWarden.Ui/                # Razor Pages UI (dashboard + request log)
tests/
  PackageWarden.Core.Tests/
  PackageWarden.Store.Sqlite.Tests/
  PackageWarden.Proxy.Npm.Tests/
  PackageWarden.Proxy.NuGet.Tests/
  ... (mirror of src layout)
```

---

## Extensibility Interfaces

### IStateStore

Persists all requests and analysis records. The SQLite implementation is the initial concrete implementation but any relational or document store can be substituted.

```csharp
public interface IStateStore
{
    Task RecordRequestAsync(ProxyRequest request, CancellationToken ct = default);
    Task<PagedResult<ProxyRequest>> QueryRequestsAsync(RequestQuery query, CancellationToken ct = default);
    Task<ProxyRequest?> GetRequestAsync(Guid requestId, CancellationToken ct = default);
    Task<SystemStats> GetStatsAsync(DateTimeOffset? since = null, CancellationToken ct = default);
}

public record RequestQuery(
    DateTimeOffset? From,
    DateTimeOffset? To,
    string? Ecosystem,         // purl type, e.g. "npm"
    string? PackageName,
    bool? Blocked,
    int Page = 1,
    int PageSize = 50
);
```

**SQLite implementation** (`SqliteStateStore`) uses a single database file at a path configured via `StateStore:Sqlite:DatabasePath`. Schema is created on first run via embedded migration scripts.

**Registration**: `services.AddStateStore<SqliteStateStore>()` - or any other `IStateStore` implementation via the same extension.

---

### IKeyValueStore

A persistent key-value store for durable data that outlives individual requests - such as approved package allowlists, cached policy decisions, or stored upstream registry metadata. This store is **not** expected to have TTL semantics.

```csharp
public interface IKeyValueStore
{
    Task<T?> GetAsync<T>(string key, CancellationToken ct = default);
    Task SetAsync<T>(string key, T value, CancellationToken ct = default);
    Task DeleteAsync(string key, CancellationToken ct = default);
    Task<bool> ExistsAsync(string key, CancellationToken ct = default);
    IAsyncEnumerable<string> ListKeysAsync(string prefix, CancellationToken ct = default);
}
```

**Directory implementation** (`DirectoryKeyValueStore`) serialises values as JSON files under a configured root directory. The key is mapped to a file path by replacing `:` and `/` with the OS path separator and appending `.json`. The root path is configured via `KeyValueStore:Directory:RootPath`.

---

### IKeyValueCache

An ephemeral cache for upstream responses - primarily raw package index responses and package content - to avoid redundant upstream requests. Entries carry a TTL; expired entries are treated as absent.

```csharp
public interface IKeyValueCache
{
    Task<CacheEntry<T>?> GetAsync<T>(string key, CancellationToken ct = default);
    Task SetAsync<T>(string key, T value, TimeSpan ttl, CancellationToken ct = default);
    Task InvalidateAsync(string key, CancellationToken ct = default);
    Task InvalidatePrefixAsync(string prefix, CancellationToken ct = default);
}

public record CacheEntry<T>(T Value, DateTimeOffset ExpiresAt);
```

**Directory implementation** (`DirectoryKeyValueCache`) writes each entry as a JSON file containing both the payload and a `expiresAt` field. Reads that encounter an expired file return `null` and asynchronously delete the file. The root path is configured via `KeyValueCache:Directory:RootPath` and must be **distinct** from the `IKeyValueStore` root to prevent collisions.

A background `CacheEvictionService` (hosted service) periodically sweeps the cache directory and deletes all expired entries on a configurable interval (default: every 15 minutes).

---

## Request Pipeline

Every package request passes through the following pipeline regardless of ecosystem:

```
Client request
  │
  ▼
EcosystemRouter       - routes /v1/proxy/{type}/... to the correct proxy handler
  │
  ▼
RequestInterceptor    - assigns RequestId (GUID), records start time, builds ProxyRequest
  │
  ▼
CacheCheck            - checks IKeyValueCache; on HIT skip to Serve
  │
  ▼
UpstreamFetch         - fetches from upstream registry (with circuit breaker)
  │
  ▼
AnalyzerExecution     - runs all enabled analyzers in parallel; each returns raw findings
  │                     (may include multiple finding types per analyzer)
  ▼
FindingAggregation    - deduplicates findings across analyzers by (FindingType, Id);
  │                     merges metadata; records all contributing analyzer names
  ▼
RiskScoring           - applies scoring config to deduplicated findings;
  │                     produces PackageRiskScore with per-type and per-finding breakdown
  ▼
PolicyEvaluation      - evaluates ordered policies against normalized findings + risk score
  │
  ├─ BLOCKED ───────► BlockResponse (403 with JSON body)
  │
  └─ ALLOWED ───────► CacheStore ──► Serve (pipe upstream bytes to client)
                              │
                              ▼
                       StateStore.RecordRequestAsync (always — both paths)
```

A `ProxyRequest` carries:

```csharp
public record ProxyRequest
{
    public Guid RequestId { get; init; }
    public DateTimeOffset Timestamp { get; init; }
    public string Ecosystem { get; init; }             // purl type
    public string PackageName { get; init; }
    public string? PackageVersion { get; init; }
    public string UpstreamUrl { get; init; }
    public string ClientIp { get; init; }
    public bool Blocked { get; set; }
    public string? BlockReason { get; set; }           // matched policy name
    public PolicyBlockMode? BlockMode { get; set; }
    public IReadOnlyList<Finding> Findings { get; set; } = [];  // deduplicated, post-aggregation
    public PackageRiskScore? RiskScore { get; set; }
    public TimeSpan Duration { get; set; }
}
```

---

## Policy Engine

### Overview

The policy engine operates on a **deduplicated, normalized set of typed findings** assembled from all analyzers. Policies are completely analyzer-agnostic — they express conditions over finding types, severities, and finding-specific fields, not over which analyzer produced a finding. Adding a new vulnerability source requires no policy changes; its findings flow automatically into existing rules.

Three block modes:

- **Hard** (`blockMode: Hard`) — any single finding matching the condition immediately blocks. Zero-tolerance: known malware, a single critical CVE, a prohibited license.
- **Threshold** (`blockMode: Threshold`) — fires when the count of matching findings reaches the configured number. One high-severity CVE is acceptable; three are not.
- **Score** (`blockMode: Score`) — fires when the aggregate risk score exceeds a configured value. Used for holistic risk across multiple signals that don't individually warrant a block.

Every policy is a blocking rule. If no policy fires, the package is allowed.

### Policy as Code

Policies live in `policy.yaml` in the working directory by default. Override via `PackageWarden:Policies:FilePath`. Hot-reload is configurable. The file is intended to be version-controlled alongside the codebase it protects.

### Finding Types

Analyzers produce typed findings. Each type has a natural identifier used for deduplication across multiple analyzers reporting the same underlying issue. When two analyzers both report the same finding, the deduplicated record retains the highest severity and CVSS score, merges properties, and lists all contributing analyzers in `ReportedBy`.

| Finding Type | `Id` field | Deduplicated on |
|---|---|---|
| `Vulnerability` | CVE / GHSA / OSV identifier | `(Vulnerability, vulnerabilityId)`, aliases resolved |
| `License` | SPDX expression (e.g. `GPL-3.0-only`) | `(License, spdxId)` — one entry per unique license regardless of file count |
| `Malware` | Indicator identifier or hash | `(Malware, indicatorId)` |
| `DependencyConfusion` | `{namespace}/{packageName}` | `(DependencyConfusion, id)` |

An analyzer may return findings of multiple types in a single result — e.g. a comprehensive scanner could emit both `Vulnerability` and `License` findings.

### Risk Scoring Configuration

The `scoring:` block in `policy.yaml` controls how findings contribute to the aggregate risk score. Score resolution priority per finding:

1. `Finding.AnalyzerScore` — an explicit override from the analyzer (takes precedence over all config).
2. `byFindingType.{type}.scoreFromCvss` — for `Vulnerability` findings: multiply `CvssScore` by `cvssScale` when the score is present.
3. `byFindingType.{type}.bySeverity` — per-finding-type severity weights.
4. `defaults.bySeverity` — global fallback.

```yaml
scoring:
  aggregation: Sum    # only Sum is supported in v1

  defaults:
    bySeverity:
      Critical: 50
      High: 20
      Medium: 5
      Low: 1
      Info: 0

  byFindingType:
    Vulnerability:
      scoreFromCvss: true     # use CvssScore × cvssScale when CvssScore is available
      cvssScale: 10           # CVSS 9.8 → 98; CVSS 5.0 → 50
      bySeverity:             # fallback when CvssScore is absent
        Critical: 50
        High: 20
        Medium: 5
        Low: 1

    License:
      bySeverity:
        High: 80              # e.g. copyleft in a proprietary codebase
        Medium: 20
        Low: 5

    Malware:
      bySeverity:
        Critical: 100
        High: 75
        Medium: 50

    DependencyConfusion:
      bySeverity:
        Critical: 75
        High: 50
        Medium: 25
```

### Policy Configuration

```yaml
# policy.yaml — every rule here is a blocking rule.
# A package that matches no rule is allowed.

scoring:
  # ... see Risk Scoring Configuration above

policies:
  # Hard block: any malware finding
  - name: block-malware
    blockMode: Hard
    conditions:
      anyOf:
        - findingType: Malware

  # Hard block: any Critical-severity vulnerability
  - name: block-critical-cves
    blockMode: Hard
    conditions:
      anyOf:
        - findingType: Vulnerability
          severity: Critical

  # Hard block: CVSS 9.0 or above (more precise than severity alone)
  - name: block-cvss-critical
    blockMode: Hard
    conditions:
      anyOf:
        - findingType: Vulnerability
          cvssScore: ">= 9.0"

  # Score block: aggregate vulnerability risk
  # A single High CVE (CVSS 8.1 → score 81) already trips this.
  # Two Mediums (CVSS 5.5 → 55 each) would accumulate to 110.
  - name: vulnerability-risk-score
    blockMode: Score
    conditions:
      scoreExceeds:
        threshold: 50
        findingType: Vulnerability   # scope to vulnerability findings only

  # Score block: combined risk across all finding types
  # A dependency confusion finding (High, score 50) plus a handful of
  # medium CVEs can tip this threshold.
  - name: combined-risk-gate
    blockMode: Score
    conditions:
      scoreExceeds:
        threshold: 100               # no findingType — aggregate across everything

  # Threshold block: many medium vulnerabilities indicates poor maintenance
  - name: medium-vulnerability-flood
    blockMode: Threshold
    conditions:
      countOf:
        findingType: Vulnerability
        severity: [Medium]
        threshold: 5

  # Hard block: specific prohibited licenses
  - name: block-copyleft-licenses
    blockMode: Hard
    conditions:
      anyOf:
        - findingType: License
          id: "in [GPL-2.0-only, GPL-3.0-only, GPL-3.0-or-later, AGPL-3.0-only, AGPL-3.0-or-later]"

  # Compound: dependency confusion AND any vulnerability — elevated combined risk
  - name: block-confusion-with-vulnerability
    blockMode: Hard
    conditions:
      allOf:
        - anyOf:
            - findingType: DependencyConfusion
        - anyOf:
            - findingType: Vulnerability
```

### Condition Reference

**Condition types:**

| Type | Behaviour |
|---|---|
| `anyOf` | Fires if at least one finding matches all criteria in any list entry. Entries are OR'd; fields within an entry are AND'd. |
| `countOf` | Fires if the number of findings matching all criteria ≥ `threshold`. |
| `scoreExceeds` | Fires if the aggregate risk score exceeds `threshold`. Optionally scoped to a single `findingType`. |
| `allOf` | Fires only if every nested sub-condition fires. |
| `noneOf` | Fires if no finding matches the criteria. |

**Finding filter fields** (applicable in `anyOf`, `countOf`, `allOf`, `noneOf`):

| Field | Applicable to | Description |
|---|---|---|
| `findingType` | all | `Vulnerability`, `License`, `Malware`, `DependencyConfusion` (string or list) |
| `severity` | all | `Critical`, `High`, `Medium`, `Low`, `Info` (string or list) |
| `id` | all | Matches `Finding.Id` — useful for specific CVE IDs or SPDX identifiers |
| `cvssScore` | `Vulnerability` | Numeric comparison against `VulnerabilityFinding.CvssScore` |
| `properties` | all | Additional analyzer-specific properties |

**Predicate expression syntax** (used in `id`, `cvssScore`, `properties` values):

| Expression | Example | Meaning |
|---|---|---|
| `">= value"` | `cvssScore: ">= 9.0"` | Numeric ≥ |
| `"> value"` | `cvssScore: "> 7.0"` | Numeric > |
| `"<= value"` | `cvssScore: "<= 3.9"` | Numeric ≤ |
| `"< value"` | `cvssScore: "< 4.0"` | Numeric < |
| `"= value"` | `id: "= CVE-2024-12345"` | Exact equality |
| `"in [a, b]"` | `id: "in [GPL-3.0-only, AGPL-3.0-only]"` | Set membership |
| `"contains text"` | `id: "contains 2024"` | Substring match |

### Interfaces

```csharp
public interface IPolicyEngine
{
    Task<PolicyDecision> EvaluateAsync(
        IReadOnlyList<Finding> findings,
        PackageRiskScore riskScore,
        CancellationToken ct = default);
}

public record PolicyDecision(
    bool IsBlocked,
    PolicyBlockMode? BlockMode,
    string? MatchedPolicyName,
    int? MatchedCount,               // Threshold: number of findings that matched
    int? Threshold,                  // Threshold: configured threshold
    decimal? RiskScoreThreshold,     // Score: threshold that was exceeded
    PackageRiskScore RiskScore       // always populated
);

public enum PolicyBlockMode { Hard, Threshold, Score }
```

```csharp
public interface IFindingAggregator
{
    IReadOnlyList<Finding> Aggregate(IReadOnlyList<AnalyzerResult> results);
}

public interface IRiskScorer
{
    PackageRiskScore Score(IReadOnlyList<Finding> findings);
}

public record PackageRiskScore(
    decimal TotalScore,
    IReadOnlyList<FindingTypeScore> ByFindingType
);

public record FindingTypeScore(
    FindingType FindingType,
    decimal Score,
    IReadOnlyList<ScoredFinding> Findings
);

public record ScoredFinding(Finding Finding, decimal Score);
```

```csharp
public interface IPackageAnalyzer
{
    string Name { get; }
    Task<AnalyzerResult> AnalyzeAsync(AnalysisContext context, CancellationToken ct = default);
}

public record AnalysisContext(
    string Ecosystem,
    string PackageName,
    string? PackageVersion,
    Stream? PackageContent,           // available only for download-type requests
    IReadOnlyDictionary<string, string> Metadata
);

// An analyzer returns zero or more findings, potentially of different types.
public record AnalyzerResult(
    string AnalyzerName,
    IReadOnlyList<Finding> Findings
);
```

**Finding type hierarchy:**

```csharp
public enum FindingType { Vulnerability, License, Malware, DependencyConfusion }
public enum Severity { Info, Low, Medium, High, Critical }

public abstract record Finding
{
    public abstract FindingType Type { get; }
    public abstract string Id { get; }             // natural dedup key within the type
    public required Severity Severity { get; init; }
    public required string Summary { get; init; }
    public string? Reference { get; init; }
    public IReadOnlyList<string> ReportedBy { get; init; } = [];   // populated after aggregation
    public decimal? AnalyzerScore { get; init; }   // analyzer-provided override; takes priority in scoring
    public IReadOnlyDictionary<string, string> Properties { get; init; } =
        ImmutableDictionary<string, string>.Empty;
}

public sealed record VulnerabilityFinding : Finding
{
    public override FindingType Type => FindingType.Vulnerability;
    public override string Id => VulnerabilityId;
    public required string VulnerabilityId { get; init; }  // e.g. "CVE-2024-12345"
    public string[]? Aliases { get; init; }                // alternate IDs (GHSA, OSV) for the same vuln
    public decimal? CvssScore { get; init; }
    public string? AffectedVersionRange { get; init; }
    public string? FixedVersion { get; init; }
}

public sealed record LicenseFinding : Finding
{
    public override FindingType Type => FindingType.License;
    public override string Id => SpdxId;
    public required string SpdxId { get; init; }           // e.g. "GPL-3.0-only"
    public required string LicenseName { get; init; }
}

public sealed record MalwareFinding : Finding
{
    public override FindingType Type => FindingType.Malware;
    public override string Id => IndicatorId;
    public required string IndicatorId { get; init; }
    public required string IndicatorType { get; init; }    // "KnownMaliciousHash", "SuspiciousInstallScript", …
}

public sealed record DependencyConfusionFinding : Finding
{
    public override FindingType Type => FindingType.DependencyConfusion;
    public override string Id => Namespace is null ? PackageName : $"{Namespace}/{PackageName}";
    public required string PackageName { get; init; }
    public string? Namespace { get; init; }
}
```

Analyzers are registered in DI and discovered automatically. Any assembly that exports `IPackageAnalyzer` implementations can be plugged in by adding it to the host project.

---

## Analyzers (Initial Set)

### OsvDevAnalyzer

Queries the [OSV.dev](https://osv.dev) batch API for known vulnerabilities affecting the requested package and version.

- **Endpoint**: `POST https://api.osv.dev/v1/querybatch`
- **Ecosystem mapping**: purl type → OSV ecosystem — `npm` → `npm`, `nuget` → `NuGet`, `pypi` → `PyPI`, `maven` → `Maven`, `cargo` → `crates.io`, `gem` → `RubyGems`, `golang` → `Go`.
- **Caching**: results stored in `IKeyValueCache` under `osv:{ecosystem}:{name}:{version}` with a configurable TTL (default: 1 hour).
- **Returns**: `VulnerabilityFinding` records.
  - `VulnerabilityId` — the primary OSV ID (e.g. `GHSA-xxxx-xxxx-xxxx`); CVE and other aliases populated in `Aliases`.
  - `CvssScore` — highest CVSS score across all listed severity entries; used directly by the scoring engine. If the OSV entry provides a CVSS v3.x vector string rather than a numeric score, the base score is calculated from the vector.
  - `Severity` — mapped from `CvssScore`: ≥ 9.0 → Critical, ≥ 7.0 → High, ≥ 4.0 → Medium, ≥ 0.1 → Low. A score of exactly 0.0 or no score at all maps to Medium.
  - `FixedVersion` — earliest version listed in the OSV `affected[].ranges[].events.fixed` entries, if present.
  - `Properties` keys emitted: `osvId`, `cveId` (if present in aliases).

**Deduplication note**: if multiple vulnerability databases (e.g. a future NVD analyzer) report the same CVE, the `FindingAggregator` resolves aliases and deduplicates to a single `VulnerabilityFinding`, retaining the highest severity and CVSS score across all sources.

---

## Ecosystem Proxies

Each proxy is an ASP.NET Core endpoint group mounted under `/v1/proxy/{type}`. The type is the Package URL type component. Each proxy translates client requests to upstream requests, handles protocol-specific rewrites, and feeds results back through the shared pipeline.

Upstream registry base URLs are configurable per ecosystem; the defaults point to the canonical public registries.

### /v1/proxy/nuget - NuGet V3

Default upstream: `https://api.nuget.org/v3`

Endpoints proxied:

| Client path | Upstream path | Notes |
|---|---|---|
| `GET /v1/proxy/nuget/v3/index.json` | `/v3/index.json` | Service index - URLs rewritten to point back through the proxy |
| `GET /v1/proxy/nuget/v3/query` | `/v3/query` | Search endpoint - pass-through |
| `GET /v1/proxy/nuget/v3/registration5/{id}/index.json` | Registration blob | Package metadata |
| `GET /v1/proxy/nuget/v3/flatcontainer/{id}/{version}/{id}.{version}.nupkg` | Flat container download | **Policy evaluated here** |
| `GET /v1/proxy/nuget/v3/flatcontainer/{id}/index.json` | Version list | Pass-through |
| `GET /v1/proxy/nuget/v3/{**path}` | Any other v3 resource | Catch-all pass-through for other rewritten resources (vulnerabilities, autocomplete, etc.) |

The service index response is rewritten so all resource URLs point back through the proxy rather than directly to nuget.org. Resources under paths not explicitly handled (e.g. v3-index, CDN search) are left pointing at the upstream so clients can reach them directly.

Policy evaluation is triggered on `.nupkg` download requests. For metadata-only requests (search, registration), the request is recorded but policy is not evaluated and no block can occur.

### /v1/proxy/npm - npm Registry

Default upstream: `https://registry.npmjs.org`

Endpoints proxied:

| Client path | Upstream path | Notes |
|---|---|---|
| `GET /v1/proxy/npm/{name}` | `/{name}` | Package manifest (all versions) |
| `GET /v1/proxy/npm/@{scope}/{name}` | `/@{scope}/{name}` | Scoped package manifest |
| `GET /v1/proxy/npm/{name}/-/{name}-{version}.tgz` | Download tarball | **Policy evaluated here** |
| `GET /v1/proxy/npm/@{scope}/{name}/-/{name}-{version}.tgz` | Scoped download | **Policy evaluated here** |

Tarball URLs in manifest responses are rewritten to route through the proxy.

### /v1/proxy/pypi - PyPI

Default upstream: `https://pypi.org`

Follows [PEP 503](https://peps.python.org/pep-0503/) (Simple Repository API) and [PEP 691](https://peps.python.org/pep-0691/) (JSON variant).

| Client path | Upstream path | Notes |
|---|---|---|
| `GET /v1/proxy/pypi/simple/` | `/simple/` | Index of all packages |
| `GET /v1/proxy/pypi/simple/{name}/` | `/simple/{name}/` | File list for a package |
| `GET /v1/proxy/pypi/packages/{...}` | `/packages/{...}` | Wheel / sdist download - **Policy evaluated here** |

Download URLs in simple index responses are rewritten through the proxy. Policy is evaluated on file downloads (`.whl`, `.tar.gz`, `.zip`).

### /v1/proxy/maven - Maven 2

Default upstream: `https://repo1.maven.org/maven2`

Follows Maven 2 repository layout.

| Client path | Upstream path | Notes |
|---|---|---|
| `GET /v1/proxy/maven/{group:path}/{artifact}/{version}/{file}` | Mirror of path | POM and metadata: pass-through. `.jar` and other binary artifacts: **Policy evaluated here** |
| `GET /v1/proxy/maven/{group:path}/{artifact}/maven-metadata.xml` | metadata | Pass-through |

Group ID segments use `/` as separator (Maven convention). Policy is evaluated on `.jar`, `.aar`, `.war`, and `.ear` downloads.

### /v1/proxy/cargo - Cargo

Default upstream: `https://index.crates.io` (sparse registry index), `https://static.crates.io` (downloads)

Implements the [sparse registry protocol](https://doc.rust-lang.org/cargo/reference/registry-index.html#sparse-protocol).

| Client path | Upstream path | Notes |
|---|---|---|
| `GET /v1/proxy/cargo/config.json` | Sparse index config | Fetches upstream config and rewrites the `dl` URL template to route downloads through the proxy |
| `GET /v1/proxy/cargo/{**path}` (index entry) | Sparse index | Returns crate metadata JSON |
| `GET /v1/proxy/cargo/api/v1/crates/{name}/{version}/download` | crate download | **Policy evaluated here** |

### /v1/proxy/gem - RubyGems

Default upstream: `https://rubygems.org`

| Client path | Upstream path | Notes |
|---|---|---|
| `GET /v1/proxy/gem/specs.4.8.gz` | Full gem index | Pass-through (used by `bundle install --full-index`) |
| `GET /v1/proxy/gem/latest_specs.4.8.gz` | Latest gems index | Pass-through |
| `GET /v1/proxy/gem/prerelease_specs.4.8.gz` | Prerelease gems index | Pass-through |
| `GET /v1/proxy/gem/versions` | Compact index versions | Pass-through (default Bundler mode) |
| `GET /v1/proxy/gem/info/{name}` | Compact index package info | Pass-through |
| `GET /v1/proxy/gem/api/v1/dependencies` | Bundler dependencies API | Pass-through |
| `GET /v1/proxy/gem/api/v1/gems/{name}.json` | Gem metadata | Pass-through |
| `GET /v1/proxy/gem/gems/{filename}` | Gem download | **Policy evaluated here** |
| `GET /v1/proxy/gem/quick/Marshal.4.8/{filename}` | Gemspec | Pass-through |

### /v1/proxy/golang - Go Modules

Default upstream: `https://proxy.golang.org`

Implements the [GOPROXY protocol](https://go.dev/ref/mod#goproxy-protocol).

| Client path | Upstream path | Notes |
|---|---|---|
| `GET /v1/proxy/golang/{module}/@v/list` | `/{module}/@v/list` | Version list |
| `GET /v1/proxy/golang/{module}/@v/{version}.info` | info | Pass-through |
| `GET /v1/proxy/golang/{module}/@v/{version}.mod` | go.mod | Pass-through |
| `GET /v1/proxy/golang/{module}/@v/{version}.zip` | module zip | **Policy evaluated here** |
| `GET /v1/proxy/golang/{module}/@latest` | latest info | Pass-through |

---

## Configuration

All configuration is via `appsettings.json` / `appsettings.{Environment}.json` and environment variable overrides using the standard `Microsoft.Extensions.Configuration` conventions.

```json
{
  "PackageWarden": {
    "BaseUrl": "http://localhost:5050",

    "StateStore": {
      "Provider": "Sqlite",
      "Sqlite": {
        "DatabasePath": "/var/package-warden/state.db"
      }
    },

    "KeyValueStore": {
      "Provider": "Directory",
      "Directory": {
        "RootPath": "/var/package-warden/kv-store"
      }
    },

    "KeyValueCache": {
      "Provider": "Directory",
      "Directory": {
        "RootPath": "/var/package-warden/kv-cache"
      },
      "EvictionIntervalMinutes": 15
    },

    "Policies": {
      "FilePath": "policy.yaml",          // relative to working directory; override with absolute path in production
      "HotReload": false                  // set true to reload on file change without restart
    },

    "DefaultAction": "Allow",

    "Proxies": {
      "Npm": {
        "Enabled": true,
        "UpstreamBaseUrl": "https://registry.npmjs.org"
      },
      "NuGet": {
        "Enabled": true,
        "UpstreamBaseUrl": "https://api.nuget.org"
      },
      "PyPI": {
        "Enabled": true,
        "UpstreamBaseUrl": "https://pypi.org",
        "FilesBaseUrl": "https://files.pythonhosted.org"   // package files are served from this separate host; both are rewritten through the proxy
      },
      "Maven": {
        "Enabled": true,
        "UpstreamBaseUrl": "https://repo1.maven.org/maven2"
      },
      "Cargo": {
        "Enabled": true,
        "UpstreamIndexUrl": "https://index.crates.io",
        "UpstreamDownloadUrl": "https://static.crates.io"
      },
      "Gem": {
        "Enabled": true,
        "UpstreamBaseUrl": "https://rubygems.org"
      },
      "Golang": {
        "Enabled": true,
        "UpstreamBaseUrl": "https://proxy.golang.org"
      }
    },

    "Analyzers": {
      "OsvDev": {
        "Enabled": true,
        "CacheTtlMinutes": 60,
        "ApiUrl": "https://api.osv.dev/v1"
      }
    }
  }
}
```

---

## API Surface

In addition to the ecosystem proxy paths, the host exposes a small internal management API consumed by the UI.

All management API endpoints are under `/api/v1`.

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/stats` | Aggregate counts: total requests, blocked, allowed, by ecosystem |
| `GET` | `/api/v1/requests` | Paginated request log (accepts `RequestQuery` parameters as query string) |
| `GET` | `/api/v1/requests/{id}` | Single request detail including all analyzer findings |
| `GET` | `/api/v1/system/status` | Health check - returns `{ status, timestamp }` |
| `GET` | `/api/v1/system/info` | Resolved server paths - returns `{ appSettingsPath, policyFilePath, dataDirectory }` |

---

## User Interface

The UI is served under `/ui`. A redirect from `/` to `/ui` is registered. The UI requires no authentication.

### Technology

Razor Pages backed by the same ASP.NET Core host. No client-side framework - server-rendered HTML with vanilla JavaScript for progressive enhancement (filtering, live stats). Minimal dependencies.

### Pages

#### Dashboard - `/ui`

Displays:
- **Request counters**: total requests today, this week, this month; percentage blocked.
- **Ecosystem breakdown**: a row per enabled ecosystem showing request count and block rate.
- **Recent blocks**: a table of the 10 most recent blocked requests with package name, ecosystem, and reason.
- **System status panel**: for each configured upstream registry, shows reachability (last checked timestamp, latency). For each internal component (state store, KV store, KV cache), shows current status.
- **Analyzer status**: for each configured analyzer, shows enabled/disabled and last successful invocation time.

Stats are fetched from `/api/v1/stats` and `/api/v1/system/status`. The dashboard auto-refreshes every 30 seconds.

#### Request Log - `/ui/requests`

A paginated, filterable table of all recorded requests.

Filter controls:
- **Date range**: from / to date pickers (defaults to last 7 days).
- **Ecosystem**: dropdown of all enabled ecosystems + "All".
- **Outcome**: All / Blocked only / Allowed only.
- **Package name**: free-text substring search.

Table columns: Timestamp, Ecosystem, Package, Version, Client IP, Outcome (Blocked / Allowed), Duration, Detail link.

Clicking a row expands or navigates to a detail view showing the full `ProxyRequest` record: the aggregate risk score with a per-analyzer breakdown, each finding with its individual score contribution, the matched policy name, and — for Score blocks — the threshold that was exceeded. The risk score breakdown is always shown regardless of block mode.

Filters are reflected in the URL query string so links are shareable.

#### Server Info - `/ui/server-info`

Displays the resolved absolute paths the server is using at runtime:

- **appsettings.json path** — full path to the active configuration file.
- **policy.yaml path** — full path to the loaded policy file.
- **Data directory** — directory containing the SQLite database and cache files.

Useful for confirming which configuration and policy files are in effect when running in an unfamiliar environment.

---

## State Store Schema (SQLite)

```sql
CREATE TABLE requests (
    id                   TEXT PRIMARY KEY,  -- GUID
    timestamp            TEXT NOT NULL,     -- ISO 8601
    ecosystem            TEXT NOT NULL,
    package              TEXT NOT NULL,
    version              TEXT,
    upstream             TEXT NOT NULL,
    client_ip            TEXT NOT NULL,
    blocked              INTEGER NOT NULL,  -- 0 / 1
    block_mode           TEXT,              -- 'Hard' | 'Threshold' | 'Score' | NULL
    block_reason         TEXT,              -- matched policy name
    matched_count        INTEGER,           -- Threshold blocks: findings that matched
    threshold            INTEGER,           -- Threshold blocks: configured threshold
    risk_score           REAL,              -- always populated: aggregate risk score
    risk_score_threshold REAL,              -- Score blocks: the threshold that was exceeded
    duration_ms          INTEGER NOT NULL
);

-- Deduplicated, normalized findings — one row per unique (request, finding type, finding id)
CREATE TABLE findings (
    id              TEXT PRIMARY KEY,      -- GUID
    request_id      TEXT NOT NULL REFERENCES requests(id),
    finding_type    TEXT NOT NULL,         -- 'Vulnerability' | 'License' | 'Malware' | 'DependencyConfusion'
    finding_id      TEXT NOT NULL,         -- natural ID: CVE, SPDX expression, indicator id, etc.
    severity        TEXT NOT NULL,
    cvss_score      REAL,                  -- Vulnerability findings only
    score           REAL NOT NULL,         -- this finding's contribution to the aggregate risk score
    reported_by     TEXT NOT NULL,         -- JSON array of analyzer names that found this
    data            TEXT NOT NULL          -- full JSON of the specific finding subtype
);

CREATE INDEX idx_requests_timestamp  ON requests(timestamp);
CREATE INDEX idx_requests_ecosystem  ON requests(ecosystem);
CREATE INDEX idx_requests_blocked    ON requests(blocked);
CREATE INDEX idx_requests_package    ON requests(package);
CREATE INDEX idx_findings_request    ON findings(request_id);
CREATE INDEX idx_findings_type       ON findings(finding_type);
CREATE INDEX idx_findings_id         ON findings(finding_id);
```

Schema is applied via versioned migration scripts embedded as resources in `PackageWarden.Store.Sqlite`, applied on startup using a lightweight migrator (no ORM migration framework).

---

## Error Handling and Resilience

- **Upstream failures**: if an upstream registry is unreachable, the proxy returns `502 Bad Gateway` with a JSON error body. The request is still recorded with a `duration` and a `block_reason` of `UpstreamUnavailable`.
- **Analyzer failures**: if an analyzer throws, its result is recorded as a finding of type `AnalyzerError` with severity `Info`, and the pipeline continues. An analyzer failure never causes a false block; the policy engine skips failed analyzers' results when evaluating conditions.
- **Circuit breaker**: each upstream registry connection is wrapped in a Polly circuit breaker (5 failures in 30 seconds → open for 60 seconds). Configuration is per-ecosystem.
- **Cache errors**: a failure reading or writing `IKeyValueCache` is logged and swallowed; the system falls through to the upstream as if the cache had missed.

---

## Blocked Response Format

When a package request is blocked, the proxy returns HTTP `403 Forbidden`. The `riskScore` object is always included — it provides the full aggregate breakdown so operators and tooling can see the complete picture regardless of which block mode fired.

**Hard block** — a single matching finding triggered an unconditional block:

```json
{
  "blocked": true,
  "blockMode": "Hard",
  "requestId": "3f7a1b2c-...",
  "policy": "block-critical-cves",
  "riskScore": {
    "total": 98.0,
    "byFindingType": [
      {
        "findingType": "Vulnerability",
        "score": 98.0,
        "findings": [
          {
            "findingType": "Vulnerability",
            "id": "CVE-2024-12345",
            "aliases": ["GHSA-xxxx-xxxx-xxxx"],
            "severity": "Critical",
            "cvssScore": 9.8,
            "score": 98.0,
            "summary": "Remote code execution in example-lib < 1.2.3",
            "reference": "https://osv.dev/vulnerability/GHSA-xxxx-xxxx-xxxx",
            "fixedVersion": "1.2.3",
            "reportedBy": ["OsvDev"]
          }
        ]
      }
    ]
  }
}
```

**Threshold block** — the count of matching findings reached the policy threshold:

```json
{
  "blocked": true,
  "blockMode": "Threshold",
  "requestId": "7a3c9d1e-...",
  "policy": "medium-vulnerability-flood",
  "matchedCount": 6,
  "threshold": 5,
  "riskScore": {
    "total": 33.0,
    "byFindingType": [
      {
        "findingType": "Vulnerability",
        "score": 33.0,
        "findings": [
          {
            "findingType": "Vulnerability",
            "id": "CVE-2024-10001",
            "severity": "Medium",
            "cvssScore": 5.5,
            "score": 5.5,
            "summary": "Incorrect input validation in example-lib",
            "reference": "...",
            "reportedBy": ["OsvDev"]
          }
        ]
      }
    ]
  }
}
```

**Score block** — aggregate risk exceeded the policy threshold:

```json
{
  "blocked": true,
  "blockMode": "Score",
  "requestId": "9b2f4c8a-...",
  "policy": "vulnerability-risk-score",
  "riskScoreThreshold": 50.0,
  "riskScore": {
    "total": 162.0,
    "byFindingType": [
      {
        "findingType": "Vulnerability",
        "score": 162.0,
        "findings": [
          {
            "findingType": "Vulnerability",
            "id": "CVE-2024-11111",
            "severity": "High",
            "cvssScore": 8.1,
            "score": 81.0,
            "summary": "Path traversal in example-lib < 2.0.0",
            "reference": "...",
            "reportedBy": ["OsvDev"]
          },
          {
            "findingType": "Vulnerability",
            "id": "CVE-2024-22222",
            "severity": "High",
            "cvssScore": 8.1,
            "score": 81.0,
            "summary": "Denial of service in example-lib < 2.0.0",
            "reference": "...",
            "reportedBy": ["OsvDev"]
          }
        ]
      }
    ]
  }
}
```

The per-finding `score` shows each finding's contribution to the total. The `reportedBy` list identifies which analyzers observed the finding. This structure is intentionally machine-readable so CI tooling can parse and display block reasons.

---

## Implementing a New Ecosystem Proxy

To add a new ecosystem:

1. Create `PackageWarden.Proxy.{Ecosystem}/`.
2. Implement `IEcosystemProxy` to declare the purl type and route prefix.
3. Register endpoint handlers that call into `IProxyPipeline.HandleAsync(ProxyRequest)`.
4. Add upstream URL configuration under `PackageWarden:Proxies:{Ecosystem}`.
5. Ensure the `AnalysisContext.Ecosystem` value matches the purl type so analyzers that use ecosystem to route to the right vulnerability source work correctly.

No changes to core are needed.

---

## Implementing a New Analyzer

1. Create a class implementing `IPackageAnalyzer`.
2. Register it with `services.AddPackageAnalyzer<MyAnalyzer>()`.
3. Reference the analyzer's `Name` in `policies.yaml` to include it in a policy.

---

## Implementing a New State Store

1. Implement `IStateStore`.
2. Register with `services.AddStateStore<MyStateStore>()`.
3. Set `PackageWarden:StateStore:Provider` in configuration.

The same pattern applies for `IKeyValueStore` (`services.AddKeyValueStore<T>()`) and `IKeyValueCache` (`services.AddKeyValueCache<T>()`).

---

## Non-Goals (v1)

- Authentication or authorisation on any endpoint (planned for v2).
- Write-through / publishing packages to upstream registries.
- Private registry hosting (package storage).
- Multi-tenant or per-team policy scoping.
- Real-time streaming of request events (planned: SSE or WebSocket feed for dashboard).
- Package content scanning (static analysis of package internals beyond metadata) - architecture supports it via `AnalysisContext.PackageContent` but no analyzer implements it in v1.
