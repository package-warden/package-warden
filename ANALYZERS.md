# Analyzers

Analyzers are the components that examine a package and produce findings. Each finding has a type, severity, and supporting detail. The policy engine then evaluates those findings against your rules to decide whether to allow or block the package.

## Finding types

| Type | Record | Description |
|------|--------|-------------|
| `Vulnerability` | `VulnerabilityFinding` | A known vulnerability in the package, typically from a CVE or OSV entry |
| `License` | `LicenseFinding` | A license associated with the package (identified by SPDX ID) |
| `Malware` | `MalwareFinding` | A malware indicator detected in the package |
| `DependencyConfusion` | `DependencyConfusionFinding` | Signals that a package may be susceptible to a dependency confusion attack |
| `SourceRepository` | `SourceRepositoryFinding` | Result of looking up the package's source repository and verifying the version |
| `HealthCheck` | `HealthCheckFinding` | Informational record that a scan completed and found nothing of concern |

`SourceRepository` and `HealthCheck` findings are produced by the built-in source repository and OSV.dev analyzers respectively. `License`, `Malware`, and `DependencyConfusion` are supported by the domain model and policy engine but require additional analyzers to emit them.

### Severity levels

`Info`, `Low`, `Medium`, `High`, `Critical` - in ascending order of severity.

### Common finding fields

All findings carry:

| Field | Type | Description |
|-------|------|-------------|
| `Severity` | `Severity` | Severity of this finding |
| `Summary` | `string` | Short human-readable description |
| `Reference` | `string?` | URL to advisory, registry entry, or other detail |
| `ReportedBy` | `string[]` | Analyzer names that contributed this finding (set by the aggregator) |
| `AnalyzerScore` | `decimal?` | Raw numeric score from the analyzer, if provided |
| `Properties` | `IReadOnlyDictionary<string, string>` | Arbitrary key/value metadata |

`VulnerabilityFinding` additionally carries:

| Field | Type | Description |
|-------|------|-------------|
| `VulnerabilityId` | `string` | Primary identifier, e.g. `GHSA-xxxx` or `CVE-xxxx` |
| `Aliases` | `string[]?` | Alternative IDs such as CVE numbers |
| `CvssScore` | `decimal?` | CVSS base score |
| `AffectedVersionRange` | `string?` | Version range string |
| `FixedVersion` | `string?` | First version that resolves the vulnerability |

`SourceRepositoryFinding` additionally carries:

| Field | Type | Description |
|-------|------|-------------|
| `PackageIdentifier` | `string` | `{ecosystem}:{packageName}` - used as the deduplication key |
| `RepositoryUrl` | `string?` | URL of the source repository or release page, if found |

`HealthCheckFinding` additionally carries:

| Field | Type | Description |
|-------|------|-------------|
| `Source` | `string` | Name of the service or check that produced this result, e.g. `OSV.dev` |

---

## OSV.dev analyzer

**Assembly:** `PackageWarden.Analyzers.OsvDev`  
**Class:** `OsvDevAnalyzer`  
**Produces:** `Vulnerability`, `HealthCheck`

Queries the [OSV.dev](https://osv.dev) batch API for known vulnerabilities. OSV aggregates data from GitHub Security Advisories, PyPA, RustSec, npm, and many other sources, making it a broad first-pass check across all supported ecosystems.

### How it works

For each package download, the analyzer sends a `POST /querybatch` request to `https://api.osv.dev/v1` with the package name, version, and ecosystem. Each vulnerability in the response is mapped to a `VulnerabilityFinding`. Results are cached by `{ecosystem}:{name}:{version}` for the configured TTL so repeat requests for the same package do not incur an API call.

Severity is derived from the CVSS score attached to the vulnerability when present, falling back to `Medium` if no score is available:

| CVSS range | Severity |
|------------|----------|
| >= 9.0 | Critical |
| >= 7.0 | High |
| >= 4.0 | Medium |
| >= 0.1 | Low |
| none | Medium |

The `VulnerabilityId` is the OSV ID (e.g. `GHSA-c2qf-rxjj-qqgw`). CVE aliases are extracted and stored in `Aliases`, with the first CVE ID also promoted to the `cveId` property in `Properties`.

### Ecosystem mapping

| Proxy ecosystem | OSV ecosystem |
|-----------------|---------------|
| `npm` | `npm` |
| `nuget` | `NuGet` |
| `pypi` | `PyPI` |
| `maven` | `Maven` |
| `cargo` | `crates.io` |
| `gem` | `RubyGems` |
| `golang` | `Go` |

### Configuration

Under `PackageWarden:Analyzers:OsvDev` in `appsettings.json`:

| Key | Default | Description |
|-----|---------|-------------|
| `Enabled` | `true` | Set to `false` to skip OSV analysis entirely |
| `CacheTtlMinutes` | `60` | How long to cache responses per `{ecosystem}:{name}:{version}` |
| `ApiUrl` | `https://api.osv.dev/v1` | Base URL of the OSV API - override for air-gapped deployments |

### Health check finding

When the OSV.dev API responds successfully and no vulnerabilities are found, the analyzer emits a `HealthCheckFinding` with `Severity: Info` and `Source: "OSV.dev"`. This is visible in the request detail UI but scores `0` and does not affect policy decisions. No health check is emitted when the analyzer is disabled, the ecosystem is unsupported, or the API call fails.

### Limitations

- If a package is requested without a version (e.g. a manifest fetch rather than a tarball download), the query is sent without a version, which may return a broader set of results or none depending on the upstream.
- OSV.dev coverage varies by ecosystem; some advisories may lag the source database by hours or days.

---

## OpenSourceMalware analyzer

**Assembly:** `PackageWarden.Analyzers.OpenSourceMalware`  
**Class:** `OpenSourceMalwareAnalyzer`  
**Produces:** `Malware`  
**Enabled by default:** No — requires an API key

Checks packages against the [OpenSourceMalware.com](https://opensourcemalware.com) database, which tracks packages that have been confirmed to contain malicious code. Any package present in the database is flagged `Critical`.

### How it works

For each package download, the analyzer calls the `check-malicious` endpoint with the package name, ecosystem, and version. If the API reports the package as malicious, a `MalwareFinding` is returned with the indicator ID, severity level, and description from the database. If the package is not in the database, no finding is produced. Results are cached by `{ecosystem}:{name}:{version}` for the configured TTL.

### Ecosystem support

The OpenSourceMalware API supports a subset of ecosystems:

| Proxy ecosystem | Supported |
|-----------------|-----------|
| `npm` | Yes |
| `pypi` | Yes |
| `maven` | Yes |
| `nuget` | Yes |
| `cargo` | No |
| `gem` | No |
| `golang` | No |

Packages in unsupported ecosystems are silently skipped.

### Getting an API key

Register for an account at [opensourcemalware.com](https://opensourcemalware.com) to obtain an API key. Check the site for current pricing and rate limit details.

### Configuration

Under `PackageWarden:Analyzers:OpenSourceMalware` in `appsettings.json`:

| Key | Default | Description |
|-----|---------|-------------|
| `Enabled` | `false` | Must be set to `true` to activate — the analyzer does nothing while disabled |
| `ApiKey` | _(empty)_ | **Required.** API key from opensourcemalware.com. The analyzer logs a warning and skips analysis if this is empty while enabled |
| `CacheTtlMinutes` | `10` | How long to cache responses per `{ecosystem}:{name}:{version}`. A shorter TTL than other analyzers is used because the malware database is updated frequently |
| `ApiUrl` | `https://api.opensourcemalware.com/functions/v1` | Base URL of the API — override for testing or air-gapped deployments |

### Limitations

- Only four ecosystems are supported by the upstream API; packages in other ecosystems are not checked.
- The database covers packages confirmed as malicious; it is not a general vulnerability scanner and will not flag packages with vulnerabilities that are not outright malware.
- Rate limiting: the API returns HTTP 429 when the rate limit is exceeded. The analyzer logs a warning and returns no findings for that request rather than blocking it.

---

## OSSF Malicious Packages analyzer

**Assembly:** `PackageWarden.Analyzers.OssfMaliciousPackages`  
**Class:** `OssfMaliciousPackagesAnalyzer`  
**Produces:** `Malware`  
**Enabled by default:** Yes — no credentials required for public access

Checks packages against the [OSSF Malicious Packages](https://github.com/ossf/malicious-packages) database, a community-maintained registry of confirmed malicious open source packages. Each entry in the database is a structured [OSV](https://osv.dev)-format report that identifies specific compromised versions. Any package found in the database is flagged `Critical`.

### How it works

For each package download, the analyzer queries the GitHub Contents API to check whether a directory for that package exists under `packages/{ecosystem}/{name}` in the `ossf/malicious-packages` repository. A `404` response means the package is not in the database. A `200` response means at least one malicious report exists: the analyzer then fetches each report's `osv.json` from `raw.githubusercontent.com` to extract the OSV summary and list of confirmed malicious versions. Results are cached by `{ecosystem}:{name}` for the configured TTL so that subsequent requests for any version of the same package do not incur additional API calls.

If the requested version appears in the `affected[].versions` list of any report, the OSV summary is used verbatim. Otherwise the summary is annotated with the set of confirmed malicious versions from the database, making it clear that a known-bad version exists even if the requested version is not explicitly listed.

### Ecosystem support

| Proxy ecosystem | OSSF directory |
|-----------------|---------------|
| `npm`    | `npm`        |
| `pypi`   | `pypi`       |
| `nuget`  | `nuget`      |
| `maven`  | `maven`      |
| `cargo`  | `crates.io`  |
| `gem`    | `rubygems`   |
| `golang` | `go`         |

PyPI package names are normalized to lowercase with underscores replaced by hyphens before the lookup, matching the canonical form used in the OSSF database.

### Rate limiting

The GitHub Contents API allows **60 unauthenticated requests per hour** per IP address. Providing a GitHub token raises this to 5,000 per hour. Without a token, the 60-request budget is shared across all package checks that miss the cache. For higher-traffic deployments a token is strongly recommended.

The raw content host (`raw.githubusercontent.com`) is not subject to the GitHub API rate limit and is used for fetching OSV report files.

### Configuration

Under `PackageWarden:Analyzers:OssfMaliciousPackages` in `appsettings.json`:

| Key | Default | Description |
|-----|---------|-------------|
| `Enabled` | `true` | Set to `false` to skip OSSF analysis entirely |
| `CacheTtlMinutes` | `60` | How long to cache the lookup result per `{ecosystem}:{name}`. The result covers all versions of the package |
| `GitHubToken` | _(empty)_ | Optional GitHub personal access token. Without one, the unauthenticated rate limit of 60 requests/hour applies |
| `GitHubApiUrl` | `https://api.github.com` | GitHub API base URL — override for GitHub Enterprise or testing |
| `GitHubRawUrl` | `https://raw.githubusercontent.com` | Raw content base URL — override for testing |

### Limitations

- The database covers only packages that have been reported and merged; newly discovered malware may not appear immediately.
- Version matching depends on reporters having listed explicit versions in the OSV `affected[].versions` field. If a report omits version details, the package is still flagged but the summary will not identify a specific version as confirmed.
- The GitHub API rate limit (60 req/hour unauthenticated) constrains how many distinct packages can be checked per hour before cached results are exhausted. A GitHub token is recommended for production use.
- Up to 10 report files are fetched per package; packages with more than 10 reports will have their later entries ignored (uncommon in practice).

---

## Source repository analyzer

**Assembly:** `PackageWarden.Analyzers.SourceRepository`  
**Class:** `SourceRepositoryAnalyzer`  
**Produces:** `SourceRepository`

Looks up the source repository declared in a package's registry metadata, then verifies that the requested version appears as a GitHub release or tag. Packages where no version can be verified are flagged to highlight potential provenance risk.

### How it works

1. **Registry lookup** — the analyzer fetches the package's metadata from the relevant ecosystem registry to find the declared source repository URL. Results are cached by `{ecosystem}:{name}` for the configured `RegistryCacheTtlMinutes` (NuGet uses `{ecosystem}:{name}:{version}` because it fetches the version-specific nuspec).
2. **GitHub check** — if the repository URL resolves to GitHub, the analyzer fetches the repository's releases and tags via the GitHub API. Results are cached by `{owner}/{repo}` for `ReleaseCacheTtlMinutes`.
3. **Version matching** — the version is matched against common tag formats: `{version}`, `v{version}`, `{name}-{version}`, `{name}@{version}`, `{name}/{version}`, and their `v`-prefixed variants.

### Outcomes

| Situation | Severity | Summary |
|-----------|----------|---------|
| Version matched in GitHub releases | `Info` | Version verified on GitHub releases |
| Version matched in GitHub tags (no formal release) | `Info` | Version verified on GitHub tags |
| No matching release or tag found | `Critical` | No GitHub release or tag matches version |
| Repository found but not on GitHub | `Medium` | Cannot verify releases for non-GitHub repositories |
| Repository URL cannot be determined | `Medium` | Unable to determine source code repository |
| GitHub API unreachable | `Medium` | Unable to fetch releases/tags from GitHub |

The analyzer skips packages requested without a version (manifest-only fetches).

### Registry support

| Ecosystem | Source of repository URL |
|-----------|--------------------------|
| `npm` | `registry.npmjs.org/{name}` → `repository.url` |
| `pypi` | `pypi.org/pypi/{name}/json` → `project_urls` (case-insensitive key lookup: `Source Code`, `Source`, `Repository`, `Code`, `Homepage`) then `home_page` |
| `nuget` | `api.nuget.org/v3-flatcontainer/{id}/{version}/{id}.nuspec` → `<repository url>` then `<projectUrl>` |
| `cargo` | `crates.io/api/v1/crates/{name}` → `crate.repository` |
| `gem` | `rubygems.org/api/v1/gems/{name}.json` → `source_code_uri` then `homepage_uri` |
| `golang` | Module path parsed directly — `github.com/{owner}/{repo}[/subpkg...]` → `https://github.com/{owner}/{repo}` |
| `maven` | Not supported → `Medium` |

### Configuration

Under `PackageWarden:Analyzers:SourceRepository` in `appsettings.json`:

| Key | Default | Description |
|-----|---------|-------------|
| `Enabled` | `true` | Set to `false` to skip source repository analysis entirely |
| `RegistryCacheTtlMinutes` | `1440` | How long to cache the registry lookup result (the source repository URL) |
| `ReleaseCacheTtlMinutes` | `60` | How long to cache the GitHub releases and tags lists |
| `GitHubToken` | _(empty)_ | Optional GitHub personal access token. Without one, the GitHub API allows 60 unauthenticated requests per hour per IP. A token raises this to 5,000/hour. |

### Limitations

- Only GitHub is supported for release and tag verification. Packages hosted on GitLab, Bitbucket, or other forges are flagged `Medium`.
- Maven package coordinates embed both a group ID and artifact ID in the URL path, which requires different parsing from other ecosystems; Maven is not currently supported.
- Go modules that do not begin with `github.com/` (e.g. `golang.org/x/net`, `k8s.io/client-go`) are flagged `Medium` even if they are ultimately mirrored on GitHub.
- Some packages use git tags without creating formal GitHub Releases (lodash is a well-known example). The tag fallback handles these correctly.
- The GitHub releases and tags APIs return up to 100 results per request. Repositories with more than 100 releases and very old versions may not be verified even if a tag exists.

---

## Writing a custom analyzer

Implement `IPackageAnalyzer` from `PackageWarden.Core.Interfaces`:

```csharp
public interface IPackageAnalyzer
{
    string Name { get; }
    Task<AnalyzerResult> AnalyzeAsync(AnalysisContext context, CancellationToken ct = default);
}
```

`AnalysisContext` provides:

| Property | Type | Description |
|----------|------|-------------|
| `Ecosystem` | `string` | purl type string: `npm`, `nuget`, `pypi`, `maven`, `cargo`, `gem`, `golang` |
| `PackageName` | `string` | Package name as reported by the proxy |
| `PackageVersion` | `string?` | Version string, or `null` for manifest-only requests |
| `PackageContent` | `Stream?` | Raw package bytes if content inspection is needed (currently always `null`) |
| `Metadata` | `IReadOnlyDictionary<string, string>` | Extensible bag for proxy-provided context |

Return an `AnalyzerResult` with your analyzer's `Name` and a list of `Finding` instances. Return an empty list if the analyzer does not apply (e.g. unsupported ecosystem or disabled). For informational scan results where nothing was found, consider returning a `HealthCheckFinding` with `Severity.Info` so the outcome is visible in the request detail UI without affecting the risk score.

Register the analyzer in `Program.cs`:

```csharp
builder.Services.AddPackageAnalyzer<MyAnalyzer>();
```

Multiple analyzers can be registered; all run for every request, and their findings are merged by the `FindingAggregator` before policy evaluation. Findings with the same `Id` from different analyzers are deduplicated - the highest severity is kept and the `ReportedBy` list records which analyzers contributed.
