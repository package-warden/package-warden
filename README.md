# Package Warden

Package Warden is a security-focused package repository proxy for developers. It sits between your package manager and public package repositories, intercepts download requests, runs analysis, and blocks packages that violate your configured policy before they are installed.

All requests are recorded regardless of outcome. You can see what was allowed, review what was blocked, and why, and permit exceptions, through the built-in dashboard.

NOTE: This project is in a pre-release state and ~~may~~ will have bugs. It is not a magic solution for all the issues surrounding software supply chain risk. It is just another layer of defense. I have done some manual testing, but the package management ecosystem can be complicated, so I'm sure there are plenty of corner cases that haven't been covered.

## Project Goals

There's already plenty of commercially supported products on the market catering to large enterprises. But nothing that really addressed incorporating additional security controls like this into existing developer workflows for the OSS maintainer, contributor, or hobbyist (well nothing I could find).

I suspect, at the moment, that some of the analysis and rules may be too cautious and will need to be fine tuned. Especially to cater for differences between package ecosystems. The aim is to have a really low noise to signal ratio and for this to be low effort. If this tool introduces too much friction, people simply won't use it. So feedback is more than welcome.

## Quick start

Download the latest release for your platform from the [releases page](https://github.com/YOUR_ORG/package-warden/releases), extract the archive, and start the proxy:

```
# Linux / macOS
./package-warden.sh

# Windows
package-warden.bat
```

The service starts on `http://localhost:5050`. Open `http://localhost:5050/ui` in a browser to see the dashboard.

Then point your package managers at the proxy:

```
# Linux / macOS
./setup-package-managers.sh

# Windows
setup-package-managers.bat
```

On first run, Package Warden creates a platform-appropriate data directory containing the SQLite database, cache, and a default `policy.yaml`.

**Running from source** requires the .NET 10 SDK. Use `./run.sh` instead of `./package-warden.sh`.

> **Note for contributors:** The repository includes a `nuget.config` that clears all inherited NuGet sources and points to `nuget.org` directly. But, the entries are commented out. It is present as a convenience to be able to bypass your local Package Warden configuration if required for development.

## Default behaviour

Out of the box, Package Warden:

- Proxies all seven ecosystems - npm, NuGet, PyPI, Maven, Cargo, RubyGems, and Go modules
- Queries [OSV.dev](https://osv.dev) for vulnerability data on every package download
- Looks up each package's declared source repository and verifies the requested version exists in GitHub releases and tags
- Applies the bundled `policy.yaml`, which blocks packages with critical CVEs, CVSS >= 9.0, a flood of medium vulnerabilities, and high combined risk scores
- Caches analyzer responses to avoid redundant lookups
- Periodically clears local package manager caches so packages are always re-fetched through the proxy rather than served from a local cache that bypasses inspection
- Allows any package that does not match a blocking rule

If no `policy.yaml` is present at startup, all packages are allowed through and requests are still recorded.

### Optional: OpenSourceMalware analyzer

Package Warden ships with an optional integration with [OpenSourceMalware.com](https://opensourcemalware.com), which maintains a database of packages confirmed to contain malicious code. It is disabled by default because it requires an API key.

To enable it:

1. Register for an API key at [opensourcemalware.com](https://opensourcemalware.com)
2. Add the key to `appsettings.json`:

```json
"OpenSourceMalware": {
  "Enabled": true,
  "ApiKey": "your-api-key-here",
  "CacheTtlMinutes": 10
}
```

When enabled, any package confirmed as malicious is flagged `Critical` regardless of other findings. See [ANALYZERS.md](ANALYZERS.md) for full configuration details.

## Pointing your tools at the proxy

The setup script detects which package managers are installed and configures them all at once:

```
# Linux / macOS
./setup-package-managers.sh

# Windows
setup-package-managers.bat
```

It configures npm, pip, dotnet/NuGet, Cargo, Go modules, and Bundler. Maven requires a manual step (see below). To restore your original settings, run the script again with `--undo`.

If `PW_PORT` is set to a non-default value, export it before running so the script uses the right address:

```
PW_PORT=8080 ./setup-package-managers.sh
```

### Manual configuration

The proxy base URL is `http://localhost:5050` by default.

**npm**
```
npm config set registry http://localhost:5050/v1/proxy/npm
```
To revert: `npm config delete registry`

**NuGet / dotnet**
```
dotnet nuget add source http://localhost:5050/v1/proxy/nuget/v3/index.json --name package-warden
dotnet nuget disable source nuget.org
```

**pip**
```
pip install --index-url http://localhost:5050/v1/proxy/pypi/simple/ <package>
```
Or set permanently in `pip.conf` / `pip.ini`:
```ini
[global]
index-url = http://localhost:5050/v1/proxy/pypi/simple/
```

**Maven**

Add a mirror to `~/.m2/settings.xml`:
```xml
<mirrors>
  <mirror>
    <id>package-warden</id>
    <mirrorOf>central</mirrorOf>
    <url>http://localhost:5050/v1/proxy/maven</url>
  </mirror>
</mirrors>
```

**Cargo**

Add to `~/.cargo/config.toml`:
```toml
[source.crates-io]
replace-with = "package-warden"

[source.package-warden]
registry = "sparse+http://localhost:5050/v1/proxy/cargo/"
```

**Bundler (RubyGems)**
```
bundle config set mirror.https://rubygems.org http://localhost:5050/v1/proxy/gem
```

**Go modules**
```
export GOPROXY=http://localhost:5050/v1/proxy/golang,direct
```
Or add to your shell profile for persistence.

## Configuration

Configuration lives in `appsettings.json`. All keys are under the `PackageWarden` section.

```json
{
  "PackageWarden": {
    "BaseUrl": "http://localhost:5050",
    "DefaultAction": "Allow",

    "StateStore": {
      "Provider": "Sqlite",
      "Sqlite": {
        "DatabasePath": "data/package-warden.db"
      }
    },

    "KeyValueStore": {
      "Provider": "Directory",
      "Directory": {
        "RootPath": "data/kv-store"
      }
    },

    "KeyValueCache": {
      "Provider": "Directory",
      "Directory": {
        "RootPath": "data/kv-cache"
      },
      "EvictionIntervalMinutes": 15
    },

    "Policies": {
      "FilePath": "policy.yaml",
      "HotReload": false
    },

    "Analyzers": {
      "OsvDev": {
        "Enabled": true,
        "CacheTtlMinutes": 60,
        "ApiUrl": "https://api.osv.dev/v1"
      },
      "SourceRepository": {
        "Enabled": true,
        "RegistryCacheTtlMinutes": 1440,
        "ReleaseCacheTtlMinutes": 60,
        "GitHubToken": ""
      }
    },

    "Proxies": {
      "Npm":    { "Enabled": true, "UpstreamBaseUrl": "https://registry.npmjs.org" },
      "NuGet":  { "Enabled": true, "UpstreamBaseUrl": "https://api.nuget.org" },
      "PyPI":   { "Enabled": true, "UpstreamBaseUrl": "https://pypi.org" },
      "Maven":  { "Enabled": true, "UpstreamBaseUrl": "https://repo1.maven.org/maven2" },
      "Cargo":  { "Enabled": true, "UpstreamIndexUrl": "https://index.crates.io", "UpstreamDownloadUrl": "https://static.crates.io" },
      "Gem":    { "Enabled": true, "UpstreamBaseUrl": "https://rubygems.org" },
      "Golang": { "Enabled": true, "UpstreamBaseUrl": "https://proxy.golang.org" }
    }
  }
}
```

**Key options:**

| Key | Default | Description |
|-----|---------|-------------|
| `BaseUrl` | `http://localhost:5050` | The public URL of the proxy, used when rewriting tarball URLs in manifests |
| `DefaultAction` | `Allow` | What to do when no policy rule matches - `Allow` or `Block` |
| `Policies.FilePath` | `policy.yaml` | Path to the policy file, relative to the working directory |
| `Policies.HotReload` | `false` | Reload the policy file on change without restarting |
| `Analyzers.OsvDev.CacheTtlMinutes` | `60` | How long to cache OSV.dev results |
| `Analyzers.SourceRepository.RegistryCacheTtlMinutes` | `1440` | How long to cache package registry lookups (source repo URL) |
| `Analyzers.SourceRepository.ReleaseCacheTtlMinutes` | `60` | How long to cache GitHub release and tag lists |
| `Analyzers.SourceRepository.GitHubToken` | _(empty)_ | Optional GitHub personal access token - raises the API rate limit from 60 to 5,000 requests/hour |
| `KeyValueCache.EvictionIntervalMinutes` | `15` | How often the cache eviction background task runs |
| `PackageManagerCacheClear.IntervalMinutes` | `10` | How often (in minutes) to clear local package manager caches (npm, NuGet, pip, gem, go) |

To disable a proxy for an ecosystem you do not use, set `"Enabled": false` for that entry.

## Policy

Policy is defined in `policy.yaml`. There are two top-level sections: `scoring` and `policies`.

### Scoring

The `scoring` section controls how findings are translated into a numeric risk score. Scores are used by `Score` and `Threshold` block modes.

```yaml
scoring:
  aggregation: Sum          # Sum all finding scores together

  defaults:
    bySeverity:
      Critical: 50
      High: 20
      Medium: 5
      Low: 1
      Info: 0

  byFindingType:
    Vulnerability:
      scoreFromCvss: true   # Derive score from CVSS rather than severity label
      cvssScale: 5
```

Finding types currently produced by the built-in analyzers: `Vulnerability` (OSV.dev), `SourceRepository` (source repository analyzer), and `HealthCheck` (informational scan results). The domain also supports `License`, `Malware`, and `DependencyConfusion`, but no built-in analyzer emits those yet. Each finding type can have its own `bySeverity` table under `byFindingType` to override the defaults. `Info` severity findings score `0` by default and do not contribute to risk scores.

### Policies

Each policy is evaluated in order. The first matching policy determines the outcome. If no policy matches, `DefaultAction` applies.

```yaml
policies:
  - name: block-critical-cves
    blockMode: Hard
    conditions:
      anyOf:
        - findingType: Vulnerability
          severity: Critical
```

**Block modes:**

| Mode | Behaviour |
|------|-----------|
| `Hard` | Block immediately if the condition matches |
| `Score` | Block if the computed risk score exceeds `scoreExceeds.threshold` |
| `Threshold` | Block if the count of matching findings meets or exceeds `countOf.threshold` |

**Condition types:**

`anyOf` - matches if any listed finding is present. Supports `findingType`, `severity`, `cvssScore` (e.g. `">= 9.0"`), and `id` (e.g. `"in [GPL-2.0-only, AGPL-3.0-only]"`).

`allOf` - nests multiple `anyOf` groups; all must match.

`scoreExceeds` - matches when the risk score for the specified `findingType` (or across all types if omitted) exceeds `threshold`.

`countOf` - matches when the number of findings of the given type and severity list meets or exceeds `threshold`.

### Modifying policy at runtime

Set `Policies.HotReload: true` in `appsettings.json` to have the policy file reloaded automatically when it changes on disk. When `HotReload` is `false`, a restart is required to pick up changes.

## Dashboard and API

The web dashboard is at `http://localhost:5050/ui`. It shows summary stats and a filterable request log with ecosystem, package name, outcome, client IP, and duration. A server info page at `/ui/server-info` shows the resolved paths for `appsettings.json`, `policy.yaml`, and the data directory.

The management API is at `http://localhost:5050/api/v1`:

| Endpoint | Description |
|----------|-------------|
| `GET /api/v1/stats` | Total, blocked, and allowed request counts |
| `GET /api/v1/requests` | Paginated request log; filter by `ecosystem`, `packageName`, `blocked`, `from`, `to` |
| `GET /api/v1/requests/{id}` | Full detail for a single request including all findings |
| `GET /api/v1/system/status` | Health check - returns `{ "status": "ok", "timestamp": "..." }` |
| `GET /api/v1/system/info` | Server paths - returns `appsettingsPath`, `policyFilePath`, `dataDirectory` |

Example - list the last 10 blocked npm requests:
```
curl "http://localhost:5050/api/v1/requests?ecosystem=npm&blocked=true&pageSize=10"
```
