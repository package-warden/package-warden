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

using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using PackageWarden.Core.Domain;
using PackageWarden.Store.Sqlite;

namespace PackageWarden.Store.Sqlite.Tests;

public class SqliteStateStoreTests : IDisposable
{
    private readonly string _dbPath;
    private readonly SqliteStateStore _store;

    public SqliteStateStoreTests()
    {
        _dbPath = Path.Combine(Path.GetTempPath(), $"test-{Guid.NewGuid()}.db");
        var opts = Options.Create(new SqliteStateStoreOptions { DatabasePath = _dbPath });
        _store = new SqliteStateStore(opts, NullLogger<SqliteStateStore>.Instance);
    }

    public void Dispose()
    {
        if (File.Exists(_dbPath)) File.Delete(_dbPath);
    }

    private static ProxyRequest MakeRequest(bool blocked = false) => new()
    {
        RequestId = Guid.NewGuid(),
        Timestamp = DateTimeOffset.UtcNow,
        Ecosystem = "npm",
        PackageName = "lodash",
        PackageVersion = "4.17.21",
        UpstreamUrl = "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
        ClientIp = "127.0.0.1",
        Blocked = blocked,
        BlockReason = blocked ? "block-malware" : null,
        BlockMode = blocked ? PolicyBlockMode.Hard : null,
        Duration = TimeSpan.FromMilliseconds(42),
        RiskScore = new PackageRiskScore(0, []),
        Findings = []
    };

    [Fact]
    public async Task RecordAndRetrieve_Works()
    {
        var req = MakeRequest();
        await _store.RecordRequestAsync(req);

        var retrieved = await _store.GetRequestAsync(req.RequestId);
        retrieved.Should().NotBeNull();
        retrieved!.PackageName.Should().Be("lodash");
        retrieved.Ecosystem.Should().Be("npm");
        retrieved.Blocked.Should().BeFalse();
    }

    [Fact]
    public async Task RecordWithFindings_FindingsStored()
    {
        var req = MakeRequest(blocked: true) with
        {
            Findings = [
                new VulnerabilityFinding
                {
                    VulnerabilityId = "CVE-2024-1234",
                    Severity = Severity.Critical,
                    CvssScore = 9.8m,
                    Summary = "Test vulnerability",
                    ReportedBy = ["OsvDev"]
                }
            ]
        };

        await _store.RecordRequestAsync(req);

        var retrieved = await _store.GetRequestAsync(req.RequestId);
        retrieved!.Findings.Should().HaveCount(1);
        var vuln = retrieved.Findings[0].Should().BeOfType<VulnerabilityFinding>().Subject;
        vuln.VulnerabilityId.Should().Be("CVE-2024-1234");
        vuln.CvssScore.Should().Be(9.8m);
    }

    [Fact]
    public async Task QueryRequests_FilterByEcosystem()
    {
        var npmReq = MakeRequest() with { Ecosystem = "npm" };
        var nugetReq = new ProxyRequest
        {
            RequestId = Guid.NewGuid(),
            Timestamp = DateTimeOffset.UtcNow,
            Ecosystem = "nuget",
            PackageName = "Newtonsoft.Json",
            PackageVersion = "13.0.3",
            UpstreamUrl = "https://api.nuget.org/...",
            ClientIp = "127.0.0.1",
            Duration = TimeSpan.FromMilliseconds(10),
            RiskScore = new PackageRiskScore(0, []),
            Findings = []
        };

        await _store.RecordRequestAsync(npmReq);
        await _store.RecordRequestAsync(nugetReq);

        var result = await _store.QueryRequestsAsync(new RequestQuery(null, null, "npm", null, null));
        result.Items.Should().HaveCount(1);
        result.Items[0].Ecosystem.Should().Be("npm");
    }

    [Fact]
    public async Task GetStats_ReturnsCorrectCounts()
    {
        var allowed = MakeRequest(blocked: false);
        var blocked = MakeRequest(blocked: true);

        await _store.RecordRequestAsync(allowed);
        await _store.RecordRequestAsync(blocked);

        var stats = await _store.GetStatsAsync();
        stats.TotalRequests.Should().Be(2);
        stats.BlockedRequests.Should().Be(1);
        stats.AllowedRequests.Should().Be(1);
    }

    // ── Exception tests ──────────────────────────────────────────────────────

    private static PackageException MakeException(string? version = "4.17.21") => new()
    {
        ExceptionId = Guid.NewGuid(),
        Ecosystem = "npm",
        PackageName = "lodash",
        PackageVersion = version,
        GrantedAt = DateTimeOffset.UtcNow,
        FindingIds = ["Vulnerability:CVE-2024-1234", "License:MIT"],
        Notes = "Test exception"
    };

    [Fact]
    public async Task CreateException_CanBeRetrievedAsActive()
    {
        var ex = MakeException();
        await _store.CreateExceptionAsync(ex);

        var retrieved = await _store.GetActiveExceptionAsync("npm", "lodash", "4.17.21");

        retrieved.Should().NotBeNull();
        retrieved!.ExceptionId.Should().Be(ex.ExceptionId);
        retrieved.Ecosystem.Should().Be("npm");
        retrieved.PackageName.Should().Be("lodash");
        retrieved.PackageVersion.Should().Be("4.17.21");
        retrieved.FindingIds.Should().BeEquivalentTo(["Vulnerability:CVE-2024-1234", "License:MIT"]);
        retrieved.Notes.Should().Be("Test exception");
        retrieved.IsActive.Should().BeTrue();
        retrieved.RevokedAt.Should().BeNull();
    }

    [Fact]
    public async Task GetActiveException_ReturnsNull_WhenNoneExist()
    {
        var result = await _store.GetActiveExceptionAsync("npm", "lodash", "4.17.21");

        result.Should().BeNull();
    }

    [Fact]
    public async Task GetActiveException_DoesNotMatch_DifferentPackage()
    {
        await _store.CreateExceptionAsync(MakeException());

        var result = await _store.GetActiveExceptionAsync("npm", "other-package", "4.17.21");

        result.Should().BeNull();
    }

    [Fact]
    public async Task GetActiveException_DoesNotMatch_DifferentEcosystem()
    {
        await _store.CreateExceptionAsync(MakeException());

        var result = await _store.GetActiveExceptionAsync("pypi", "lodash", "4.17.21");

        result.Should().BeNull();
    }

    [Fact]
    public async Task GetActiveException_DoesNotMatch_DifferentVersion()
    {
        await _store.CreateExceptionAsync(MakeException("4.17.21"));

        var result = await _store.GetActiveExceptionAsync("npm", "lodash", "4.17.22");

        result.Should().BeNull();
    }

    [Fact]
    public async Task GetActiveException_WildcardVersion_MatchesVersionedRequest()
    {
        await _store.CreateExceptionAsync(MakeException(version: null));

        var result1 = await _store.GetActiveExceptionAsync("npm", "lodash", "4.17.21");
        var result2 = await _store.GetActiveExceptionAsync("npm", "lodash", "5.0.0");
        var result3 = await _store.GetActiveExceptionAsync("npm", "lodash", null);

        result1.Should().NotBeNull();
        result2.Should().NotBeNull();
        result3.Should().NotBeNull();
    }

    [Fact]
    public async Task GetActiveException_DoesNotReturn_RevokedExceptions()
    {
        var ex = MakeException();
        await _store.CreateExceptionAsync(ex);
        await _store.RevokeExceptionAsync(ex.ExceptionId);

        var result = await _store.GetActiveExceptionAsync("npm", "lodash", "4.17.21");

        result.Should().BeNull();
    }

    [Fact]
    public async Task RevokeException_SetsRevokedAt_AndMarksInactive()
    {
        var ex = MakeException();
        await _store.CreateExceptionAsync(ex);

        await _store.RevokeExceptionAsync(ex.ExceptionId);

        var listed = await _store.QueryExceptionsAsync(new ExceptionQuery());
        var stored = listed.Items.Single();
        stored.IsActive.Should().BeFalse();
        stored.RevokedAt.Should().NotBeNull();
        stored.RevokedAt!.Value.Should().BeCloseTo(DateTimeOffset.UtcNow, TimeSpan.FromSeconds(5));
    }

    [Fact]
    public async Task RevokeException_IsIdempotent()
    {
        var ex = MakeException();
        await _store.CreateExceptionAsync(ex);
        await _store.RevokeExceptionAsync(ex.ExceptionId);

        var act = () => _store.RevokeExceptionAsync(ex.ExceptionId);

        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task QueryExceptions_ActiveFilter_ReturnsOnlyActiveExceptions()
    {
        var active = MakeException() with { ExceptionId = Guid.NewGuid(), PackageVersion = "1.0.0" };
        var revoked = MakeException() with { ExceptionId = Guid.NewGuid(), PackageVersion = "2.0.0" };
        await _store.CreateExceptionAsync(active);
        await _store.CreateExceptionAsync(revoked);
        await _store.RevokeExceptionAsync(revoked.ExceptionId);

        var result = await _store.QueryExceptionsAsync(new ExceptionQuery(Active: true));

        result.TotalCount.Should().Be(1);
        result.Items[0].ExceptionId.Should().Be(active.ExceptionId);
        result.Items[0].IsActive.Should().BeTrue();
    }

    [Fact]
    public async Task QueryExceptions_RevokedFilter_ReturnsOnlyRevokedExceptions()
    {
        var active = MakeException() with { ExceptionId = Guid.NewGuid(), PackageVersion = "1.0.0" };
        var revoked = MakeException() with { ExceptionId = Guid.NewGuid(), PackageVersion = "2.0.0" };
        await _store.CreateExceptionAsync(active);
        await _store.CreateExceptionAsync(revoked);
        await _store.RevokeExceptionAsync(revoked.ExceptionId);

        var result = await _store.QueryExceptionsAsync(new ExceptionQuery(Active: false));

        result.TotalCount.Should().Be(1);
        result.Items[0].ExceptionId.Should().Be(revoked.ExceptionId);
        result.Items[0].IsActive.Should().BeFalse();
    }

    [Fact]
    public async Task QueryExceptions_NoFilter_ReturnsActiveAndRevoked()
    {
        var ex1 = MakeException() with { ExceptionId = Guid.NewGuid(), PackageVersion = "1.0.0" };
        var ex2 = MakeException() with { ExceptionId = Guid.NewGuid(), PackageVersion = "2.0.0" };
        await _store.CreateExceptionAsync(ex1);
        await _store.CreateExceptionAsync(ex2);
        await _store.RevokeExceptionAsync(ex2.ExceptionId);

        var result = await _store.QueryExceptionsAsync(new ExceptionQuery());

        result.TotalCount.Should().Be(2);
    }
}