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
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using PackageWarden.Core.Domain;
using PackageWarden.Core.Interfaces;

namespace PackageWarden.Store.Sqlite;

public class SqliteStateStore : IStateStore
{
    private readonly string _connectionString;
    private readonly ILogger<SqliteStateStore> _logger;

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    public SqliteStateStore(IOptions<SqliteStateStoreOptions> opts, ILogger<SqliteStateStore> logger)
    {
        _logger = logger;
        var path = opts.Value.DatabasePath;
        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        _connectionString = $"Data Source={path}";
        EnsureMigrated();
    }

    private void EnsureMigrated()
    {
        using var conn = new SqliteConnection(_connectionString);
        SqliteMigrator.Migrate(conn);
    }

    private SqliteConnection Open()
    {
        var conn = new SqliteConnection(_connectionString);
        conn.Open();
        // Enable WAL for concurrent read access
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;";
        cmd.ExecuteNonQuery();
        return conn;
    }

    public async Task RecordRequestAsync(ProxyRequest request, CancellationToken ct = default)
    {
        await using var conn = Open();
        await using var tx = await conn.BeginTransactionAsync(ct);

        var riskScore = request.RiskScore;
        var scoredFindings = riskScore?.ByFindingType.SelectMany(t => t.Findings.Select(sf => (t.FindingType, sf))).ToList()
                             ?? [];

        await using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO requests
                (id, timestamp, ecosystem, package, version, upstream, client_ip, blocked,
                 block_mode, block_reason, matched_count, threshold, risk_score, risk_score_threshold, duration_ms)
            VALUES
                (@id, @ts, @eco, @pkg, @ver, @up, @ip, @blocked,
                 @bm, @br, @mc, @th, @rs, @rst, @dur)
            ON CONFLICT(id) DO NOTHING;
            """;
        cmd.Parameters.AddWithValue("@id", request.RequestId.ToString());
        cmd.Parameters.AddWithValue("@ts", request.Timestamp.ToString("O"));
        cmd.Parameters.AddWithValue("@eco", request.Ecosystem);
        cmd.Parameters.AddWithValue("@pkg", request.PackageName);
        cmd.Parameters.AddWithValue("@ver", (object?)request.PackageVersion ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@up", request.UpstreamUrl);
        cmd.Parameters.AddWithValue("@ip", request.ClientIp);
        cmd.Parameters.AddWithValue("@blocked", request.Blocked ? 1 : 0);
        cmd.Parameters.AddWithValue("@bm", (object?)request.BlockMode?.ToString() ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@br", (object?)request.BlockReason ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@mc", (object?)request.MatchedCount ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@th", (object?)request.Threshold ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@rs", (object?)riskScore?.TotalScore ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@rst", (object?)request.RiskScoreThreshold ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@dur", (long)request.Duration.TotalMilliseconds);
        await cmd.ExecuteNonQueryAsync(ct);

        foreach (var finding in request.Findings)
        {
            var scored = scoredFindings.FirstOrDefault(sf => sf.sf.Finding == finding);
            var score = scored.sf?.Score ?? 0m;

            await using var fCmd = conn.CreateCommand();
            fCmd.CommandText = """
                INSERT INTO findings
                    (id, request_id, finding_type, finding_id, severity, cvss_score, score, reported_by, data)
                VALUES
                    (@id, @rid, @ft, @fid, @sev, @cvss, @score, @rb, @data)
                ON CONFLICT(id) DO NOTHING;
                """;
            fCmd.Parameters.AddWithValue("@id", Guid.NewGuid().ToString());
            fCmd.Parameters.AddWithValue("@rid", request.RequestId.ToString());
            fCmd.Parameters.AddWithValue("@ft", finding.Type.ToString());
            fCmd.Parameters.AddWithValue("@fid", finding.Id);
            fCmd.Parameters.AddWithValue("@sev", finding.Severity.ToString());
            fCmd.Parameters.AddWithValue("@cvss", finding is VulnerabilityFinding v ? (object?)v.CvssScore ?? DBNull.Value : DBNull.Value);
            fCmd.Parameters.AddWithValue("@score", score);
            fCmd.Parameters.AddWithValue("@rb", JsonSerializer.Serialize(finding.ReportedBy, JsonOpts));
            fCmd.Parameters.AddWithValue("@data", JsonSerializer.Serialize(finding, finding.GetType(), JsonOpts));
            await fCmd.ExecuteNonQueryAsync(ct);
        }

        await tx.CommitAsync(ct);
    }

    public async Task<PagedResult<ProxyRequest>> QueryRequestsAsync(RequestQuery query, CancellationToken ct = default)
    {
        await using var conn = Open();

        var where = new List<string>();
        var p = new Dictionary<string, object?>();

        if (query.From.HasValue) { where.Add("timestamp >= @from"); p["@from"] = query.From.Value.ToString("O"); }
        if (query.To.HasValue) { where.Add("timestamp <= @to"); p["@to"] = query.To.Value.ToString("O"); }
        if (query.Ecosystem is not null) { where.Add("ecosystem = @eco"); p["@eco"] = query.Ecosystem; }
        if (query.PackageName is not null) { where.Add("package LIKE @pkg"); p["@pkg"] = $"%{query.PackageName}%"; }
        if (query.Blocked.HasValue) { where.Add("blocked = @bl"); p["@bl"] = query.Blocked.Value ? 1 : 0; }

        var whereClause = where.Count > 0 ? "WHERE " + string.Join(" AND ", where) : "";

        await using var countCmd = conn.CreateCommand();
        countCmd.CommandText = $"SELECT COUNT(*) FROM requests {whereClause}";
        foreach (var (k, v) in p) countCmd.Parameters.AddWithValue(k, v ?? DBNull.Value);
        var total = Convert.ToInt32(await countCmd.ExecuteScalarAsync(ct));

        await using var cmd = conn.CreateCommand();
        cmd.CommandText = $"""
            SELECT id, timestamp, ecosystem, package, version, upstream, client_ip,
                   blocked, block_mode, block_reason, matched_count, threshold,
                   risk_score, risk_score_threshold, duration_ms
            FROM requests {whereClause}
            ORDER BY timestamp DESC
            LIMIT @limit OFFSET @offset
            """;
        foreach (var (k, v) in p) cmd.Parameters.AddWithValue(k, v ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@limit", query.PageSize);
        cmd.Parameters.AddWithValue("@offset", (query.Page - 1) * query.PageSize);

        var items = new List<ProxyRequest>();
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            items.Add(ReadRequest(reader));
        }

        // Load findings for each request
        foreach (var req in items)
        {
            req.Findings = await LoadFindingsAsync(conn, req.RequestId, ct);
        }

        return new PagedResult<ProxyRequest>(items, total, query.Page, query.PageSize);
    }

    public async Task<ProxyRequest?> GetRequestAsync(Guid requestId, CancellationToken ct = default)
    {
        await using var conn = Open();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT id, timestamp, ecosystem, package, version, upstream, client_ip,
                   blocked, block_mode, block_reason, matched_count, threshold,
                   risk_score, risk_score_threshold, duration_ms
            FROM requests WHERE id = @id
            """;
        cmd.Parameters.AddWithValue("@id", requestId.ToString());

        await using var reader = await cmd.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct)) return null;
        var req = ReadRequest(reader);
        req.Findings = await LoadFindingsAsync(conn, requestId, ct);
        return req;
    }

    public async Task<SystemStats> GetStatsAsync(DateTimeOffset? since = null, CancellationToken ct = default)
    {
        await using var conn = Open();

        var sinceClause = since.HasValue ? "WHERE timestamp >= @since" : "";

        await using var cmd = conn.CreateCommand();
        cmd.CommandText = $"""
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END) as blocked,
                ecosystem
            FROM requests {sinceClause}
            GROUP BY ecosystem
            """;
        if (since.HasValue) cmd.Parameters.AddWithValue("@since", since.Value.ToString("O"));

        var byEco = new List<EcosystemStats>();
        int total = 0, blocked = 0;

        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var ecoTotal = reader.GetInt32(0);
            var ecoBlocked = reader.GetInt32(1);
            var eco = reader.GetString(2);
            byEco.Add(new EcosystemStats(eco, ecoTotal, ecoBlocked));
            total += ecoTotal;
            blocked += ecoBlocked;
        }

        return new SystemStats(total, blocked, total - blocked, byEco);
    }

    private static ProxyRequest ReadRequest(SqliteDataReader r)
    {
        PolicyBlockMode? blockMode = null;
        if (!r.IsDBNull(8) && Enum.TryParse<PolicyBlockMode>(r.GetString(8), out var bm))
            blockMode = bm;

        return new ProxyRequest
        {
            RequestId = Guid.Parse(r.GetString(0)),
            Timestamp = DateTimeOffset.Parse(r.GetString(1)),
            Ecosystem = r.GetString(2),
            PackageName = r.GetString(3),
            PackageVersion = r.IsDBNull(4) ? null : r.GetString(4),
            UpstreamUrl = r.GetString(5),
            ClientIp = r.GetString(6),
            Blocked = r.GetInt32(7) == 1,
            BlockMode = blockMode,
            BlockReason = r.IsDBNull(9) ? null : r.GetString(9),
            MatchedCount = r.IsDBNull(10) ? null : r.GetInt32(10),
            Threshold = r.IsDBNull(11) ? null : r.GetInt32(11),
            RiskScore = r.IsDBNull(12) ? null : new PackageRiskScore(r.GetDecimal(12), []),
            RiskScoreThreshold = r.IsDBNull(13) ? null : r.GetDecimal(13),
            Duration = TimeSpan.FromMilliseconds(r.GetInt64(14))
        };
    }

    private async Task<IReadOnlyList<Finding>> LoadFindingsAsync(SqliteConnection conn, Guid requestId, CancellationToken ct)
    {
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT finding_type, data FROM findings WHERE request_id = @rid ORDER BY severity DESC";
        cmd.Parameters.AddWithValue("@rid", requestId.ToString());

        var findings = new List<Finding>();
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var type = reader.GetString(0);
            var json = reader.GetString(1);
            var finding = DeserializeFinding(type, json);
            if (finding is not null) findings.Add(finding);
        }
        return findings;
    }

    public async Task CreateExceptionAsync(PackageException exception, CancellationToken ct = default)
    {
        await using var conn = Open();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO exceptions (id, ecosystem, package, version, granted_at, revoked_at, request_id, finding_ids, notes)
            VALUES (@id, @eco, @pkg, @ver, @ga, NULL, @rid, @fids, @notes)
            ON CONFLICT(id) DO NOTHING;
            """;
        cmd.Parameters.AddWithValue("@id", exception.ExceptionId.ToString());
        cmd.Parameters.AddWithValue("@eco", exception.Ecosystem);
        cmd.Parameters.AddWithValue("@pkg", exception.PackageName);
        cmd.Parameters.AddWithValue("@ver", (object?)exception.PackageVersion ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@ga", exception.GrantedAt.ToString("O"));
        cmd.Parameters.AddWithValue("@rid", (object?)exception.GrantedForRequestId?.ToString() ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@fids", JsonSerializer.Serialize(exception.FindingIds, JsonOpts));
        cmd.Parameters.AddWithValue("@notes", (object?)exception.Notes ?? DBNull.Value);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task<PackageException?> GetActiveExceptionAsync(string ecosystem, string packageName, string? version, CancellationToken ct = default)
    {
        await using var conn = Open();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT id, ecosystem, package, version, granted_at, revoked_at, request_id, finding_ids, notes
            FROM exceptions
            WHERE ecosystem = @eco AND package = @pkg AND revoked_at IS NULL
              AND (version IS NULL OR version = @ver)
            ORDER BY granted_at DESC
            LIMIT 1
            """;
        cmd.Parameters.AddWithValue("@eco", ecosystem);
        cmd.Parameters.AddWithValue("@pkg", packageName);
        cmd.Parameters.AddWithValue("@ver", (object?)version ?? DBNull.Value);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct)) return null;
        return ReadException(reader);
    }

    public async Task<PagedResult<PackageException>> QueryExceptionsAsync(ExceptionQuery query, CancellationToken ct = default)
    {
        await using var conn = Open();

        var whereClause = query.Active switch
        {
            true => "WHERE revoked_at IS NULL",
            false => "WHERE revoked_at IS NOT NULL",
            null => ""
        };

        await using var countCmd = conn.CreateCommand();
        countCmd.CommandText = $"SELECT COUNT(*) FROM exceptions {whereClause}";
        var total = Convert.ToInt32(await countCmd.ExecuteScalarAsync(ct));

        await using var cmd = conn.CreateCommand();
        cmd.CommandText = $"""
            SELECT id, ecosystem, package, version, granted_at, revoked_at, request_id, finding_ids, notes
            FROM exceptions {whereClause}
            ORDER BY granted_at DESC
            LIMIT @limit OFFSET @offset
            """;
        cmd.Parameters.AddWithValue("@limit", query.PageSize);
        cmd.Parameters.AddWithValue("@offset", (query.Page - 1) * query.PageSize);

        var items = new List<PackageException>();
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
            items.Add(ReadException(reader));

        return new PagedResult<PackageException>(items, total, query.Page, query.PageSize);
    }

    public async Task RevokeExceptionAsync(Guid exceptionId, CancellationToken ct = default)
    {
        await using var conn = Open();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "UPDATE exceptions SET revoked_at = @ra WHERE id = @id AND revoked_at IS NULL";
        cmd.Parameters.AddWithValue("@ra", DateTimeOffset.UtcNow.ToString("O"));
        cmd.Parameters.AddWithValue("@id", exceptionId.ToString());
        await cmd.ExecuteNonQueryAsync(ct);
    }

    private static PackageException ReadException(SqliteDataReader r)
    {
        return new PackageException
        {
            ExceptionId = Guid.Parse(r.GetString(0)),
            Ecosystem = r.GetString(1),
            PackageName = r.GetString(2),
            PackageVersion = r.IsDBNull(3) ? null : r.GetString(3),
            GrantedAt = DateTimeOffset.Parse(r.GetString(4)),
            RevokedAt = r.IsDBNull(5) ? null : DateTimeOffset.Parse(r.GetString(5)),
            GrantedForRequestId = r.IsDBNull(6) ? null : Guid.Parse(r.GetString(6)),
            FindingIds = JsonSerializer.Deserialize<string[]>(r.GetString(7), JsonOpts) ?? [],
            Notes = r.IsDBNull(8) ? null : r.GetString(8)
        };
    }

    private Finding? DeserializeFinding(string type, string json)
    {
        try
        {
            return type switch
            {
                "Vulnerability" => JsonSerializer.Deserialize<VulnerabilityFinding>(json, JsonOpts),
                "License" => JsonSerializer.Deserialize<LicenseFinding>(json, JsonOpts),
                "Malware" => JsonSerializer.Deserialize<MalwareFinding>(json, JsonOpts),
                "DependencyConfusion" => JsonSerializer.Deserialize<DependencyConfusionFinding>(json, JsonOpts),
                "SourceRepository" => JsonSerializer.Deserialize<SourceRepositoryFinding>(json, JsonOpts),
                "HealthCheck" => JsonSerializer.Deserialize<HealthCheckFinding>(json, JsonOpts),
                _ => null
            };
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to deserialize finding of type {Type}", type);
            return null;
        }
    }
}