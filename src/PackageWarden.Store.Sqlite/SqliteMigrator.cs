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

using System.Reflection;
using Microsoft.Data.Sqlite;

namespace PackageWarden.Store.Sqlite;

public static class SqliteMigrator
{
    public static void Migrate(SqliteConnection conn)
    {
        conn.Open();

        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL
            );
            """;
        cmd.ExecuteNonQuery();

        var appliedVersions = GetAppliedVersions(conn);
        var assembly = Assembly.GetExecutingAssembly();
        var prefix = "PackageWarden.Store.Sqlite.Migrations.";

        var scripts = assembly.GetManifestResourceNames()
            .Where(n => n.StartsWith(prefix) && n.EndsWith(".sql"))
            .OrderBy(n => n)
            .Select(n => (
                Version: ParseVersion(n[prefix.Length..]),
                ResourceName: n))
            .Where(t => !appliedVersions.Contains(t.Version));

        foreach (var (version, resourceName) in scripts)
        {
            using var stream = assembly.GetManifestResourceStream(resourceName)!;
            using var reader = new StreamReader(stream);
            var sql = reader.ReadToEnd();

            using var tx = conn.BeginTransaction();
            using var scriptCmd = conn.CreateCommand();
            scriptCmd.CommandText = sql;
            scriptCmd.ExecuteNonQuery();

            using var markCmd = conn.CreateCommand();
            markCmd.CommandText = "INSERT INTO schema_migrations (version, applied_at) VALUES (@v, @a)";
            markCmd.Parameters.AddWithValue("@v", version);
            markCmd.Parameters.AddWithValue("@a", DateTimeOffset.UtcNow.ToString("O"));
            markCmd.ExecuteNonQuery();
            tx.Commit();
        }
    }

    private static HashSet<int> GetAppliedVersions(SqliteConnection conn)
    {
        var result = new HashSet<int>();
        try
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT version FROM schema_migrations";
            using var reader = cmd.ExecuteReader();
            while (reader.Read()) result.Add(reader.GetInt32(0));
        }
        catch { /* table may not exist yet */ }
        return result;
    }

    private static int ParseVersion(string filename)
    {
        var part = filename.Split('_')[0];
        return int.TryParse(part, out var v) ? v : 0;
    }
}