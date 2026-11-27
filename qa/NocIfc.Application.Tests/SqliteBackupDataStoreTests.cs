using System.Text.Json.Nodes;
using NocIfc.Infrastructure.Persistence.Sqlite;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class SqliteBackupDataStoreTests
{
    [Fact]
    public async Task LegacySettingsBackupMergesMissingRowsAndModelExportKeepsAllowlist()
    {
        using var workspace = new TemporaryDirectory("nocifc-legacy-backup-");
        var databasePath = Path.Combine(workspace.Path, "database.sqlite");
        using (File.Create(databasePath)) { }
        var connections = new SqliteConnectionFactory($"sqlite:///{databasePath}");
        await using (var connection = connections.Create())
        {
            await connection.OpenAsync();
            await using var setup = connection.CreateCommand();
            setup.CommandText = """
                CREATE TABLE keywords (id INTEGER PRIMARY KEY, word TEXT UNIQUE, weight INTEGER);
                CREATE TABLE feed_sources (id INTEGER PRIMARY KEY, url TEXT UNIQUE, name TEXT);
                CREATE TABLE monitored_locations (
                    id INTEGER PRIMARY KEY, name TEXT UNIQUE, lat REAL, lon REAL, loc_type TEXT, priority TEXT
                );
                CREATE TABLE node_aliases (
                    id INTEGER PRIMARY KEY, node_pattern TEXT, mapped_location_name TEXT,
                    confidence_score REAL, is_verified BOOLEAN
                );
                INSERT INTO keywords VALUES (1, 'existing', 10);
                """;
            await setup.ExecuteNonQueryAsync();
        }

        var store = new SqliteBackupDataStore(connections);
        var restore = JsonNode.Parse("""
            {
              "keywords": [{ "word": "new keyword", "weight": 22 }, { "word": "existing", "weight": 99 }],
              "feeds": [{ "url": "https://feeds.example/rss", "name": "New feed" }],
              "locations": [{ "name": "North", "lat": 34.7, "lon": -92.3, "type": "SCADA", "prio": "P2-High" }],
              "aliases": [{ "pattern": "node-a", "mapped": "North", "conf": 0.9, "ver": true }]
            }
            """)!.AsObject();

        var added = await store.RestoreLegacySettingsBackupAsync(restore, CancellationToken.None);
        await store.RestoreLegacySettingsBackupAsync(restore, CancellationToken.None);
        var backup = await store.GetLegacySettingsBackupAsync(CancellationToken.None);
        var export = await store.ExportAllTablesAsync(CancellationToken.None);

        Assert.Equal(1, added["kw"]);
        Assert.Equal(1, added["feeds"]);
        Assert.Equal(1, added["locs"]);
        Assert.Equal(1, added["alias"]);
        Assert.Equal(2, backup["keywords"]!.AsArray().Count);
        Assert.Equal("https://feeds.example/rss", backup["feeds"]![0]!["url"]!.GetValue<string>());
        Assert.True(backup["aliases"]![0]!["ver"]!.GetValue<bool>());
        Assert.Equal(2, export["keywords"]!.AsArray().Count);
        Assert.False(export.ContainsKey("user_sessions"));
    }

    [Fact]
    public async Task FullLegacyImportReplacesOnlyProvidedTablesAndMergeSkipsExistingIds()
    {
        using var workspace = new TemporaryDirectory("nocifc-import-all-");
        var databasePath = Path.Combine(workspace.Path, "database.sqlite");
        using (File.Create(databasePath)) { }
        var connections = new SqliteConnectionFactory($"sqlite:///{databasePath}");
        await using (var connection = connections.Create())
        {
            await connection.OpenAsync();
            await using var setup = connection.CreateCommand();
            setup.CommandText = """
                CREATE TABLE keywords (id INTEGER PRIMARY KEY, word TEXT UNIQUE, weight INTEGER);
                INSERT INTO keywords VALUES (1, 'old', 10);
                """;
            await setup.ExecuteNonQueryAsync();
        }

        var store = new SqliteBackupDataStore(connections);
        var replacement = JsonNode.Parse("""
            { "keywords": [{ "id": 2, "word": "new", "weight": 20 }] }
            """)!.AsObject();
        var merged = JsonNode.Parse("""
            { "keywords": [{ "id": 2, "word": "different", "weight": 99 }, { "id": 3, "word": "third", "weight": 30 }] }
            """)!.AsObject();

        await store.ImportAllTablesAsync(replacement, merge: false, CancellationToken.None);
        await store.ImportAllTablesAsync(merged, merge: true, CancellationToken.None);
        var exported = await store.ExportAllTablesAsync(CancellationToken.None);
        var words = exported["keywords"]!.AsArray()
            .Select(row => row!["word"]!.GetValue<string>()).ToArray();

        Assert.Equal(2, exported["keywords"]!.AsArray().Count);
        Assert.Contains("new", words);
        Assert.Contains("third", words);
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        public string Path { get; }
        public TemporaryDirectory(string prefix) => Path = Directory.CreateTempSubdirectory(prefix).FullName;
        public void Dispose() => Directory.Delete(Path, true);
    }
}
