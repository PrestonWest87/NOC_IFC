using System.Globalization;
using NocIfc.Domain.Dashboard;
using NocIfc.Infrastructure.Persistence.Sqlite;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class SqliteOperationalDashboardStoreTests
{
    [Fact]
    public async Task ReadsOperationalMetricsCurrentHazardsTrendsAndSavedBriefs()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"nocifc-dashboard-{Guid.NewGuid():N}.sqlite");
        using (File.Create(databasePath)) { }
        try
        {
            var connections = new SqliteConnectionFactory($"sqlite:///{databasePath}");
            var now = DateTime.UtcNow;
            await using (var connection = connections.Create())
            {
                await connection.OpenAsync();
                await using var setup = connection.CreateCommand();
                setup.CommandText = """
                    CREATE TABLE articles (id INTEGER PRIMARY KEY, published_date DATETIME, score REAL);
                    CREATE TABLE cve_items (id INTEGER PRIMARY KEY, date_added DATETIME);
                    CREATE TABLE regional_hazards (
                        id INTEGER PRIMARY KEY, hazard_id TEXT, hazard_type TEXT, severity TEXT,
                        title TEXT, description TEXT, location TEXT, updated_at DATETIME,
                        last_seen_at DATETIME, status TEXT, sent_at DATETIME, effective_at DATETIME,
                        onset_at DATETIME, expires_at DATETIME, event_ending_at DATETIME,
                        message_type TEXT, references_json TEXT, coverage_scope TEXT, coverage_precision TEXT
                    );
                    CREATE TABLE cloud_outages (id INTEGER PRIMARY KEY, updated_at DATETIME, is_resolved INTEGER);
                    CREATE TABLE daily_threat_scores (
                        id INTEGER PRIMARY KEY, record_date DATETIME, cyber_points REAL,
                        physical_points REAL, cyber_baseline REAL, physical_baseline REAL
                    );
                    CREATE TABLE system_config (
                        id INTEGER PRIMARY KEY, rolling_summary TEXT, rolling_summary_time DATETIME,
                        global_brief TEXT, global_brief_time DATETIME, internal_brief TEXT,
                        internal_brief_time DATETIME, unified_brief TEXT, unified_brief_time DATETIME,
                        last_global_risk TEXT, last_internal_risk TEXT
                    );
                    """;
                await setup.ExecuteNonQueryAsync();
                await using var seed = connection.CreateCommand();
                seed.CommandText = """
                    INSERT INTO articles VALUES (1, $recent, 80), (2, $recent, 20), (3, $old, 90);
                    INSERT INTO cve_items VALUES (1, $recent), (2, $old);
                    INSERT INTO regional_hazards VALUES
                        (1, 'haz-1', 'Tornado Warning', 'Severe', 'Current warning', 'Description', 'County', $recent, $recent, 'active', $recent, $past, NULL, $future, NULL, 'Alert', '["REF-1"]', 'state', 'county'),
                        (2, 'haz-2', 'Watch', 'Moderate', 'Expired warning', 'Description', 'County', $recent, $recent, 'active', $recent, $past, NULL, $past, NULL, 'Alert', '[]', 'state', 'county'),
                        (3, 'haz-3', 'Watch', 'Moderate', 'Future warning', 'Description', 'County', $recent, $recent, 'active', $recent, $future, NULL, $future, NULL, 'Alert', '[]', 'state', 'county'),
                        (4, 'haz-4', 'Watch', 'Moderate', 'Old warning', 'Description', 'County', $old, $old, 'active', $old, $past, NULL, $future, NULL, 'Alert', '[]', 'state', 'county');
                    INSERT INTO cloud_outages VALUES (1, $recent, 0), (2, $recent, 1);
                    INSERT INTO daily_threat_scores VALUES (1, $old, 1, 2, 3, 4), (2, $recent, 5, 6, 7, 8);
                    INSERT INTO system_config VALUES (1, 'shift', $recent, 'global', $recent, 'internal', $recent, 'unified', $recent, 'ORANGE', 'RED');
                    """;
                seed.Parameters.AddWithValue("$recent", FormatDate(now.AddHours(-12)));
                seed.Parameters.AddWithValue("$old", FormatDate(now.AddDays(-20)));
                seed.Parameters.AddWithValue("$past", FormatDate(now.AddHours(-1)));
                seed.Parameters.AddWithValue("$future", FormatDate(now.AddHours(1)));
                await seed.ExecuteNonQueryAsync();
            }

            var store = new SqliteOperationalDashboardStore(connections);
            var metrics = await store.GetMetricsAsync(now.AddDays(-1), now, CancellationToken.None);
            Assert.Equal(new DashboardMetrics(1, 1, 1, 1), metrics);

            var hazards = await store.GetHazardsAsync(now, 10, CancellationToken.None);
            Assert.Equal(new[] { 1, 4 }, hazards.Select(hazard => hazard.Id));
            Assert.Equal("REF-1", hazards[0].ReferencesJson!.Value.EnumerateArray().Single().GetString());

            var trends = await store.GetThreatTrendsAsync(now.AddDays(-14), CancellationToken.None);
            Assert.Single(trends);
            Assert.Equal(2, trends[0].Id);
            Assert.Equal((double?)5, trends[0].CyberPoints);

            var briefs = Assert.IsType<NocIfc.Domain.Dashboard.DashboardBriefSnapshot>(
                await store.GetBriefsAsync(CancellationToken.None));
            Assert.Equal("shift", briefs.RollingSummary);
            Assert.Equal("unified", briefs.UnifiedBrief);
            Assert.Equal("ORANGE", briefs.LastGlobalRisk);
            Assert.Equal("RED", briefs.LastInternalRisk);
            Assert.True(await store.SaveUnifiedBriefAsync("New unified brief", now, CancellationToken.None));
            Assert.True(await store.SaveGlobalBriefAsync("New global brief", now, CancellationToken.None));
            var savedBrief = await store.GetBriefsAsync(CancellationToken.None);
            Assert.Equal("New unified brief", savedBrief?.UnifiedBrief);
            Assert.Equal("New global brief", savedBrief?.GlobalBrief);
        }
        finally
        {
            File.Delete(databasePath);
        }
    }

    private static string FormatDate(DateTime value) =>
        value.ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture);
}
