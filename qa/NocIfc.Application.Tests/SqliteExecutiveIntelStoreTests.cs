using System.Globalization;
using NocIfc.Infrastructure.Persistence.Sqlite;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class SqliteExecutiveIntelStoreTests
{
    [Fact]
    public async Task LoadsExecutiveInputsAndKeepsTheHighestDailyScore()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"nocifc-executive-intel-{Guid.NewGuid():N}.sqlite");
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
                    CREATE TABLE system_config (
                        id INTEGER PRIMARY KEY, scoring_mode TEXT, baseline_override_cyber REAL,
                        baseline_override_phys REAL, cyber_criticality_override INTEGER,
                        cyber_lethality_override INTEGER, physical_criticality_override INTEGER,
                        physical_lethality_override INTEGER, internal_criticality_override INTEGER,
                        internal_lethality_override INTEGER, global_risk_offset INTEGER,
                        internal_risk_offset INTEGER, sys_countermeasures INTEGER, net_countermeasures INTEGER
                    );
                    INSERT INTO system_config VALUES (1, 'hybrid', 21, 26, 2, 3, 4, 5, 1, 2, -1, 0, 3, 4);
                    CREATE TABLE daily_threat_scores (
                        id INTEGER PRIMARY KEY, record_date DATETIME UNIQUE,
                        cyber_points REAL, physical_points REAL, cyber_baseline REAL, physical_baseline REAL
                    );
                    CREATE TABLE articles (
                        id INTEGER PRIMARY KEY, title TEXT, link TEXT, summary TEXT,
                        published_date DATETIME, source TEXT, score REAL, category TEXT,
                        keywords_found TEXT, is_bubbled INTEGER, story_group TEXT,
                        human_feedback INTEGER, full_content TEXT, ai_bluf TEXT,
                        is_pinned INTEGER, ingested_at DATETIME, enrichment_status TEXT,
                        enrichment_attempts INTEGER, last_enrichment_error TEXT, last_enriched_at DATETIME
                    );
                    CREATE TABLE cve_items (
                        id INTEGER PRIMARY KEY, cve_id TEXT, vendor TEXT, product TEXT,
                        vulnerability_name TEXT, date_added DATETIME, description TEXT,
                        required_action TEXT, due_date TEXT
                    );
                    CREATE TABLE crime_incidents (
                        id TEXT PRIMARY KEY, category TEXT, raw_title TEXT, timestamp DATETIME,
                        distance_miles REAL, severity TEXT, lat REAL, lon REAL
                    );
                    CREATE TABLE regional_hazards (
                        id INTEGER PRIMARY KEY, status TEXT, updated_at DATETIME,
                        expires_at DATETIME, effective_at DATETIME
                    );
                    """;
                await setup.ExecuteNonQueryAsync();
                await InsertArticleAsync(connection, 1, "Cyber entry", "Exploits", "Cyber: Exploits & Vulns", 80, "Cyber Feed", now.AddHours(-2));
                await InsertArticleAsync(connection, 2, "ICS advisory", "KEV in the wild", "General", 30, "CISA Advisories", now.AddHours(-3));
                await InsertArticleAsync(connection, 3, "Physical event", "Arkansas grid threat", "Physical Security & Crime", 75, "Local", now.AddHours(-4));
                await InsertArticleAsync(connection, 4, "Old cyber", "Old report", "Cyber: Exploits & Vulns", 90, "Cyber Feed", now.AddDays(-2));
                await using var seeds = connection.CreateCommand();
                seeds.CommandText = """
                    INSERT INTO cve_items VALUES (1, 'CVE-2026-0001', 'Vendor', 'Product', 'Issue', $recent, 'Description', 'Patch', '2026-12-01');
                    INSERT INTO crime_incidents VALUES
                        ('grid', 'Asset/Copper Theft Risk', 'Copper theft', $recent, 0.5, 'High', 34.7, -92.3),
                        ('other', 'Noise', 'Unrelated', $recent, 0.5, 'Low', 34.8, -92.4);
                    INSERT INTO regional_hazards VALUES
                        (1, 'active', $recent, $future, $past),
                        (2, 'active', $recent, $past, $past),
                        (3, 'active', $recent, $future, $future);
                    INSERT INTO daily_threat_scores VALUES
                        (1, $old_history, 10, 20, 20, 25), (2, $history, 12, 22, 20, 25);
                    """;
                seeds.Parameters.AddWithValue("$recent", FormatDate(now.AddHours(-1)));
                seeds.Parameters.AddWithValue("$future", FormatDate(now.AddHours(1)));
                seeds.Parameters.AddWithValue("$past", FormatDate(now.AddHours(-1)));
                seeds.Parameters.AddWithValue("$history", FormatDate(now.AddDays(-3)));
                seeds.Parameters.AddWithValue("$old_history", FormatDate(now.AddDays(-20)));
                await seeds.ExecuteNonQueryAsync();
            }

            var store = new SqliteExecutiveIntelStore(connections);
            var inputs = await store.GetInputsAsync(now.AddHours(-24), now, CancellationToken.None);
            Assert.Equal("hybrid", inputs.RiskSettings?.ScoringMode);
            Assert.Equal((double?)21, inputs.RiskSettings?.BaselineOverrideCyber);
            Assert.Equal(1, Assert.Single(inputs.CyberCandidates).Id);
            Assert.Equal(new[] { 1, 2, 3 }, inputs.RecentArticles.Select(article => article.Id));
            Assert.Equal(3, Assert.Single(inputs.PhysicalCandidates).Id);
            Assert.Single(inputs.RecentCves);
            Assert.Single(inputs.RecentCrimes);
            Assert.Equal(1, inputs.ActiveWarningCount);
            Assert.Single(inputs.ScoreHistory);
            var recentScored = await store.GetRecentScoredArticlesAsync(now.AddHours(-24), 250, CancellationToken.None);
            Assert.Equal(new[] { 1, 3 }, recentScored.Select(article => article.Id));

            await store.SaveDailyThreatScoreAsync(now.Date, 5, 2, 20, 25, CancellationToken.None);
            await store.SaveDailyThreatScoreAsync(now.Date, 3, 4, 22, 26, CancellationToken.None);
            var latest = await store.GetInputsAsync(now.AddHours(-24), now, CancellationToken.None);
            var daily = latest.ScoreHistory.Single(point => point.RecordDate?.Date == now.Date);
            Assert.Equal((double?)5, daily.CyberPoints);
            Assert.Equal((double?)4, daily.PhysicalPoints);
            Assert.Equal((double?)22, daily.CyberBaseline);
            Assert.Equal((double?)26, daily.PhysicalBaseline);
        }
        finally
        {
            File.Delete(databasePath);
        }
    }

    private static async Task InsertArticleAsync(
        Microsoft.Data.Sqlite.SqliteConnection connection,
        int id,
        string title,
        string summary,
        string category,
        int score,
        string source,
        DateTime published)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO articles (
                id, title, link, summary, published_date, source, score, category,
                keywords_found, is_bubbled, is_pinned, ingested_at, enrichment_status, enrichment_attempts
            ) VALUES ($id, $title, $link, $summary, $published, $source, $score, $category,
                      '[]', 0, 0, $published, 'complete', 1)
            """;
        command.Parameters.AddWithValue("$id", id);
        command.Parameters.AddWithValue("$title", title);
        command.Parameters.AddWithValue("$link", $"https://example.test/{id}");
        command.Parameters.AddWithValue("$summary", summary);
        command.Parameters.AddWithValue("$published", FormatDate(published));
        command.Parameters.AddWithValue("$source", source);
        command.Parameters.AddWithValue("$score", score);
        command.Parameters.AddWithValue("$category", category);
        await command.ExecuteNonQueryAsync();
    }

    private static string FormatDate(DateTime value) =>
        value.ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture);
}
