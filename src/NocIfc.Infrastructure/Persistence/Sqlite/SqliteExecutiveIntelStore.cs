using System.Globalization;
using Microsoft.Data.Sqlite;
using NocIfc.Application.Abstractions.Dashboard;
using NocIfc.Domain.Dashboard;
using NocIfc.Domain.Settings;
using NocIfc.Domain.Threat;

namespace NocIfc.Infrastructure.Persistence.Sqlite;

public sealed class SqliteExecutiveIntelStore(SqliteConnectionFactory connections) : IExecutiveIntelStore
{
    private static readonly string[] CyberCategories =
        ["Cyber: Exploits & Vulns", "Cyber: Malware & Threats", "ICS/OT & SCADA", "Cloud & IT Infrastructure"];
    private static readonly string[] PhysicalCategories =
        ["Physical Security & Crime", "Severe Weather & Natural Hazards", "Geopolitics & Policy"];
    private static readonly string[] GridCrimeCategories =
    [
        "Perimeter Breach/Vandalism", "Violent Proximity Threat", "Asset/Copper Theft Risk",
        "Trespassing/Suspicious Activity", "Public Disturbance/Narcotics",
    ];

    public async Task<ExecutiveIntelInputs> GetInputsAsync(
        DateTime sinceUtc,
        DateTime nowUtc,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        var riskSettings = await ReadRiskSettingsAsync(connection, cancellationToken);
        var history = await ReadHistoryAsync(connection, nowUtc.AddDays(-14), cancellationToken);
        var cyberArticles = await ReadArticlesAsync(
            connection,
            "published_date >= $since AND score >= 50 AND category IN ($c0, $c1, $c2, $c3)",
            "score DESC",
            200,
            cancellationToken,
            command =>
            {
                AddDate(command, "$since", sinceUtc);
                for (var index = 0; index < CyberCategories.Length; index++)
                {
                    command.Parameters.AddWithValue($"$c{index}", CyberCategories[index]);
                }
            });
        var recentArticles = await ReadArticlesAsync(
            connection,
            "published_date >= $since",
            "published_date DESC",
            150,
            cancellationToken,
            command => AddDate(command, "$since", sinceUtc));
        var physicalArticles = await ReadArticlesAsync(
            connection,
            "published_date >= $since AND score >= 50 AND category IN ($c0, $c1, $c2)",
            "score DESC",
            100,
            cancellationToken,
            command =>
            {
                AddDate(command, "$since", sinceUtc);
                for (var index = 0; index < PhysicalCategories.Length; index++)
                {
                    command.Parameters.AddWithValue($"$c{index}", PhysicalCategories[index]);
                }
            });
        var cves = await ReadRecentCvesAsync(connection, sinceUtc, cancellationToken);
        var crimes = await ReadGridCrimesAsync(connection, sinceUtc, cancellationToken);
        var activeWarnings = await CountActiveWarningsAsync(connection, nowUtc, cancellationToken);
        return new ExecutiveIntelInputs(
            riskSettings,
            history,
            cyberArticles,
            recentArticles,
            physicalArticles,
            cves,
            crimes,
            activeWarnings);
    }

    public async Task SaveDailyThreatScoreAsync(
        DateTime recordDateUtc,
        int cyberPoints,
        int physicalPoints,
        double cyberBaseline,
        double physicalBaseline,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO daily_threat_scores
                (record_date, cyber_points, physical_points, cyber_baseline, physical_baseline)
            VALUES ($record_date, $cyber_points, $physical_points, $cyber_baseline, $physical_baseline)
            ON CONFLICT(record_date) DO UPDATE SET
                cyber_points = MAX(daily_threat_scores.cyber_points, excluded.cyber_points),
                physical_points = MAX(daily_threat_scores.physical_points, excluded.physical_points),
                cyber_baseline = excluded.cyber_baseline,
                physical_baseline = excluded.physical_baseline
            """;
        AddDate(command, "$record_date", recordDateUtc);
        command.Parameters.AddWithValue("$cyber_points", cyberPoints);
        command.Parameters.AddWithValue("$physical_points", physicalPoints);
        command.Parameters.AddWithValue("$cyber_baseline", cyberBaseline);
        command.Parameters.AddWithValue("$physical_baseline", physicalBaseline);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task<RiskScoringSettings?> ReadRiskSettingsAsync(
        SqliteConnection connection,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT scoring_mode, baseline_override_cyber, baseline_override_phys,
                   cyber_criticality_override, cyber_lethality_override,
                   physical_criticality_override, physical_lethality_override,
                   internal_criticality_override, internal_lethality_override,
                   global_risk_offset, internal_risk_offset, sys_countermeasures, net_countermeasures
            FROM system_config
            ORDER BY id
            LIMIT 1
            """;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }
        return new RiskScoringSettings(
            ReadString(reader, 0),
            ReadDouble(reader, 1),
            ReadDouble(reader, 2),
            ReadInt(reader, 3),
            ReadInt(reader, 4),
            ReadInt(reader, 5),
            ReadInt(reader, 6),
            ReadInt(reader, 7),
            ReadInt(reader, 8),
            ReadInt(reader, 9),
            ReadInt(reader, 10),
            ReadInt(reader, 11),
            ReadInt(reader, 12));
    }

    private static async Task<IReadOnlyList<DailyThreatScoreEntry>> ReadHistoryAsync(
        SqliteConnection connection,
        DateTime sinceUtc,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT id, record_date, cyber_points, physical_points, cyber_baseline, physical_baseline
            FROM daily_threat_scores
            WHERE record_date >= $since
            ORDER BY record_date ASC
            """;
        AddDate(command, "$since", sinceUtc);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var rows = new List<DailyThreatScoreEntry>();
        while (await reader.ReadAsync(cancellationToken))
        {
            rows.Add(new DailyThreatScoreEntry(
                reader.GetInt32(0),
                ReadDateTime(reader, 1),
                ReadDouble(reader, 2),
                ReadDouble(reader, 3),
                ReadDouble(reader, 4),
                ReadDouble(reader, 5)));
        }
        return rows;
    }

    private static async Task<IReadOnlyList<ThreatArticle>> ReadArticlesAsync(
        SqliteConnection connection,
        string filter,
        string ordering,
        int limit,
        CancellationToken cancellationToken,
        Action<SqliteCommand> addParameters)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = $"SELECT {SqliteThreatArticleStore.ArticleColumns} FROM articles WHERE {filter} ORDER BY {ordering} LIMIT $limit";
        command.Parameters.AddWithValue("$limit", limit);
        addParameters(command);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var rows = new List<ThreatArticle>();
        while (await reader.ReadAsync(cancellationToken))
        {
            rows.Add(SqliteThreatArticleStore.ReadArticle(reader));
        }
        return rows;
    }

    private static async Task<IReadOnlyList<CisaKevEntry>> ReadRecentCvesAsync(
        SqliteConnection connection,
        DateTime sinceUtc,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT id, cve_id, vendor, product, vulnerability_name, date_added,
                   description, required_action, due_date
            FROM cve_items
            WHERE date_added >= $since
            """;
        AddDate(command, "$since", sinceUtc);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var cves = new List<CisaKevEntry>();
        while (await reader.ReadAsync(cancellationToken))
        {
            cves.Add(new CisaKevEntry(
                reader.GetInt32(0), ReadString(reader, 1), ReadString(reader, 2),
                ReadString(reader, 3), ReadString(reader, 4), ReadDateTime(reader, 5),
                ReadString(reader, 6), ReadString(reader, 7), ReadString(reader, 8)));
        }
        return cves;
    }

    private static async Task<IReadOnlyList<CrimeIncidentEntry>> ReadGridCrimesAsync(
        SqliteConnection connection,
        DateTime sinceUtc,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT id, category, raw_title, timestamp, distance_miles, severity, lat, lon
            FROM crime_incidents
            WHERE timestamp >= $since AND distance_miles <= 1.0
              AND category IN ($c0, $c1, $c2, $c3, $c4)
            ORDER BY timestamp DESC
            """;
        AddDate(command, "$since", sinceUtc);
        for (var index = 0; index < GridCrimeCategories.Length; index++)
        {
            command.Parameters.AddWithValue($"$c{index}", GridCrimeCategories[index]);
        }
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var incidents = new List<CrimeIncidentEntry>();
        while (await reader.ReadAsync(cancellationToken))
        {
            incidents.Add(new CrimeIncidentEntry(
                reader.GetString(0), ReadString(reader, 1), ReadString(reader, 2),
                ReadDateTime(reader, 3), ReadDouble(reader, 4), ReadString(reader, 5),
                ReadDouble(reader, 6), ReadDouble(reader, 7)));
        }
        return incidents;
    }

    private static async Task<int> CountActiveWarningsAsync(
        SqliteConnection connection,
        DateTime nowUtc,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT COUNT(*) FROM regional_hazards
            WHERE status = 'active'
              AND (expires_at IS NULL OR expires_at > $now)
              AND (effective_at IS NULL OR effective_at <= $now)
            """;
        AddDate(command, "$now", nowUtc);
        return Convert.ToInt32(await command.ExecuteScalarAsync(cancellationToken), CultureInfo.InvariantCulture);
    }

    private static void AddDate(SqliteCommand command, string name, DateTime value) =>
        command.Parameters.AddWithValue(name, value.ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture));

    private static string? ReadString(SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);

    private static int? ReadInt(SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal) ? null : reader.GetInt32(ordinal);

    private static double? ReadDouble(SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal) ? null : reader.GetDouble(ordinal);

    private static DateTime? ReadDateTime(SqliteDataReader reader, int ordinal)
    {
        if (reader.IsDBNull(ordinal))
        {
            return null;
        }
        return DateTime.SpecifyKind(reader.GetDateTime(ordinal), DateTimeKind.Unspecified);
    }
}
