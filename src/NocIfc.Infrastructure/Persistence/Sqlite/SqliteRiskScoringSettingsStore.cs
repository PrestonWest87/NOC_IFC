using System.Globalization;
using Microsoft.Data.Sqlite;
using NocIfc.Application.Abstractions.Settings;
using NocIfc.Application.Features.Settings;
using NocIfc.Domain.Settings;

namespace NocIfc.Infrastructure.Persistence.Sqlite;

public sealed class SqliteRiskScoringSettingsStore(SqliteConnectionFactory connections) : IRiskScoringSettingsStore
{
    public async Task<RiskScoringSettings?> GetAsync(CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
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
            NullableDouble(reader, 1),
            NullableDouble(reader, 2),
            NullableInt(reader, 3),
            NullableInt(reader, 4),
            NullableInt(reader, 5),
            NullableInt(reader, 6),
            NullableInt(reader, 7),
            NullableInt(reader, 8),
            NullableInt(reader, 9),
            NullableInt(reader, 10),
            NullableInt(reader, 11),
            NullableInt(reader, 12));
    }

    public async Task UpdateAsync(RiskScoringSettings settings, CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using (var exists = connection.CreateCommand())
        {
            exists.CommandText = "SELECT 1 FROM system_config ORDER BY id LIMIT 1";
            if (await exists.ExecuteScalarAsync(cancellationToken) is null)
            {
                await SqliteApplicationSettingsStore.InsertDefaultsAsync(
                    connection,
                    new GlobalApplicationSettingsUpdate(null, null, null, null, null, null, null),
                    cancellationToken);
            }
        }

        using var transaction = connection.BeginTransaction();
        await using var configIdCommand = connection.CreateCommand();
        configIdCommand.Transaction = transaction;
        configIdCommand.CommandText = "SELECT id FROM system_config ORDER BY id LIMIT 1";
        var configId = await configIdCommand.ExecuteScalarAsync(cancellationToken);
        if (configId is null or DBNull)
        {
            return;
        }

        await using var update = connection.CreateCommand();
        update.Transaction = transaction;
        var assignments = new List<string>();
        AddUpdate(update, assignments, "scoring_mode", settings.ScoringMode);
        AddUpdate(update, assignments, "baseline_override_cyber", settings.BaselineOverrideCyber);
        AddUpdate(update, assignments, "baseline_override_phys", settings.BaselineOverridePhys);
        AddUpdate(update, assignments, "cyber_criticality_override", settings.CyberCriticalityOverride);
        AddUpdate(update, assignments, "cyber_lethality_override", settings.CyberLethalityOverride);
        AddUpdate(update, assignments, "physical_criticality_override", settings.PhysicalCriticalityOverride);
        AddUpdate(update, assignments, "physical_lethality_override", settings.PhysicalLethalityOverride);
        AddUpdate(update, assignments, "internal_criticality_override", settings.InternalCriticalityOverride);
        AddUpdate(update, assignments, "internal_lethality_override", settings.InternalLethalityOverride);
        AddUpdate(update, assignments, "global_risk_offset", settings.GlobalRiskOffset);
        AddUpdate(update, assignments, "internal_risk_offset", settings.InternalRiskOffset);
        AddUpdate(update, assignments, "sys_countermeasures", settings.SysCountermeasures);
        AddUpdate(update, assignments, "net_countermeasures", settings.NetCountermeasures);
        update.CommandText = $"UPDATE system_config SET {string.Join(", ", assignments)} WHERE id = $id";
        update.Parameters.AddWithValue("$id", Convert.ToInt64(configId, CultureInfo.InvariantCulture));
        await update.ExecuteNonQueryAsync(cancellationToken);
        transaction.Commit();
    }

    private static void AddUpdate<T>(SqliteCommand command, List<string> assignments, string field, T? value)
    {
        if (value is null)
        {
            return;
        }
        var parameter = $"${field}";
        assignments.Add($"{field} = {parameter}");
        command.Parameters.AddWithValue(parameter, value);
    }

    private static string? ReadString(SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);

    private static int? NullableInt(SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal) ? null : reader.GetInt32(ordinal);

    private static double? NullableDouble(SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal) ? null : reader.GetDouble(ordinal);
}
