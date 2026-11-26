using System.Globalization;
using Microsoft.Data.Sqlite;
using NocIfc.Application.Abstractions.Settings;
using NocIfc.Application.Features.Settings;

namespace NocIfc.Infrastructure.Persistence.Sqlite;

public sealed class SqliteApplicationSettingsStore(SqliteConnectionFactory connections) : IApplicationSettingsStore
{
    public async Task<GlobalApplicationSettings?> GetAsync(CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT public_app_url, tech_stack, monitored_asns,
                   failed_login_alert_enabled, failed_login_alert_recipients,
                   failed_login_alert_threshold, failed_login_alert_window_minutes
            FROM system_config
            ORDER BY id
            LIMIT 1
            """;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }
        return new GlobalApplicationSettings(
            ReadString(reader, 0) ?? "",
            ReadString(reader, 1) ?? "",
            ReadString(reader, 2) ?? "",
            !reader.IsDBNull(3) && reader.GetBoolean(3),
            ReadString(reader, 4) ?? "",
            reader.IsDBNull(5) ? 5 : reader.GetInt32(5),
            reader.IsDBNull(6) ? 5 : reader.GetInt32(6));
    }

    public async Task<bool> ActiveEmailProfileIsReadyAsync(CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT active_smtp_provider, smtp_server, smtp_sender, smtp_enabled,
                   gmail_smtp_username, gmail_smtp_client_id, gmail_smtp_client_secret,
                   gmail_smtp_refresh_token, gmail_smtp_sender, gmail_smtp_enabled
            FROM system_config
            ORDER BY id
            LIMIT 1
            """;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return false;
        }

        var provider = ReadString(reader, 0);
        if (string.IsNullOrEmpty(provider))
        {
            provider = "smtp";
        }
        if (provider == "smtp")
        {
            return !reader.IsDBNull(3) && reader.GetBoolean(3)
                && !string.IsNullOrWhiteSpace(ReadString(reader, 1))
                && !string.IsNullOrWhiteSpace(ReadString(reader, 2));
        }
        if (provider != "gmail")
        {
            return false;
        }

        var username = ReadString(reader, 4);
        var sender = ReadString(reader, 8);
        return !reader.IsDBNull(9) && reader.GetBoolean(9)
            && !string.IsNullOrWhiteSpace(username)
            && !string.IsNullOrWhiteSpace(ReadString(reader, 5))
            && !string.IsNullOrWhiteSpace(ReadString(reader, 6))
            && !string.IsNullOrWhiteSpace(ReadString(reader, 7))
            && !string.IsNullOrWhiteSpace(string.IsNullOrEmpty(sender) ? username : sender);
    }

    public async Task SaveAsync(GlobalApplicationSettingsUpdate settings, CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        var assignments = new List<string>();
        AddUpdate(command, assignments, "public_app_url", settings.PublicAppUrl);
        AddUpdate(command, assignments, "tech_stack", settings.TechStack);
        AddUpdate(command, assignments, "monitored_asns", settings.MonitoredAsns);
        AddUpdate(command, assignments, "failed_login_alert_enabled", settings.FailedLoginAlertEnabled);
        AddUpdate(command, assignments, "failed_login_alert_recipients", settings.FailedLoginAlertRecipients);
        AddUpdate(command, assignments, "failed_login_alert_threshold", settings.FailedLoginAlertThreshold);
        AddUpdate(command, assignments, "failed_login_alert_window_minutes", settings.FailedLoginAlertWindowMinutes);
        if (assignments.Count == 0)
        {
            return;
        }

        var configId = await ReadConfigIdAsync(connection, cancellationToken);
        if (configId is null)
        {
            await InsertDefaultsAsync(connection, settings, cancellationToken);
            return;
        }

        command.CommandText = $"UPDATE system_config SET {string.Join(", ", assignments)} WHERE id = $id";
        command.Parameters.AddWithValue("$id", configId.Value);
        await command.ExecuteNonQueryAsync(cancellationToken);
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

    private static async Task<long?> ReadConfigIdAsync(SqliteConnection connection, CancellationToken cancellationToken)
    {
        await using var query = connection.CreateCommand();
        query.CommandText = "SELECT id FROM system_config ORDER BY id LIMIT 1";
        var value = await query.ExecuteScalarAsync(cancellationToken);
        return value is null or DBNull ? null : Convert.ToInt64(value, CultureInfo.InvariantCulture);
    }

    internal static async Task InsertDefaultsAsync(
        SqliteConnection connection,
        GlobalApplicationSettingsUpdate settings,
        CancellationToken cancellationToken)
    {
        await using var insert = connection.CreateCommand();
        insert.CommandText = """
            INSERT INTO system_config (
                llm_provider, active_smtp_provider, gmail_smtp_enabled,
                public_app_url, tech_stack, monitored_asns,
                failed_login_alert_enabled, failed_login_alert_recipients,
                failed_login_alert_threshold, failed_login_alert_window_minutes,
                permission_catalog_version, scheduler_revision, scheduler_applied_revision
            ) VALUES (
                'openai_compatible', 'smtp', 0,
                $public_app_url, $tech_stack, $monitored_asns,
                $alert_enabled, $alert_recipients, $alert_threshold, $alert_window,
                0, 0, 0
            )
            """;
        insert.Parameters.AddWithValue("$public_app_url", settings.PublicAppUrl ?? "http://localhost:8503");
        insert.Parameters.AddWithValue("$tech_stack", settings.TechStack ?? "SolarWinds, Cisco SD-WAN, Microsoft Office, Verizon, Cisco");
        insert.Parameters.AddWithValue("$monitored_asns", settings.MonitoredAsns ?? "AS701, AS7922, AS3356");
        insert.Parameters.AddWithValue("$alert_enabled", settings.FailedLoginAlertEnabled ?? false);
        insert.Parameters.AddWithValue("$alert_recipients", settings.FailedLoginAlertRecipients ?? "");
        insert.Parameters.AddWithValue("$alert_threshold", settings.FailedLoginAlertThreshold ?? 5);
        insert.Parameters.AddWithValue("$alert_window", settings.FailedLoginAlertWindowMinutes ?? 5);
        await insert.ExecuteNonQueryAsync(cancellationToken);
    }

    private static string? ReadString(SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);
}
