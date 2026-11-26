using System.Globalization;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using NocIfc.Application.Abstractions.Settings;
using NocIfc.Application.Features.Settings;

namespace NocIfc.Infrastructure.Persistence.Sqlite;

public sealed class SqliteOperationalIntegrationSettingsStore(
    SqliteConnectionFactory connections,
    IntegrationEnvironmentSettings environment) : IOperationalIntegrationSettingsStore
{
    public async Task<OperationalIntegrationSettings> GetAsync(CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT risk_alert_recipients, remedyforce_ticket_email, noc_notify_email,
                   noc_onpage_email, itnetwork_onpage_email, elastic_url, elastic_api_key,
                   elastic_verify_certs, elastic_ca_certs, elastic_request_timeout,
                   elastic_max_results, crime_alert_sms, crime_alert_email
            FROM system_config
            ORDER BY id
            LIMIT 1
            """;

        string? riskRecipients = null;
        string? remedyforce = null;
        string? nocNotify = null;
        string? nocOnpage = null;
        string? itnetworkOnpage = null;
        string? elasticUrl = null;
        string? elasticApiKey = null;
        bool? verifyCerts = null;
        string? caCerts = null;
        double? timeout = null;
        int? maxResults = null;
        string? crimeSms = null;
        string? crimeEmail = null;
        await using (var reader = await command.ExecuteReaderAsync(cancellationToken))
        {
            if (await reader.ReadAsync(cancellationToken))
            {
                riskRecipients = ReadString(reader, 0);
                remedyforce = ReadString(reader, 1);
                nocNotify = ReadString(reader, 2);
                nocOnpage = ReadString(reader, 3);
                itnetworkOnpage = ReadString(reader, 4);
                elasticUrl = ReadString(reader, 5);
                elasticApiKey = ReadString(reader, 6);
                verifyCerts = reader.IsDBNull(7) ? null : reader.GetBoolean(7);
                caCerts = ReadString(reader, 8);
                timeout = reader.IsDBNull(9) ? null : reader.GetDouble(9);
                maxResults = reader.IsDBNull(10) ? null : reader.GetInt32(10);
                crimeSms = ReadString(reader, 11);
                crimeEmail = ReadString(reader, 12);
            }
        }

        var sources = new Dictionary<string, string>(StringComparer.Ordinal);
        string ResolveString(string key, string? stored, string? fallback)
        {
            sources[key] = stored is null ? "environment" : "database";
            return stored ?? fallback ?? "";
        }

        bool ResolveBoolean(string key, bool? stored, bool fallback)
        {
            sources[key] = stored is null ? "environment" : "database";
            return stored ?? fallback;
        }

        double ResolveDouble(string key, double? stored, double fallback)
        {
            sources[key] = stored is null ? "environment" : "database";
            return stored ?? fallback;
        }

        int ResolveInteger(string key, int? stored, int fallback)
        {
            sources[key] = stored is null ? "environment" : "database";
            return stored ?? fallback;
        }

        return new OperationalIntegrationSettings(
            ResolveString("risk_alert_recipients", riskRecipients, environment.RiskAlertRecipients),
            ResolveString("remedyforce_ticket_email", remedyforce, environment.RemedyforceTicketEmail),
            ResolveString("noc_notify_email", nocNotify, environment.NocNotifyEmail),
            ResolveString("noc_onpage_email", nocOnpage, environment.NocOnpageEmail),
            ResolveString("itnetwork_onpage_email", itnetworkOnpage, environment.ItnetworkOnpageEmail),
            ResolveString("elastic_url", elasticUrl, environment.ElasticUrl),
            !string.IsNullOrEmpty(ResolveString("elastic_api_key", elasticApiKey, environment.ElasticApiKey)),
            ResolveBoolean("elastic_verify_certs", verifyCerts, environment.ElasticVerifyCerts),
            ResolveString("elastic_ca_certs", caCerts, environment.ElasticCaCerts),
            ResolveDouble("elastic_request_timeout", timeout, environment.ElasticRequestTimeout),
            ResolveInteger("elastic_max_results", maxResults, environment.ElasticMaxResults),
            ResolveString("crime_alert_sms", crimeSms, environment.CrimeAlertSms),
            ResolveString("crime_alert_email", crimeEmail, environment.CrimeAlertEmail),
            sources);
    }

    public async Task SaveAsync(
        OperationalIntegrationSettingsUpdate update,
        int actorUserId,
        CancellationToken cancellationToken)
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
        await using var updateCommand = connection.CreateCommand();
        updateCommand.Transaction = transaction;
        var assignments = new List<string>();
        var values = GetValues(update);
        foreach (var (field, value) in values)
        {
            if (!update.ProvidedFields.Contains(field))
            {
                continue;
            }
            assignments.Add($"{field} = ${field}");
            updateCommand.Parameters.AddWithValue($"${field}", value ?? DBNull.Value);
        }
        if (assignments.Count == 0)
        {
            throw new ArgumentException("Provide at least one integration setting.");
        }

        await using (var configId = connection.CreateCommand())
        {
            configId.Transaction = transaction;
            configId.CommandText = "SELECT id FROM system_config ORDER BY id LIMIT 1";
            var id = await configId.ExecuteScalarAsync(cancellationToken);
            if (id is null or DBNull)
            {
                throw new InvalidOperationException("Unable to initialize application settings.");
            }
            updateCommand.Parameters.AddWithValue("$id", Convert.ToInt64(id, CultureInfo.InvariantCulture));
        }

        updateCommand.CommandText = $"UPDATE system_config SET {string.Join(", ", assignments)} WHERE id = $id";
        await updateCommand.ExecuteNonQueryAsync(cancellationToken);
        await using (var audit = connection.CreateCommand())
        {
            audit.Transaction = transaction;
            audit.CommandText = """
                INSERT INTO account_audit_events
                    (actor_user_id, subject_user_id, event_type, event_detail, created_at)
                VALUES ($actor_id, NULL, 'operational_settings_changed', $detail, $created_at)
                """;
            audit.Parameters.AddWithValue("$actor_id", actorUserId);
            audit.Parameters.AddWithValue(
                "$detail",
                JsonSerializer.Serialize(new { changed_fields = update.ProvidedFields.Order().ToArray() }));
            audit.Parameters.AddWithValue(
                "$created_at",
                DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture));
            await audit.ExecuteNonQueryAsync(cancellationToken);
        }
        transaction.Commit();
    }

    private static IEnumerable<(string Field, object? Value)> GetValues(OperationalIntegrationSettingsUpdate update)
    {
        yield return ("risk_alert_recipients", update.RiskAlertRecipients);
        yield return ("remedyforce_ticket_email", update.RemedyforceTicketEmail);
        yield return ("noc_notify_email", update.NocNotifyEmail);
        yield return ("noc_onpage_email", update.NocOnpageEmail);
        yield return ("itnetwork_onpage_email", update.ItnetworkOnpageEmail);
        yield return ("elastic_url", update.ElasticUrl);
        yield return ("elastic_api_key", update.ElasticApiKey);
        yield return ("elastic_verify_certs", update.ElasticVerifyCerts);
        yield return ("elastic_ca_certs", update.ElasticCaCerts);
        yield return ("elastic_request_timeout", update.ElasticRequestTimeout);
        yield return ("elastic_max_results", update.ElasticMaxResults);
        yield return ("crime_alert_sms", update.CrimeAlertSms);
        yield return ("crime_alert_email", update.CrimeAlertEmail);
    }

    private static string? ReadString(SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);
}
