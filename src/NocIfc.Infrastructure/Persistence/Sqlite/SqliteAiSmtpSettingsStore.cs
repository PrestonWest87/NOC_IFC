using System.Globalization;
using Microsoft.Data.Sqlite;
using NocIfc.Application.Abstractions.Settings;
using NocIfc.Application.Features.Settings;

namespace NocIfc.Infrastructure.Persistence.Sqlite;

public sealed class SqliteAiSmtpSettingsStore(SqliteConnectionFactory connections) : IAiSmtpSettingsStore
{
    public async Task<AiSmtpSettings?> GetAsync(CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT llm_endpoint, llm_api_key, llm_model_name, llm_provider, is_active,
                   llm_context_window, active_smtp_provider, smtp_enabled, smtp_server,
                   smtp_port, smtp_username, smtp_sender, smtp_recipient, smtp_password,
                   gmail_smtp_enabled, gmail_smtp_username, gmail_smtp_sender,
                   gmail_smtp_client_id, gmail_smtp_client_secret, gmail_smtp_refresh_token
            FROM system_config
            ORDER BY id
            LIMIT 1
            """;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }
        return new AiSmtpSettings(
            ReadString(reader, 0),
            ReadString(reader, 3) ?? "openai_compatible",
            !string.IsNullOrEmpty(ReadString(reader, 1)),
            ReadString(reader, 2),
            ReadNullableBoolean(reader, 4),
            reader.IsDBNull(5) ? null : reader.GetInt32(5),
            ReadString(reader, 6) ?? "smtp",
            ReadNullableBoolean(reader, 7),
            ReadString(reader, 8),
            reader.IsDBNull(9) ? null : reader.GetInt32(9),
            ReadString(reader, 10),
            ReadString(reader, 11),
            ReadString(reader, 12),
            !string.IsNullOrEmpty(ReadString(reader, 13)),
            !reader.IsDBNull(14) && reader.GetBoolean(14),
            ReadString(reader, 15) ?? "",
            ReadString(reader, 16) ?? "",
            !string.IsNullOrEmpty(ReadString(reader, 17)),
            !string.IsNullOrEmpty(ReadString(reader, 18)),
            !string.IsNullOrEmpty(ReadString(reader, 19)));
    }

    public async Task<string> GetSavedLlmApiKeyForProviderAsync(
        string provider,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT llm_api_key FROM system_config WHERE llm_provider = $provider ORDER BY id LIMIT 1";
        command.Parameters.AddWithValue("$provider", provider);
        return Convert.ToString(await command.ExecuteScalarAsync(cancellationToken), CultureInfo.InvariantCulture) ?? "";
    }

    public async Task SaveAsync(AiSmtpSettingsUpdate update, CancellationToken cancellationToken)
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
        long configId;
        string existingProvider;
        await using (var config = connection.CreateCommand())
        {
            config.Transaction = transaction;
            config.CommandText = "SELECT id, llm_provider FROM system_config ORDER BY id LIMIT 1";
            await using var reader = await config.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken))
            {
                throw new InvalidOperationException("Unable to initialize AI and SMTP settings.");
            }
            configId = reader.GetInt64(0);
            existingProvider = ReadString(reader, 1) ?? "openai_compatible";
        }

        var assignments = new List<string>();
        await using var updateCommand = connection.CreateCommand();
        updateCommand.Transaction = transaction;
        foreach (var (field, value) in GetValues(update))
        {
            if (!update.ProvidedFields.Contains(field))
            {
                continue;
            }
            assignments.Add($"{field} = ${field}");
            updateCommand.Parameters.AddWithValue($"${field}", value ?? DBNull.Value);
        }

        var nextProvider = update.ProvidedFields.Contains("llm_provider")
            ? update.LlmProvider ?? "openai_compatible"
            : existingProvider;
        if (nextProvider != existingProvider && !update.ProvidedFields.Contains("llm_api_key"))
        {
            assignments.Add("llm_api_key = $clear_llm_api_key");
            updateCommand.Parameters.AddWithValue("$clear_llm_api_key", "");
        }
        if (assignments.Count == 0)
        {
            transaction.Commit();
            return;
        }
        updateCommand.Parameters.AddWithValue("$id", configId);
        updateCommand.CommandText = $"UPDATE system_config SET {string.Join(", ", assignments)} WHERE id = $id";
        await updateCommand.ExecuteNonQueryAsync(cancellationToken);
        transaction.Commit();
    }

    private static IEnumerable<(string Field, object? Value)> GetValues(AiSmtpSettingsUpdate update)
    {
        yield return ("llm_endpoint", update.LlmEndpoint);
        yield return ("llm_api_key", update.LlmApiKey);
        yield return ("llm_model_name", update.LlmModelName);
        yield return ("llm_provider", update.LlmProvider);
        yield return ("is_active", update.IsActive);
        yield return ("llm_context_window", update.LlmContextWindow);
        yield return ("active_smtp_provider", update.ActiveSmtpProvider);
        yield return ("smtp_enabled", update.SmtpEnabled);
        yield return ("smtp_server", update.SmtpServer);
        yield return ("smtp_port", update.SmtpPort);
        yield return ("smtp_username", update.SmtpUsername);
        yield return ("smtp_password", update.SmtpPassword);
        yield return ("smtp_sender", update.SmtpSender);
        yield return ("smtp_recipient", update.SmtpRecipient);
        yield return ("gmail_smtp_username", update.GmailSmtpUsername);
        yield return ("gmail_smtp_client_id", update.GmailSmtpClientId);
        yield return ("gmail_smtp_client_secret", update.GmailSmtpClientSecret);
        yield return ("gmail_smtp_refresh_token", update.GmailSmtpRefreshToken);
        yield return ("gmail_smtp_sender", update.GmailSmtpSender);
        yield return ("gmail_smtp_enabled", update.GmailSmtpEnabled);
    }

    private static string? ReadString(SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);

    private static bool? ReadNullableBoolean(SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal) ? null : reader.GetBoolean(ordinal);
}
