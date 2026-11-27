using System.Globalization;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using NocIfc.Application.Abstractions.OperationalEmail;
using NocIfc.Domain.OperationalEmail;

namespace NocIfc.Infrastructure.Persistence.Sqlite;

public sealed class SqliteOperationalEmailStore(SqliteConnectionFactory connections) : IOperationalEmailStore
{
    public async Task EnsureTemplateDefaultsAsync(
        IReadOnlyList<OperationalEmailTemplateDefault> defaults,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction();
        var now = FormatDate(DateTime.UtcNow);
        foreach (var template in defaults)
        {
            await using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = """
                INSERT OR IGNORE INTO operational_email_templates (
                    template_key, label, description, default_subject, default_body,
                    default_to, default_cc, default_bcc, created_at, updated_at
                ) VALUES (
                    $key, $label, $description, $subject, $body, '', '', '', $created_at, $updated_at
                )
                """;
            command.Parameters.AddWithValue("$key", template.TemplateKey);
            command.Parameters.AddWithValue("$label", template.Label);
            command.Parameters.AddWithValue("$description", template.Description);
            command.Parameters.AddWithValue("$subject", template.DefaultSubject);
            command.Parameters.AddWithValue("$body", template.DefaultBody);
            command.Parameters.AddWithValue("$created_at", now);
            command.Parameters.AddWithValue("$updated_at", now);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
        transaction.Commit();
    }

    public async Task<IReadOnlyList<OperationalEmailTemplateDefault>> GetTemplateDefaultsAsync(
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT template_key, label, description, default_subject, default_body,
                   default_to, default_cc, default_bcc, updated_at
            FROM operational_email_templates
            ORDER BY id
            """;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var templates = new List<OperationalEmailTemplateDefault>();
        while (await reader.ReadAsync(cancellationToken))
        {
            templates.Add(new OperationalEmailTemplateDefault(
                reader.GetString(0), ReadString(reader, 1) ?? "", ReadString(reader, 2) ?? "",
                ReadString(reader, 3) ?? "", ReadString(reader, 4) ?? "", ReadString(reader, 5) ?? "",
                ReadString(reader, 6) ?? "", ReadString(reader, 7) ?? "", ReadDateTime(reader, 8)));
        }
        return templates;
    }

    public async Task<bool> UpdateTemplateDefaultsAsync(
        string templateKey,
        IReadOnlyDictionary<string, string> values,
        int actorUserId,
        CancellationToken cancellationToken)
    {
        var columns = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["default_subject"] = "default_subject",
            ["default_body"] = "default_body",
            ["default_to"] = "default_to",
            ["default_cc"] = "default_cc",
            ["default_bcc"] = "default_bcc",
        };
        if (values.Keys.Any(key => !columns.ContainsKey(key)))
        {
            throw new ArgumentException("Unsupported operational email template default.");
        }
        if (values.Count == 0) return false;

        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction();
        await using var update = connection.CreateCommand();
        update.Transaction = transaction;
        var assignments = new List<string>();
        foreach (var (field, value) in values)
        {
            var parameter = $"${field}";
            assignments.Add($"{columns[field]} = {parameter}");
            update.Parameters.AddWithValue(parameter, value);
        }
        assignments.Add("updated_by_user_id = $actor");
        assignments.Add("updated_at = $updated_at");
        update.Parameters.AddWithValue("$actor", actorUserId);
        update.Parameters.AddWithValue("$updated_at", FormatDate(DateTime.UtcNow));
        update.Parameters.AddWithValue("$key", templateKey);
        update.CommandText = $"UPDATE operational_email_templates SET {string.Join(", ", assignments)} WHERE template_key = $key";
        if (await update.ExecuteNonQueryAsync(cancellationToken) == 0) return false;
        await WriteAuditAsync(
            connection,
            transaction,
            "operational_email_template_updated",
            actorUserId,
            new { template_key = templateKey, changed_fields = values.Keys.Order(StringComparer.Ordinal).ToArray() },
            cancellationToken);
        transaction.Commit();
        return true;
    }

    public async Task<IReadOnlyList<OperationalEmailSignatureEntry>> GetSignaturesAsync(
        bool includeInactive,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = $"""
            SELECT id, name, content, is_active, is_default, created_by_user_id,
                   updated_by_user_id, created_at, updated_at
            FROM operational_email_signatures
            {(includeInactive ? "" : "WHERE is_active = 1")}
            ORDER BY name, id
            """;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var signatures = new List<OperationalEmailSignatureEntry>();
        while (await reader.ReadAsync(cancellationToken)) signatures.Add(ReadSignature(reader));
        return signatures;
    }

    public async Task<OperationalEmailSignatureEntry?> GetSignatureAsync(
        int signatureId,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT id, name, content, is_active, is_default, created_by_user_id,
                   updated_by_user_id, created_at, updated_at
            FROM operational_email_signatures WHERE id = $id LIMIT 1
            """;
        command.Parameters.AddWithValue("$id", signatureId);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? ReadSignature(reader) : null;
    }

    public async Task<OperationalEmailSignatureMutation> CreateSignatureAsync(
        OperationalEmailSignatureValues signature,
        int actorUserId,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction();
        if (await SignatureNameExistsAsync(connection, transaction, signature.Name, null, cancellationToken))
        {
            return new OperationalEmailSignatureMutation(false, true, null);
        }
        if (signature.IsDefault)
        {
            await using var clear = connection.CreateCommand();
            clear.Transaction = transaction;
            clear.CommandText = "UPDATE operational_email_signatures SET is_default = 0";
            await clear.ExecuteNonQueryAsync(cancellationToken);
        }

        var now = FormatDate(DateTime.UtcNow);
        await using var insert = connection.CreateCommand();
        insert.Transaction = transaction;
        insert.CommandText = """
            INSERT INTO operational_email_signatures (
                name, content, is_active, is_default, created_by_user_id, updated_by_user_id, created_at, updated_at
            ) VALUES (
                $name, $content, $active, $default, $actor, $actor, $created_at, $updated_at
            )
            """;
        insert.Parameters.AddWithValue("$name", signature.Name);
        insert.Parameters.AddWithValue("$content", signature.Content);
        insert.Parameters.AddWithValue("$active", signature.IsActive);
        insert.Parameters.AddWithValue("$default", signature.IsDefault);
        insert.Parameters.AddWithValue("$actor", actorUserId);
        insert.Parameters.AddWithValue("$created_at", now);
        insert.Parameters.AddWithValue("$updated_at", now);
        await insert.ExecuteNonQueryAsync(cancellationToken);
        await using var idCommand = connection.CreateCommand();
        idCommand.Transaction = transaction;
        idCommand.CommandText = "SELECT last_insert_rowid()";
        var id = Convert.ToInt32(await idCommand.ExecuteScalarAsync(cancellationToken), CultureInfo.InvariantCulture);
        await WriteAuditAsync(connection, transaction, "operational_email_signature_created", actorUserId,
            new { signature_id = id, is_default = signature.IsDefault }, cancellationToken);
        transaction.Commit();
        return new OperationalEmailSignatureMutation(true, false,
            new OperationalEmailSignatureEntry(id, signature.Name, signature.Content, signature.IsActive,
                signature.IsDefault, actorUserId, actorUserId, DateTime.UtcNow, DateTime.UtcNow));
    }

    public async Task<OperationalEmailSignatureMutation> UpdateSignatureAsync(
        int signatureId,
        OperationalEmailSignatureValues signature,
        IReadOnlyList<string> changedFields,
        int actorUserId,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction();
        OperationalEmailSignatureEntry? existing;
        await using (var read = connection.CreateCommand())
        {
            read.Transaction = transaction;
            read.CommandText = """
                SELECT id, name, content, is_active, is_default, created_by_user_id,
                       updated_by_user_id, created_at, updated_at
                FROM operational_email_signatures WHERE id = $id LIMIT 1
                """;
            read.Parameters.AddWithValue("$id", signatureId);
            await using var reader = await read.ExecuteReaderAsync(cancellationToken);
            existing = await reader.ReadAsync(cancellationToken) ? ReadSignature(reader) : null;
        }
        if (existing is null) return new OperationalEmailSignatureMutation(false, false, null);
        if (await SignatureNameExistsAsync(connection, transaction, signature.Name, signatureId, cancellationToken))
        {
            return new OperationalEmailSignatureMutation(true, true, null);
        }
        var isDefault = signature.IsActive && signature.IsDefault;
        if (isDefault)
        {
            await using var clear = connection.CreateCommand();
            clear.Transaction = transaction;
            clear.CommandText = "UPDATE operational_email_signatures SET is_default = 0 WHERE id <> $id";
            clear.Parameters.AddWithValue("$id", signatureId);
            await clear.ExecuteNonQueryAsync(cancellationToken);
        }
        var updatedAt = DateTime.UtcNow;
        await using (var update = connection.CreateCommand())
        {
            update.Transaction = transaction;
            update.CommandText = """
                UPDATE operational_email_signatures
                SET name = $name, content = $content, is_active = $active, is_default = $default,
                    updated_by_user_id = $actor, updated_at = $updated_at
                WHERE id = $id
                """;
            update.Parameters.AddWithValue("$name", signature.Name);
            update.Parameters.AddWithValue("$content", signature.Content);
            update.Parameters.AddWithValue("$active", signature.IsActive);
            update.Parameters.AddWithValue("$default", isDefault);
            update.Parameters.AddWithValue("$actor", actorUserId);
            update.Parameters.AddWithValue("$updated_at", FormatDate(updatedAt));
            update.Parameters.AddWithValue("$id", signatureId);
            await update.ExecuteNonQueryAsync(cancellationToken);
        }
        await WriteAuditAsync(connection, transaction, "operational_email_signature_updated", actorUserId,
            new { signature_id = signatureId, is_active = signature.IsActive, is_default = isDefault, changed_fields = changedFields.Order(StringComparer.Ordinal).ToArray() },
            cancellationToken);
        transaction.Commit();
        return new OperationalEmailSignatureMutation(true, false,
            existing with
            {
                Name = signature.Name,
                Content = signature.Content,
                IsActive = signature.IsActive,
                IsDefault = isDefault,
                UpdatedByUserId = actorUserId,
                UpdatedAt = updatedAt,
            });
    }

    private static async Task<bool> SignatureNameExistsAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string name,
        int? excludingId,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT 1 FROM operational_email_signatures
            WHERE lower(name) = lower($name) AND ($exclude_id IS NULL OR id <> $exclude_id)
            LIMIT 1
            """;
        command.Parameters.AddWithValue("$name", name);
        command.Parameters.AddWithValue("$exclude_id", (object?)excludingId ?? DBNull.Value);
        return await command.ExecuteScalarAsync(cancellationToken) is not null;
    }

    private static async Task WriteAuditAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string eventType,
        int actorUserId,
        object detail,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO account_audit_events (actor_user_id, subject_user_id, event_type, event_detail, created_at)
            VALUES ($actor, NULL, $event_type, $detail, $created_at)
            """;
        command.Parameters.AddWithValue("$actor", actorUserId);
        command.Parameters.AddWithValue("$event_type", eventType);
        command.Parameters.AddWithValue("$detail", JsonSerializer.Serialize(detail));
        command.Parameters.AddWithValue("$created_at", FormatDate(DateTime.UtcNow));
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static OperationalEmailSignatureEntry ReadSignature(SqliteDataReader reader) => new(
        reader.GetInt32(0),
        reader.GetString(1),
        reader.GetString(2),
        reader.GetBoolean(3),
        reader.GetBoolean(4),
        reader.IsDBNull(5) ? null : reader.GetInt32(5),
        reader.IsDBNull(6) ? null : reader.GetInt32(6),
        ReadDateTime(reader, 7),
        ReadDateTime(reader, 8));

    private static string? ReadString(SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);

    private static DateTime? ReadDateTime(SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal) ? null : DateTime.SpecifyKind(reader.GetDateTime(ordinal), DateTimeKind.Unspecified);

    private static string FormatDate(DateTime value) =>
        value.ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture);
}
