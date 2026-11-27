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

    public async Task<int> CreateEmailAsync(
        OperationalEmailMessageSnapshot email,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction();
        var now = FormatDate(DateTime.UtcNow);
        await using var insert = connection.CreateCommand();
        insert.Transaction = transaction;
        insert.CommandText = """
            INSERT INTO operational_emails (
                template_key, created_by_user_id, signature_id, signature_name, signature_content,
                parent_email_id, group_id, group_company, bcc_copy_only, subject, body, fields_json,
                to_recipients, cc_recipients, bcc_recipients, schedule_type, timezone, scheduled_at,
                recurrence_time, recurrence_weekday, next_run_at, processing_started_at, status,
                created_at, updated_at
            ) VALUES (
                $template_key, $created_by_user_id, $signature_id, $signature_name, $signature_content,
                $parent_email_id, $group_id, $group_company, $bcc_copy_only, $subject, $body, $fields_json,
                $to_recipients, $cc_recipients, $bcc_recipients, $schedule_type, $timezone, $scheduled_at,
                $recurrence_time, $recurrence_weekday, $next_run_at, $processing_started_at, $status,
                $created_at, $updated_at
            )
            """;
        insert.Parameters.AddWithValue("$template_key", email.TemplateKey);
        insert.Parameters.AddWithValue("$created_by_user_id", email.CreatedByUserId);
        AddNullable(insert, "$signature_id", email.SignatureId);
        AddNullable(insert, "$signature_name", email.SignatureName);
        AddNullable(insert, "$signature_content", email.SignatureContent);
        AddNullable(insert, "$parent_email_id", email.ParentEmailId);
        AddNullable(insert, "$group_id", email.GroupId);
        AddNullable(insert, "$group_company", email.GroupCompany);
        insert.Parameters.AddWithValue("$bcc_copy_only", email.BccCopyOnly);
        insert.Parameters.AddWithValue("$subject", email.Subject);
        insert.Parameters.AddWithValue("$body", email.Body);
        insert.Parameters.AddWithValue("$fields_json", JsonSerializer.Serialize(email.Fields));
        insert.Parameters.AddWithValue("$to_recipients", JsonSerializer.Serialize(email.ToRecipients));
        insert.Parameters.AddWithValue("$cc_recipients", JsonSerializer.Serialize(email.CcRecipients));
        insert.Parameters.AddWithValue("$bcc_recipients", JsonSerializer.Serialize(email.BccRecipients));
        insert.Parameters.AddWithValue("$schedule_type", email.ScheduleType);
        insert.Parameters.AddWithValue("$timezone", email.Timezone);
        AddNullable(insert, "$scheduled_at", email.ScheduledAt is { } scheduledAt ? FormatDate(scheduledAt) : null);
        AddNullable(insert, "$recurrence_time", email.RecurrenceTime);
        AddNullable(insert, "$recurrence_weekday", email.RecurrenceWeekday);
        AddNullable(insert, "$next_run_at", email.NextRunAt is { } nextRunAt ? FormatDate(nextRunAt) : null);
        AddNullable(insert, "$processing_started_at", email.ScheduleType == "immediate" ? now : null);
        insert.Parameters.AddWithValue("$status", email.ScheduleType == "immediate" ? "processing" : "scheduled");
        insert.Parameters.AddWithValue("$created_at", now);
        insert.Parameters.AddWithValue("$updated_at", now);
        await insert.ExecuteNonQueryAsync(cancellationToken);

        await using var idCommand = connection.CreateCommand();
        idCommand.Transaction = transaction;
        idCommand.CommandText = "SELECT last_insert_rowid()";
        var emailId = Convert.ToInt32(
            await idCommand.ExecuteScalarAsync(cancellationToken), CultureInfo.InvariantCulture);
        foreach (var attachment in email.Attachments)
        {
            await using var attachmentCommand = connection.CreateCommand();
            attachmentCommand.Transaction = transaction;
            attachmentCommand.CommandText = """
                INSERT INTO operational_email_attachments (
                    operational_email_id, filename, content_type, content, size_bytes
                ) VALUES ($email_id, $filename, $content_type, $content, $size_bytes)
                """;
            attachmentCommand.Parameters.AddWithValue("$email_id", emailId);
            attachmentCommand.Parameters.AddWithValue("$filename", attachment.FileName);
            attachmentCommand.Parameters.AddWithValue("$content_type", attachment.ContentType);
            attachmentCommand.Parameters.AddWithValue("$content", attachment.Content);
            attachmentCommand.Parameters.AddWithValue("$size_bytes", attachment.Content.Length);
            await attachmentCommand.ExecuteNonQueryAsync(cancellationToken);
        }
        await WriteAuditAsync(
            connection,
            transaction,
            email.ScheduleType == "immediate" ? "operational_email_created" : "operational_email_scheduled",
            email.CreatedByUserId,
            new { email_id = emailId, template_key = email.TemplateKey, schedule_type = email.ScheduleType },
            cancellationToken);
        transaction.Commit();
        return emailId;
    }

    public async Task<int> CreateDeliverySnapshotAsync(
        int emailId,
        string smtpProvider,
        string? senderAddress,
        DateTime attemptedAtUtc,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction();
        int? signatureId;
        string signatureName;
        string toRecipients;
        string ccRecipients;
        string bccRecipients;
        string subject;
        string body;
        string fields;
        await using (var read = connection.CreateCommand())
        {
            read.Transaction = transaction;
            read.CommandText = """
                SELECT signature_id, signature_name, to_recipients, cc_recipients,
                       bcc_recipients, subject, body, fields_json
                FROM operational_emails WHERE id = $id AND status = 'processing' LIMIT 1
                """;
            read.Parameters.AddWithValue("$id", emailId);
            await using var reader = await read.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken))
            {
                throw new InvalidOperationException("Operational email is not ready for delivery.");
            }
            signatureId = reader.IsDBNull(0) ? null : reader.GetInt32(0);
            signatureName = ReadString(reader, 1) ?? "";
            toRecipients = reader.GetString(2);
            ccRecipients = reader.GetString(3);
            bccRecipients = reader.GetString(4);
            subject = reader.GetString(5);
            body = reader.GetString(6);
            fields = reader.GetString(7);
        }

        var attachmentNames = new List<string>();
        await using (var attachments = connection.CreateCommand())
        {
            attachments.Transaction = transaction;
            attachments.CommandText = """
                SELECT filename FROM operational_email_attachments
                WHERE operational_email_id = $email_id ORDER BY id
                """;
            attachments.Parameters.AddWithValue("$email_id", emailId);
            await using var reader = await attachments.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken)) attachmentNames.Add(reader.GetString(0));
        }

        await using var insert = connection.CreateCommand();
        insert.Transaction = transaction;
        insert.CommandText = """
            INSERT INTO operational_email_deliveries (
                operational_email_id, status, smtp_provider, sender_address, signature_id, signature_name,
                to_recipients, cc_recipients, bcc_recipients, subject, body, fields_json, attachment_names,
                attempted_at
            ) VALUES (
                $email_id, 'sending', $provider, $sender, $signature_id, $signature_name,
                $to_recipients, $cc_recipients, $bcc_recipients, $subject, $body, $fields, $attachment_names,
                $attempted_at
            )
            """;
        insert.Parameters.AddWithValue("$email_id", emailId);
        insert.Parameters.AddWithValue("$provider", smtpProvider);
        AddNullable(insert, "$sender", senderAddress);
        AddNullable(insert, "$signature_id", signatureId);
        AddNullable(insert, "$signature_name", string.IsNullOrEmpty(signatureName) ? null : signatureName);
        insert.Parameters.AddWithValue("$to_recipients", toRecipients);
        insert.Parameters.AddWithValue("$cc_recipients", ccRecipients);
        insert.Parameters.AddWithValue("$bcc_recipients", bccRecipients);
        insert.Parameters.AddWithValue("$subject", subject);
        insert.Parameters.AddWithValue("$body", body);
        insert.Parameters.AddWithValue("$fields", fields);
        insert.Parameters.AddWithValue("$attachment_names", JsonSerializer.Serialize(attachmentNames));
        insert.Parameters.AddWithValue("$attempted_at", FormatDate(attemptedAtUtc));
        await insert.ExecuteNonQueryAsync(cancellationToken);
        await using var idCommand = connection.CreateCommand();
        idCommand.Transaction = transaction;
        idCommand.CommandText = "SELECT last_insert_rowid()";
        var deliveryId = Convert.ToInt32(
            await idCommand.ExecuteScalarAsync(cancellationToken), CultureInfo.InvariantCulture);
        transaction.Commit();
        return deliveryId;
    }

    public async Task CompleteImmediateDeliveryAsync(
        int emailId,
        int deliveryId,
        bool success,
        string message,
        DateTime completedAtUtc,
        CancellationToken cancellationToken)
    {
        var completed = FormatDate(completedAtUtc);
        var detail = message.Length > 2000 ? message[..2000] : message;
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction();
        await using var delivery = connection.CreateCommand();
        delivery.Transaction = transaction;
        delivery.CommandText = """
            UPDATE operational_email_deliveries
            SET status = $status, sent_at = $sent_at, error_message = $error
            WHERE id = $delivery_id AND operational_email_id = $email_id
            """;
        delivery.Parameters.AddWithValue("$status", success ? "sent" : "failed");
        AddNullable(delivery, "$sent_at", success ? completed : null);
        AddNullable(delivery, "$error", success ? null : detail);
        delivery.Parameters.AddWithValue("$delivery_id", deliveryId);
        delivery.Parameters.AddWithValue("$email_id", emailId);
        if (await delivery.ExecuteNonQueryAsync(cancellationToken) != 1)
        {
            throw new InvalidOperationException("Operational email delivery record could not be updated.");
        }

        await using var update = connection.CreateCommand();
        update.Transaction = transaction;
        update.CommandText = """
            UPDATE operational_emails
            SET status = $status, last_sent_at = CASE WHEN $success = 1 THEN $completed ELSE last_sent_at END,
                last_error = $error, processing_started_at = NULL, updated_at = $completed
            WHERE id = $email_id AND status = 'processing'
            """;
        update.Parameters.AddWithValue("$status", success ? "sent" : "failed");
        update.Parameters.AddWithValue("$success", success);
        update.Parameters.AddWithValue("$completed", completed);
        AddNullable(update, "$error", success ? null : detail);
        update.Parameters.AddWithValue("$email_id", emailId);
        if (await update.ExecuteNonQueryAsync(cancellationToken) != 1)
        {
            throw new InvalidOperationException("Operational email status could not be updated.");
        }

        string templateKey;
        await using (var read = connection.CreateCommand())
        {
            read.Transaction = transaction;
            read.CommandText = "SELECT template_key FROM operational_emails WHERE id = $id";
            read.Parameters.AddWithValue("$id", emailId);
            templateKey = (string?)await read.ExecuteScalarAsync(cancellationToken)
                ?? throw new InvalidOperationException("Operational email could not be found.");
        }
        await WriteAuditAsync(
            connection,
            transaction,
            success ? "operational_email_sent" : "operational_email_failed",
            null,
            new { email_id = emailId, delivery_id = deliveryId, template_key = templateKey },
            cancellationToken);
        transaction.Commit();
    }

    public async Task<IReadOnlyList<OperationalEmailSourceMessage>> GetSuccessfulSourceMessagesAsync(
        int sourceEmailId,
        IReadOnlyList<string> allowedTemplateKeys,
        bool includeBccCopies,
        CancellationToken cancellationToken)
    {
        if (allowedTemplateKeys.Count == 0) return [];
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        var parameters = new List<SqliteParameter>();
        var templateParameters = new List<string>();
        for (var index = 0; index < allowedTemplateKeys.Count; index++)
        {
            var name = $"$template_{index}";
            templateParameters.Add(name);
            parameters.Add(new SqliteParameter(name, allowedTemplateKeys[index]));
        }
        var templates = string.Join(", ", templateParameters);
        string? groupId;
        await using (var parent = connection.CreateCommand())
        {
            parent.CommandText = $"""
                SELECT group_id FROM operational_emails e
                WHERE e.id = $id AND e.template_key IN ({templates}) AND e.bcc_copy_only = 0
                    AND EXISTS (
                        SELECT 1 FROM operational_email_deliveries d
                        WHERE d.operational_email_id = e.id AND d.status = 'sent'
                    )
                LIMIT 1
                """;
            parent.Parameters.AddWithValue("$id", sourceEmailId);
            parent.Parameters.AddRange(parameters);
            var value = await parent.ExecuteScalarAsync(cancellationToken);
            groupId = value as string;
        }
        var groupCondition = groupId is null ? "e.id = $id" : "e.group_id = $group_id";
        var bccFilter = includeBccCopies ? "" : "AND e.bcc_copy_only = 0";
        await using var query = connection.CreateCommand();
        query.CommandText = $"""
            SELECT e.id, e.template_key, e.group_id, e.group_company, e.bcc_copy_only,
                   e.subject, e.body, e.fields_json, e.to_recipients, e.cc_recipients,
                   e.bcc_recipients, e.signature_id, e.signature_name, e.signature_content
            FROM operational_emails e
            WHERE {groupCondition} AND e.template_key IN ({templates}) {bccFilter}
                AND EXISTS (
                    SELECT 1 FROM operational_email_deliveries d
                    WHERE d.operational_email_id = e.id AND d.status = 'sent'
                )
            ORDER BY e.id
            """;
        query.Parameters.AddWithValue("$id", sourceEmailId);
        if (groupId is not null) query.Parameters.AddWithValue("$group_id", groupId);
        query.Parameters.AddRange(parameters.Select(parameter => new SqliteParameter(parameter.ParameterName, parameter.Value)));
        await using var reader = await query.ExecuteReaderAsync(cancellationToken);
        var result = new List<OperationalEmailSourceMessage>();
        while (await reader.ReadAsync(cancellationToken))
        {
            result.Add(new OperationalEmailSourceMessage(
                reader.GetInt32(0),
                reader.GetString(1),
                ReadString(reader, 2),
                ReadString(reader, 3),
                reader.GetBoolean(4),
                reader.GetString(5),
                reader.GetString(6),
                JsonSerializer.Deserialize<Dictionary<string, string>>(reader.GetString(7)) ?? [],
                JsonSerializer.Deserialize<string[]>(reader.GetString(8)) ?? [],
                JsonSerializer.Deserialize<string[]>(reader.GetString(9)) ?? [],
                JsonSerializer.Deserialize<string[]>(reader.GetString(10)) ?? [],
                reader.IsDBNull(11) ? null : reader.GetInt32(11),
                ReadString(reader, 12),
                ReadString(reader, 13)));
        }
        return result;
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
        int? actorUserId,
        object detail,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO account_audit_events (actor_user_id, subject_user_id, event_type, event_detail, created_at)
            VALUES ($actor, NULL, $event_type, $detail, $created_at)
            """;
        AddNullable(command, "$actor", actorUserId);
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

    private static void AddNullable(SqliteCommand command, string name, object? value) =>
        command.Parameters.AddWithValue(name, value ?? DBNull.Value);

    private static string FormatDate(DateTime value) =>
        value.ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture);
}
