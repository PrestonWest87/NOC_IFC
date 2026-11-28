using System.Globalization;
using NocIfc.Application.Features.OperationalEmail;
using NocIfc.Domain.OperationalEmail;
using NocIfc.Infrastructure.Persistence.Sqlite;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class SqliteOperationalEmailStoreTests
{
    [Fact]
    public async Task SeedsMissingDefaultsPreservesEditsAndAuditsSignatureChangesWithoutContent()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"nocifc-operational-email-{Guid.NewGuid():N}.sqlite");
        using (File.Create(databasePath)) { }
        try
        {
            var connections = new SqliteConnectionFactory($"sqlite:///{databasePath}");
            await using (var connection = connections.Create())
            {
                await connection.OpenAsync();
                await using var setup = connection.CreateCommand();
                setup.CommandText = """
                    CREATE TABLE operational_email_templates (
                        id INTEGER PRIMARY KEY, template_key TEXT UNIQUE, label TEXT, description TEXT,
                        default_subject TEXT, default_body TEXT, default_to TEXT, default_cc TEXT, default_bcc TEXT,
                        updated_by_user_id INTEGER, created_at DATETIME, updated_at DATETIME
                    );
                    CREATE TABLE operational_email_signatures (
                        id INTEGER PRIMARY KEY, name TEXT UNIQUE, content TEXT, is_active INTEGER, is_default INTEGER,
                        created_by_user_id INTEGER, updated_by_user_id INTEGER, created_at DATETIME, updated_at DATETIME
                    );
                    CREATE TABLE account_audit_events (
                        id INTEGER PRIMARY KEY, actor_user_id INTEGER, subject_user_id INTEGER,
                        event_type TEXT, event_detail TEXT, created_at DATETIME
                    );
                    CREATE TABLE operational_emails (
                        id INTEGER PRIMARY KEY, template_key TEXT, created_by_user_id INTEGER,
                        signature_id INTEGER, signature_name TEXT, signature_content TEXT,
                        parent_email_id INTEGER, group_id TEXT, group_company TEXT, bcc_copy_only INTEGER,
                        subject TEXT, body TEXT, fields_json TEXT, to_recipients TEXT, cc_recipients TEXT,
                        bcc_recipients TEXT, schedule_type TEXT, timezone TEXT, scheduled_at DATETIME,
                        recurrence_time TEXT, recurrence_weekday INTEGER, next_run_at DATETIME,
                        processing_started_at DATETIME, status TEXT, last_sent_at DATETIME, last_error TEXT,
                        created_at DATETIME, updated_at DATETIME
                    );
                    CREATE TABLE operational_email_attachments (
                        id INTEGER PRIMARY KEY, operational_email_id INTEGER, filename TEXT,
                        content_type TEXT, content BLOB, size_bytes INTEGER
                    );
                    CREATE TABLE operational_email_deliveries (
                        id INTEGER PRIMARY KEY, operational_email_id INTEGER, status TEXT,
                        smtp_provider TEXT, sender_address TEXT, signature_id INTEGER, signature_name TEXT,
                        to_recipients TEXT, cc_recipients TEXT, bcc_recipients TEXT, subject TEXT, body TEXT,
                        fields_json TEXT, attachment_names TEXT, attempted_at DATETIME, sent_at DATETIME,
                        error_message TEXT
                    );
                    """;
                await setup.ExecuteNonQueryAsync();
            }

            var store = new SqliteOperationalEmailStore(connections);
            var defaults = OperationalEmailTemplateCatalog.All.Select(template => new OperationalEmailTemplateDefault(
                template.Key, template.Label, template.Description, template.DefaultSubject, template.DefaultBody,
                "", "", "", null)).ToArray();
            await store.EnsureTemplateDefaultsAsync(defaults, CancellationToken.None);
            Assert.Equal(11, (await store.GetTemplateDefaultsAsync(CancellationToken.None)).Count);

            Assert.True(await store.UpdateTemplateDefaultsAsync(
                "maintenance_notice", new Dictionary<string, string> { ["default_subject"] = "Custom {{ticket_title}}" },
                7, CancellationToken.None));
            await store.EnsureTemplateDefaultsAsync(defaults, CancellationToken.None);
            var savedTemplate = Assert.Single(
                await store.GetTemplateDefaultsAsync(CancellationToken.None),
                template => template.TemplateKey == "maintenance_notice");
            Assert.Equal("Custom {{ticket_title}}", savedTemplate.DefaultSubject);

            var created = await store.CreateSignatureAsync(
                new OperationalEmailSignatureValues("NOC Default", "-- NOC signature", true, true),
                7, CancellationToken.None);
            Assert.True(created.Found);
            Assert.False(created.NameConflict);
            var signature = Assert.IsType<OperationalEmailSignatureEntry>(created.Signature);
            var conflict = await store.CreateSignatureAsync(
                new OperationalEmailSignatureValues("noc default", "duplicate", true, false),
                7, CancellationToken.None);
            Assert.True(conflict.NameConflict);

            var updated = await store.UpdateSignatureAsync(signature.Id,
                new OperationalEmailSignatureValues("NOC Default", "-- Updated", false, true),
                ["content", "is_active", "is_default"], 7, CancellationToken.None);
            Assert.True(updated.Found);
            Assert.False(updated.NameConflict);
            Assert.False(updated.Signature?.IsDefault);
            Assert.Empty(await store.GetSignaturesAsync(false, CancellationToken.None));
            Assert.Equal("-- Updated", Assert.Single(await store.GetSignaturesAsync(true, CancellationToken.None)).Content);

            await using (var connection = connections.Create())
            {
                await connection.OpenAsync();
                await using var audit = connection.CreateCommand();
                audit.CommandText = "SELECT event_type, event_detail FROM account_audit_events ORDER BY id";
                await using var reader = await audit.ExecuteReaderAsync();
                var events = new List<(string Type, string Detail)>();
                while (await reader.ReadAsync()) events.Add((reader.GetString(0), reader.GetString(1)));
                Assert.Equal(3, events.Count);
                Assert.Equal("operational_email_template_updated", events[0].Type);
                Assert.Equal("operational_email_signature_created", events[1].Type);
                Assert.Equal("operational_email_signature_updated", events[2].Type);
                Assert.DoesNotContain(events, item => item.Detail.Contains("NOC signature", StringComparison.Ordinal));
            }

            var emailId = await store.CreateEmailAsync(new OperationalEmailMessageSnapshot(
                "maintenance_notice", 7, null, null, null, null, "group-1", "Utility A", false,
                "Maintenance window", "Message body", new Dictionary<string, string> { ["site"] = "North" },
                ["to@example.com"], ["cc@example.com"], ["bcc@example.com"], "immediate", "America/Chicago",
                null, null, null, null,
                [new OperationalEmailAttachmentSnapshot("report.txt", "text/plain", [1, 2, 3])]),
                CancellationToken.None);
            var deliveryId = await store.CreateDeliverySnapshotAsync(
                emailId, "smtp", "noc@example.com", DateTime.UtcNow, CancellationToken.None);
            await store.CompleteDeliveryAsync(
                emailId, deliveryId, true, "Email sent successfully.", DateTime.UtcNow, null, CancellationToken.None);

            var source = Assert.Single(await store.GetSuccessfulSourceMessagesAsync(
                emailId, ["maintenance_notice"], false, CancellationToken.None));
            Assert.Equal("group-1", source.GroupId);
            Assert.Equal("Utility A", source.GroupCompany);
            Assert.Equal("Message body", source.Body);
            Assert.Equal(["bcc@example.com"], source.BccRecipients);
            await using (var connection = connections.Create())
            {
                await connection.OpenAsync();
                await using var read = connection.CreateCommand();
                read.CommandText = """
                    SELECT e.status, d.status, d.smtp_provider, d.sender_address,
                           d.attachment_names, a.content
                    FROM operational_emails e
                    JOIN operational_email_deliveries d ON d.operational_email_id = e.id
                    JOIN operational_email_attachments a ON a.operational_email_id = e.id
                    WHERE e.id = $id
                    """;
                read.Parameters.AddWithValue("$id", emailId);
                await using var reader = await read.ExecuteReaderAsync();
                Assert.True(await reader.ReadAsync());
                Assert.Equal("sent", reader.GetString(0));
                Assert.Equal("sent", reader.GetString(1));
                Assert.Equal("smtp", reader.GetString(2));
                Assert.Equal("noc@example.com", reader.GetString(3));
                Assert.Equal("[\"report.txt\"]", reader.GetString(4));
                Assert.Equal(new byte[] { 1, 2, 3 }, (byte[])reader[5]);
            }

            var ungroupedId = await store.CreateEmailAsync(new OperationalEmailMessageSnapshot(
                "maintenance_notice", 7, null, null, null, null, null, null, false,
                "Solo maintenance", "Single source", new Dictionary<string, string>(),
                ["solo@example.com"], [], [], "immediate", "America/Chicago", null, null, null, null, []),
                CancellationToken.None);
            var ungroupedDeliveryId = await store.CreateDeliverySnapshotAsync(
                ungroupedId, "smtp", "noc@example.com", DateTime.UtcNow, CancellationToken.None);
            await store.CompleteDeliveryAsync(
                ungroupedId, ungroupedDeliveryId, true, "sent", DateTime.UtcNow, null, CancellationToken.None);
            var ungroupedSource = Assert.Single(await store.GetSuccessfulSourceMessagesAsync(
                ungroupedId, ["maintenance_notice"], false, CancellationToken.None));
            Assert.Null(ungroupedSource.GroupId);
            Assert.Equal("Single source", ungroupedSource.Body);

            var history = await store.GetDeliveryHistoryAsync(10, CancellationToken.None);
            Assert.Equal(2, history.Count);
            var detail = await store.GetDeliveryDetailAsync(ungroupedDeliveryId, CancellationToken.None);
            Assert.Equal("Single source", detail?.Body);
            Assert.Equal("noc@example.com", detail?.SenderAddress);
            var sourceGroups = await store.GetSentSourceGroupsAsync(["maintenance_notice"], 10, CancellationToken.None);
            Assert.Equal(2, sourceGroups.Count);
            Assert.Contains(sourceGroups, item => item.GroupId == "group-1" && item.Grouped);

            var nextRun = DateTime.UtcNow.AddDays(1);
            var scheduleId = await store.CreateEmailAsync(new OperationalEmailMessageSnapshot(
                "maintenance_notice", 7, null, null, null, null, null, null, false,
                "Scheduled maintenance", "Future body", new Dictionary<string, string>(),
                ["ops@example.com"], [], [], "once", "America/Chicago", nextRun, null, null, nextRun,
                [new OperationalEmailAttachmentSnapshot("plan.txt", "text/plain", [9, 8])]),
                CancellationToken.None);
            var scheduled = Assert.Single(await store.GetScheduledEmailsByIdsAsync([scheduleId], CancellationToken.None));
            Assert.Equal("scheduled", scheduled.Status);
            Assert.Equal("once", scheduled.ScheduleType);
            Assert.Equal("plan.txt", Assert.Single(scheduled.Attachments).FileName);
            Assert.Contains(await store.GetScheduledEmailsAsync(100, CancellationToken.None), item => item.Id == scheduleId);
            Assert.Equal(OperationalEmailCancellationResult.Cancelled,
                await store.CancelScheduledEmailAsync(scheduleId, 7, DateTime.UtcNow, CancellationToken.None));
            Assert.DoesNotContain(await store.GetScheduledEmailsAsync(100, CancellationToken.None), item => item.Id == scheduleId);

            var recurringId = await store.CreateEmailAsync(new OperationalEmailMessageSnapshot(
                "maintenance_notice", 7, null, null, null, null, null, null, false,
                "Recurring maintenance", "Future body", new Dictionary<string, string>(),
                ["ops@example.com"], [], [], "daily", "America/Chicago", null, "08:30", null, nextRun, []),
                CancellationToken.None);
            await using (var connection = connections.Create())
            {
                await connection.OpenAsync();
                await using var claim = connection.CreateCommand();
                claim.CommandText = "UPDATE operational_emails SET status = 'processing' WHERE id = $id";
                claim.Parameters.AddWithValue("$id", recurringId);
                await claim.ExecuteNonQueryAsync();
            }
            Assert.Equal(OperationalEmailCancellationResult.InProgress,
                await store.CancelScheduledEmailAsync(recurringId, 7, DateTime.UtcNow, CancellationToken.None));

            var now = DateTime.UtcNow;
            var dueAt = now.AddMinutes(-1);
            var onceDueId = await store.CreateEmailAsync(new OperationalEmailMessageSnapshot(
                "morning_report", 7, null, null, null, null, null, null, false,
                "Due once", "", new Dictionary<string, string> { ["shift_analysis"] = "" }, ["ops@example.com"], [], [],
                "once", "America/Chicago", dueAt, null, null, dueAt, []), CancellationToken.None);
            var staleRecurringId = await store.CreateEmailAsync(new OperationalEmailMessageSnapshot(
                "maintenance_notice", 7, null, null, null, null, null, null, false,
                "Recurring", "Body", new Dictionary<string, string>(), ["ops@example.com"], [], [],
                "daily", "America/Chicago", null, "08:30", null, dueAt, []), CancellationToken.None);
            var staleUnattemptedId = await store.CreateEmailAsync(new OperationalEmailMessageSnapshot(
                "maintenance_notice", 7, null, null, null, null, null, null, false,
                "Unattempted once", "Body", new Dictionary<string, string>(), ["ops@example.com"], [], [],
                "once", "America/Chicago", dueAt, null, null, dueAt, []), CancellationToken.None);
            await using (var connection = connections.Create())
            {
                await connection.OpenAsync();
                await using var stale = connection.CreateCommand();
                stale.CommandText = """
                    UPDATE operational_emails SET status = 'processing', processing_started_at = $started
                    WHERE id IN ($recurring_id, $unattempted_id)
                    """;
                stale.Parameters.AddWithValue("$started", now.AddMinutes(-30));
                stale.Parameters.AddWithValue("$recurring_id", staleRecurringId);
                stale.Parameters.AddWithValue("$unattempted_id", staleUnattemptedId);
                await stale.ExecuteNonQueryAsync();
            }
            var staleDeliveryId = await store.CreateDeliverySnapshotAsync(
                staleRecurringId, "smtp", "noc@example.com", now.AddMinutes(-30), CancellationToken.None);

            var claimed = await store.ClaimDueEmailsAsync(now, TimeSpan.FromMinutes(20), 25, CancellationToken.None);

            Assert.Equal([onceDueId], claimed);
            var queued = Assert.IsType<OperationalEmailQueuedMessage>(
                await store.GetProcessingEmailAsync(onceDueId, CancellationToken.None));
            Assert.Equal("morning_report", queued.TemplateKey);
            await store.UpdateProcessingEmailContentAsync(
                onceDueId, "Fresh shift analysis", new Dictionary<string, string> { ["shift_analysis"] = "Fresh shift analysis" },
                DateTime.UtcNow, CancellationToken.None);
            var dueDeliveryId = await store.CreateDeliverySnapshotAsync(
                onceDueId, "smtp", "noc@example.com", DateTime.UtcNow, CancellationToken.None);
            var dueDetail = await store.GetDeliveryDetailAsync(dueDeliveryId, CancellationToken.None);
            Assert.Equal("Fresh shift analysis", dueDetail?.Body);
            Assert.Equal("Fresh shift analysis", dueDetail?.Fields["shift_analysis"]);
            await store.CompleteDeliveryAsync(
                onceDueId, dueDeliveryId, true, "sent", DateTime.UtcNow, null, CancellationToken.None);
            Assert.DoesNotContain(await store.ClaimDueEmailsAsync(now, TimeSpan.FromMinutes(20), 25, CancellationToken.None),
                item => item == onceDueId);
            var staleHistory = await store.GetDeliveryDetailAsync(staleDeliveryId, CancellationToken.None);
            Assert.Equal("failed", staleHistory?.Status);
            var unattemptedHistory = Assert.Single(
                await store.GetDeliveryHistoryAsync(250, CancellationToken.None),
                item => item.EmailId == staleUnattemptedId);
            Assert.Equal("failed", unattemptedHistory.Status);
            Assert.Contains("interrupted", unattemptedHistory.ErrorMessage!, StringComparison.OrdinalIgnoreCase);
            var recurringAfterRecovery = Assert.Single(await store.GetScheduledEmailsByIdsAsync(
                [staleRecurringId], CancellationToken.None));
            Assert.Equal("active", recurringAfterRecovery.Status);
            Assert.True(recurringAfterRecovery.NextRunAt > now);
        }
        finally
        {
            File.Delete(databasePath);
        }
    }
}
