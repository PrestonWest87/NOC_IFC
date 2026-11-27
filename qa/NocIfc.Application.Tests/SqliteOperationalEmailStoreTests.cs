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
        }
        finally
        {
            File.Delete(databasePath);
        }
    }
}
