using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;
using NocIfc.Application.Abstractions.Email;
using NocIfc.Application.Abstractions.Settings;
using NocIfc.Application.Features.Settings;
using NocIfc.Domain.Settings;
using NocIfc.Infrastructure.Integrations.Threat;
using NocIfc.Infrastructure.Persistence.Sqlite;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class CrimeDataSyncClientTests
{
    [Fact]
    public async Task ImportsDeduplicatedIncidentsPurgesOldRowsAndDispatchesHighSeverityOnlyOnce()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"nocifc-crime-sync-{Guid.NewGuid():N}.sqlite");
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
                    CREATE TABLE crime_incidents (
                        id TEXT PRIMARY KEY, category TEXT, raw_title TEXT, timestamp DATETIME,
                        distance_miles REAL, severity TEXT, lat REAL, lon REAL, is_alert_dispatched INTEGER
                    );
                    INSERT INTO crime_incidents VALUES ('old-incident','General','Old', $old, 0.1,'High',34.6,-92.3,0);
                    """;
                setup.Parameters.AddWithValue("$old", (now.AddDays(-8)).ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture));
                await setup.ExecuteNonQueryAsync();
            }

            var address = $"Smoke {Guid.NewGuid():N} Main Street";
            var secondAddress = $"Smoke {Guid.NewGuid():N} Second Street";
            var central = TimeZoneInfo.FindSystemTimeZoneById("America/Chicago");
            var dispatchDate = TimeZoneInfo.ConvertTime(DateTimeOffset.UtcNow, central)
                .ToString("MM/dd/yyyy HH:mm:ss", CultureInfo.InvariantCulture);
            var cad = JsonSerializer.Serialize(new[]
            {
                new { typeDescription = "BURGLARY", location = address, dispatchDate },
                new { typeDescription = "BURGLARY", location = address, dispatchDate },
                new { typeDescription = "NOISE", location = secondAddress, dispatchDate },
            });
            var handler = new ArcGisHandler(cad);
            using var httpClient = new HttpClient(handler);
            var sender = new StubEmailSender();
            var settings = new StubIntegrationSettingsStore(new OperationalIntegrationSettings(
                "", "", "", "", "", "", false, true, "", 15, 500,
                "sms@example.test", "email@example.test", new Dictionary<string, string>()));
            var client = new CrimeDataSyncClient(
                httpClient, new SqliteCrimeDataSyncStore(connections), settings, sender);

            var first = await client.SyncAsync(CancellationToken.None);

            Assert.Equal(2, first.AddedCount);
            Assert.Equal(1, first.AlertsDispatched);
            var sent = Assert.Single(sender.Sent);
            Assert.Equal("sms@example.test", sent.Recipient);
            Assert.Equal("Crime Alert: 0mi", sent.Subject);
            Assert.Contains("[ALERT] PERIMETER ALERT [ALERT]", sent.Body);
            Assert.Contains("Map: https://www.google.com/maps?q=34.6755,-92.3235", sent.Body);
            Assert.Equal(2, handler.GeocodeCalls);

            await using (var connection = connections.Create())
            {
                await connection.OpenAsync();
                await using var command = connection.CreateCommand();
                command.CommandText = "SELECT category, severity, distance_miles, is_alert_dispatched FROM crime_incidents ORDER BY category";
                await using var reader = await command.ExecuteReaderAsync();
                var rows = new List<(string Category, string Severity, double Distance, bool Dispatched)>();
                while (await reader.ReadAsync())
                {
                    rows.Add((reader.GetString(0), reader.GetString(1), reader.GetDouble(2), reader.GetBoolean(3)));
                }
                Assert.Collection(rows,
                    row =>
                    {
                        Assert.Equal("Asset/Copper Theft Risk", row.Category);
                        Assert.Equal("High", row.Severity);
                        Assert.Equal(0, row.Distance);
                        Assert.True(row.Dispatched);
                    },
                    row =>
                    {
                        Assert.Equal("General Police Activity", row.Category);
                        Assert.Equal("Low", row.Severity);
                        Assert.False(row.Dispatched);
                    });
            }

            var second = await client.SyncAsync(CancellationToken.None);
            Assert.Equal(0, second.AddedCount);
            Assert.Equal(0, second.AlertsDispatched);
            Assert.Single(sender.Sent);
        }
        finally
        {
            File.Delete(databasePath);
        }
    }

    private sealed class ArcGisHandler(string cad) : HttpMessageHandler
    {
        public int GeocodeCalls { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.Method == HttpMethod.Post)
            {
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(cad, Encoding.UTF8, "application/json"),
                });
            }
            GeocodeCalls++;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    "{\"candidates\":[{\"location\":{\"x\":-92.3235,\"y\":34.6755},\"score\":100}]}",
                    Encoding.UTF8,
                    "application/json"),
            });
        }
    }

    private sealed class StubIntegrationSettingsStore(OperationalIntegrationSettings settings) : IOperationalIntegrationSettingsStore
    {
        public Task<OperationalIntegrationSettings> GetAsync(CancellationToken cancellationToken) => Task.FromResult(settings);
        public Task<ElasticClientSettings> GetElasticClientSettingsAsync(CancellationToken cancellationToken) =>
            Task.FromResult(new ElasticClientSettings("", "", true, "", 15, 500));
        public Task SaveAsync(OperationalIntegrationSettingsUpdate update, int actorUserId, CancellationToken cancellationToken) =>
            Task.CompletedTask;
    }

    private sealed class StubEmailSender : IEmailSender
    {
        public List<(string Recipient, string Subject, string Body)> Sent { get; } = [];
        public Task<EmailSendResult> SendPlainTextAsync(string recipientOverride, string subject, string body, CancellationToken cancellationToken)
        {
            Sent.Add((recipientOverride, subject, body));
            return Task.FromResult(new EmailSendResult(true, "sent"));
        }
        public Task<EmailSendResult> SendHtmlAsync(string recipientOverride, string subject, string body, CancellationToken cancellationToken) =>
            Task.FromResult(new EmailSendResult(true, "sent"));
        public Task<EmailSendResult> SendHtmlWithAttachmentsAsync(
            string recipientOverride, string subject, string body, IReadOnlyList<EmailAttachment> attachments,
            CancellationToken cancellationToken) => Task.FromResult(new EmailSendResult(true, "sent"));
    }
}
