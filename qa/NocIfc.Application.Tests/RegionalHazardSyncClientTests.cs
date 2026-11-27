using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json.Nodes;
using NocIfc.Application.Abstractions.Email;
using NocIfc.Application.Abstractions.Regional;
using NocIfc.Application.Abstractions.Settings;
using NocIfc.Application.Features.Settings;
using NocIfc.Domain.Settings;
using NocIfc.Infrastructure.Integrations.Weather;
using NocIfc.Infrastructure.Persistence.Sqlite;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class RegionalHazardSyncClientTests
{
    [Fact]
    public async Task PollsCombinedNwsFeedWithLeaseValidatorsAndPersistsScopedLifecycleRows()
    {
        var (path, connections) = await CreateDatabaseAsync();
        try
        {
            var now = DateTime.UtcNow;
            var body = new JsonObject
            {
                ["type"] = "FeatureCollection",
                ["features"] = new JsonArray(
                    Alert("ar-alert", -92.2896, 34.7465, now),
                    Alert("border-alert", -93.75, 32.5252, now),
                    Alert("outside-alert", -80, 40, now)),
            }.ToJsonString();
            var handler = new NwsHandler(body);
            var coverage = ArkansasFireCoverage.LoadBundled();
            var store = new SqliteRegionalHazardSyncStore(connections);
            var client = Client(handler, store, coverage);

            var result = await client.SyncNwsAlertsAsync(CancellationToken.None);

            Assert.Equal("ok", result["status"]!.GetValue<string>());
            Assert.Equal(3, result["feature_count"]!.GetValue<int>());
            Assert.Equal(1, result["arkansas_alerts"]!.GetValue<int>());
            Assert.Equal(1, result["border_alerts"]!.GetValue<int>());
            Assert.Equal("NOC-IFC/2.0 (admin@example.test)", handler.Requests[0].UserAgent);
            Assert.Equal("https://api.weather.gov/alerts/active?area=AR,LA,TX,MS,MO,OK,TN", handler.Requests[0].Url);

            var layers = await ReadLayersAsync(connections);
            Assert.Equal(new[] { "ar-alert" }, FeatureIds(layers["nws_ar"]));
            Assert.Equal(new[] { "border-alert" }, FeatureIds(layers["nws_oos"]));
            var rows = await ReadHazardsAsync(connections);
            Assert.Equal(2, rows.Count);
            Assert.All(rows.Values, row => Assert.Equal("active", row));

            await AgeNwsPollAsync(connections, now.AddMinutes(-2));
            var notModified = await client.SyncNwsAlertsAsync(CancellationToken.None);
            Assert.Equal("not_modified", notModified["status"]!.GetValue<string>());
            Assert.Equal(2, handler.Requests.Count);
            Assert.Equal("\"nws-test-v1\"", handler.Requests[1].IfNoneMatch);
            Assert.Equal("Tue, 03 Nov 2026 18:00:00 GMT", handler.Requests[1].IfModifiedSince);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task RefreshesSpcAndUsgsFeedsAndSendsDeduplicatedProximityAlerts()
    {
        var (path, connections) = await CreateDatabaseAsync();
        try
        {
            var coverage = ArkansasFireCoverage.LoadBundled();
            var site = new MonitoredLocationEntry(
                1, "Central NOC", 34.7465, -92.2896, "NOC", "Central", "P1-Critical", null, null,
                false, null, null, null, null, null, null, null, null);
            var wildfirePayload = new JsonObject
            {
                ["meta"] = new JsonObject { ["status"] = "ok", ["last_success_at"] = DateTime.UtcNow.ToString("O") },
                ["incidents"] = new JsonArray(new JsonObject
                {
                    ["name"] = "Test Fire", ["irwin_id"] = "fire-1", ["lon"] = -92.2896,
                    ["lat"] = 34.7465, ["acres"] = 10,
                }),
                ["perimeters"] = new JsonArray(new JsonObject
                {
                    ["name"] = "Test Fire", ["irwin_id"] = "fire-1", ["acres"] = 10,
                    ["perimeter_acres"] = 12, ["contained"] = 0, ["state"] = "AR", ["county"] = "Pulaski",
                    ["started"] = "2026-11-26T10:00:00Z", ["cause"] = "Unknown",
                    ["perimeter_updated"] = "2026-11-26T12:00:00Z", ["map_method"] = "IRWIN",
                    ["geometry"] = Polygon((-92.30, 34.74), (-92.28, 34.74), (-92.28, 34.76), (-92.30, 34.76), (-92.30, 34.74)),
                }),
                ["footprints"] = new JsonArray(),
            }.ToJsonString();
            var sender = new StubEmailSender();
            var handler = new RegionalFeedsHandler(coverage.ArkansasBounds, EarthquakeCollection());
            var client = Client(
                handler,
                new SqliteRegionalHazardSyncStore(connections),
                coverage,
                new StubWildfires(wildfirePayload),
                [site],
                new StubIntegrationSettings("risk@example.test", "noc@example.test"),
                sender);

            var result = await client.SyncRegionalFeedsAsync(CancellationToken.None);

            Assert.Equal("ok", result["status"]!.GetValue<string>());
            Assert.Equal(3, handler.SpcRequests);
            Assert.Equal(2, handler.UsgsRequests);
            Assert.Equal(2, sender.Messages.Count);
            Assert.Equal("risk@example.test", sender.Messages[0].Recipient);
            Assert.Equal("NOC Alert: Earthquake Proximity Warning", sender.Messages[0].Subject);
            Assert.Contains("Magnitude: M3.2", sender.Messages[0].Body, StringComparison.Ordinal);
            Assert.Equal("noc@example.test", sender.Messages[1].Recipient);
            Assert.Equal("Wildfire Proximity Alert", sender.Messages[1].Subject);
            Assert.Contains("FIRE: Test Fire", sender.Messages[1].Body, StringComparison.Ordinal);
            var state = await new SqliteRegionalHazardSyncStore(connections).GetAlertStateAsync(CancellationToken.None);
            Assert.Contains("usgs-test", state.AlertedEarthquakeIds, StringComparison.Ordinal);
            Assert.Contains("fire-1:1", state.AlertedWildfireIds, StringComparison.Ordinal);
            Assert.Contains("last_alert_distance", state.WildfireProximityState, StringComparison.Ordinal);

            var repeated = await client.SyncRegionalFeedsAsync(CancellationToken.None);
            Assert.Equal("ok", repeated["status"]!.GetValue<string>());
            Assert.Equal(2, sender.Messages.Count);
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static RegionalHazardSyncClient Client(
        HttpMessageHandler handler,
        SqliteRegionalHazardSyncStore store,
        ArkansasFireCoverage coverage,
        StubWildfires? wildfires = null,
        IReadOnlyList<MonitoredLocationEntry>? sites = null,
        StubIntegrationSettings? integrationSettings = null,
        StubEmailSender? emailSender = null) =>
        new(
            new HttpClient(handler),
            new NwsForecastConfiguration("NOC-IFC/2.0", "admin@example.test"),
            store,
            coverage,
            coverage,
            new StubFacilities(sites),
            integrationSettings ?? new StubIntegrationSettings(),
            wildfires ?? new StubWildfires(),
            new WfcaWildfireSnapshotCache(),
            emailSender ?? new StubEmailSender());

    private static JsonObject Alert(string id, double longitude, double latitude, DateTime now) => new()
    {
        ["type"] = "Feature",
        ["id"] = id,
        ["properties"] = new JsonObject
        {
            ["id"] = $"https://api.weather.gov/alerts/{id}",
            ["event"] = "Tornado Warning",
            ["severity"] = "Extreme",
            ["headline"] = $"{id} warning",
            ["description"] = "Test alert",
            ["areaDesc"] = "Test county",
            ["messageType"] = "Alert",
            ["sent"] = now.AddMinutes(-1).ToString("O", CultureInfo.InvariantCulture),
            ["expires"] = now.AddHours(1).ToString("O", CultureInfo.InvariantCulture),
        },
        ["geometry"] = new JsonObject
        {
            ["type"] = "Point",
            ["coordinates"] = new JsonArray(longitude, latitude),
        },
    };

    private static JsonObject Polygon(params (double Longitude, double Latitude)[] positions) => new()
    {
        ["type"] = "Polygon",
        ["coordinates"] = new JsonArray(new JsonArray(positions.Select(position =>
            (JsonNode?)new JsonArray(position.Longitude, position.Latitude)).ToArray())),
    };

    private static JsonObject EarthquakeCollection() => new()
    {
        ["type"] = "FeatureCollection",
        ["features"] = new JsonArray(new JsonObject
        {
            ["type"] = "Feature", ["id"] = "usgs-test",
            ["properties"] = new JsonObject
            {
                ["mag"] = 3.2, ["place"] = "Near Conway",
                ["time"] = DateTimeOffset.UtcNow.AddMinutes(-10).ToUnixTimeMilliseconds(),
            },
            ["geometry"] = new JsonObject
            {
                ["type"] = "Point", ["coordinates"] = new JsonArray(-92.2896, 34.7465, 6),
            },
        }),
    };

    private static string[] FeatureIds(string json) =>
        ((JsonArray)(JsonNode.Parse(json)!["features"]!)).OfType<JsonObject>()
            .Select(feature => feature["id"]!.GetValue<string>()).ToArray();

    private static async Task<Dictionary<string, string>> ReadLayersAsync(SqliteConnectionFactory connections)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT feed_name, data FROM geojson_cache WHERE feed_name IN ('nws_ar','nws_oos')";
        await using var reader = await command.ExecuteReaderAsync();
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        while (await reader.ReadAsync()) result[reader.GetString(0)] = reader.GetString(1);
        return result;
    }

    private static async Task<Dictionary<string, string>> ReadHazardsAsync(SqliteConnectionFactory connections)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT hazard_id, status FROM regional_hazards";
        await using var reader = await command.ExecuteReaderAsync();
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        while (await reader.ReadAsync()) result[reader.GetString(0)] = reader.GetString(1);
        return result;
    }

    private static async Task AgeNwsPollAsync(SqliteConnectionFactory connections, DateTime lastAttempt)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "UPDATE geojson_cache SET last_attempt_at = $attempt WHERE feed_name = 'nws_region'";
        command.Parameters.AddWithValue("$attempt", lastAttempt.ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture));
        await command.ExecuteNonQueryAsync();
    }

    private static async Task<(string Path, SqliteConnectionFactory Connections)> CreateDatabaseAsync()
    {
        var path = Path.Combine(Path.GetTempPath(), $"nocifc-nws-sync-{Guid.NewGuid():N}.sqlite");
        using (File.Create(path)) { }
        var connections = new SqliteConnectionFactory($"sqlite:///{path}");
        await using var connection = connections.Create();
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE geojson_cache (
                feed_name TEXT PRIMARY KEY, data TEXT, updated_at DATETIME,
                last_attempt_at DATETIME, last_success_at DATETIME, last_error TEXT,
                last_http_status INTEGER, last_duration_ms INTEGER, retry_after_at DATETIME,
                etag TEXT, last_modified TEXT, feature_count INTEGER, coverage_summary TEXT
            );
            CREATE TABLE regional_hazards (
                id INTEGER PRIMARY KEY, hazard_id TEXT UNIQUE, hazard_type TEXT, severity TEXT,
                title TEXT, description TEXT, location TEXT, updated_at DATETIME, last_seen_at DATETIME,
                status TEXT, sent_at DATETIME, effective_at DATETIME, onset_at DATETIME,
                expires_at DATETIME, event_ending_at DATETIME, message_type TEXT,
                references_json TEXT, coverage_scope TEXT, coverage_precision TEXT
            );
            CREATE TABLE system_config (
                id INTEGER PRIMARY KEY, alerted_eq_ids TEXT, alerted_wildfire_ids TEXT,
                wildfire_proximity_state TEXT
            );
            INSERT INTO system_config VALUES (1, '[]', '[]', '{}');
            """;
        await command.ExecuteNonQueryAsync();
        return (path, connections);
    }

    private sealed class NwsHandler(string body) : HttpMessageHandler
    {
        public List<RequestInfo> Requests { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(new RequestInfo(
                request.RequestUri!.ToString(),
                request.Headers.UserAgent.ToString(),
                request.Headers.IfNoneMatch.FirstOrDefault()?.ToString(),
                request.Headers.IfModifiedSince?.ToString("R", CultureInfo.InvariantCulture)));
            var response = Requests.Count == 1
                ? new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body) }
                : new HttpResponseMessage(HttpStatusCode.NotModified);
            if (Requests.Count == 1)
            {
                response.Headers.ETag = new EntityTagHeaderValue("\"nws-test-v1\"");
                response.Content.Headers.LastModified = DateTimeOffset.Parse("Tue, 03 Nov 2026 18:00:00 GMT", CultureInfo.InvariantCulture);
            }
            return Task.FromResult(response);
        }
    }

    private sealed record RequestInfo(string Url, string UserAgent, string? IfNoneMatch, string? IfModifiedSince);

    private sealed class StubFacilities(IReadOnlyList<MonitoredLocationEntry>? locations = null) : IFacilityDirectoryStore
    {
        public Task<IReadOnlyList<MonitoredLocationEntry>> GetLocationsAsync(CancellationToken cancellationToken) => Task.FromResult<IReadOnlyList<MonitoredLocationEntry>>(locations ?? []);
        public Task<IReadOnlyList<MonitoredLocationEntry>> GetAdminLocationsAsync(CancellationToken cancellationToken) => Task.FromResult<IReadOnlyList<MonitoredLocationEntry>>(locations ?? []);
        public Task<IReadOnlyList<MonitoredLocationContactEntry>?> GetSiteContactsAsync(int locationId, CancellationToken cancellationToken) => Task.FromResult<IReadOnlyList<MonitoredLocationContactEntry>?>(null);
        public Task<IReadOnlyList<MonitoredLocationContactEntry>?> ReplaceSiteContactsAsync(int locationId, IReadOnlyList<MonitoredLocationContactValue> contacts, CancellationToken cancellationToken) => Task.FromResult<IReadOnlyList<MonitoredLocationContactEntry>?>(null);
        public Task<int> ImportLocationsAsync(IReadOnlyList<MonitoredLocationImportRow> locations, string mode, CancellationToken cancellationToken) => Task.FromResult(0);
        public Task UpdateLocationsAsync(IReadOnlyList<MonitoredLocationEditRow> locations, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class StubIntegrationSettings(
        string riskAlertRecipients = "",
        string nocNotifyEmail = "") : IOperationalIntegrationSettingsStore
    {
        public Task<OperationalIntegrationSettings> GetAsync(CancellationToken cancellationToken) => Task.FromResult(
            new OperationalIntegrationSettings(
                riskAlertRecipients, "", nocNotifyEmail, "", "", "", false, true, "", 15, 500, "", "",
                new Dictionary<string, string>(StringComparer.Ordinal)));
        public Task<ElasticClientSettings> GetElasticClientSettingsAsync(CancellationToken cancellationToken) => throw new NotImplementedException();
        public Task SaveAsync(OperationalIntegrationSettingsUpdate update, int actorUserId, CancellationToken cancellationToken) => throw new NotImplementedException();
    }

    private sealed class StubWildfires(string json = "{\"meta\":{\"status\":\"error\"},\"incidents\":[],\"perimeters\":[]}") : IRegionalWildfireProvider
    {
        public Task<string> GetActiveWildfiresJsonAsync(CancellationToken cancellationToken) => Task.FromResult(json);
    }

    private sealed class StubEmailSender : IEmailSender
    {
        public List<EmailMessage> Messages { get; } = [];

        public Task<EmailSendResult> SendPlainTextAsync(string recipientOverride, string subject, string body, CancellationToken cancellationToken)
        {
            Messages.Add(new EmailMessage(recipientOverride, subject, body));
            return Task.FromResult(new EmailSendResult(true, "sent"));
        }

        public Task<EmailSendResult> SendHtmlAsync(string recipientOverride, string subject, string body, CancellationToken cancellationToken) =>
            SendPlainTextAsync(recipientOverride, subject, body, cancellationToken);

        public Task<EmailSendResult> SendHtmlWithAttachmentsAsync(
            string recipientOverride,
            string subject,
            string body,
            IReadOnlyList<EmailAttachment> attachments,
            CancellationToken cancellationToken) =>
            SendHtmlAsync(recipientOverride, subject, body, cancellationToken);
    }

    private sealed record EmailMessage(string Recipient, string Subject, string Body);

    private sealed class RegionalFeedsHandler(string arkansasBounds, JsonObject earthquakeCollection) : HttpMessageHandler
    {
        public int SpcRequests { get; private set; }
        public int UsgsRequests { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var url = request.RequestUri!.ToString();
            JsonObject response;
            if (url.Contains("spc.noaa.gov", StringComparison.Ordinal))
            {
                SpcRequests++;
                response = new JsonObject { ["type"] = "FeatureCollection", ["features"] = new JsonArray() };
            }
            else
            {
                UsgsRequests++;
                var minLatitude = arkansasBounds.Split(',')[1];
                response = request.RequestUri.Query.Contains($"minlatitude={minLatitude}", StringComparison.Ordinal)
                    ? (JsonObject)earthquakeCollection.DeepClone()
                    : new JsonObject { ["type"] = "FeatureCollection", ["features"] = new JsonArray() };
            }
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(response.ToJsonString(), Encoding.UTF8, "application/geo+json"),
            });
        }
    }
}
