using System.Globalization;
using System.Net;
using System.Text;
using NocIfc.Infrastructure.Integrations.Threat;
using NocIfc.Infrastructure.Persistence.Sqlite;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class CloudStatusSyncClientTests
{
    private const string AwsUrl = "https://status.aws.amazon.com/rss/all.rss";
    private const string MicrosoftUrl = "https://status.cloud.microsoft/api/feed/mac";

    [Fact]
    public async Task FetchesFiltersAndReconcilesProviderIncidentsAndMicrosoftFreshness()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"nocifc-cloud-sync-{Guid.NewGuid():N}.sqlite");
        using (File.Create(databasePath)) { }
        try
        {
            var connections = new SqliteConnectionFactory($"sqlite:///{databasePath}");
            await using (var connection = connections.Create())
            {
                await connection.OpenAsync();
                await using var setup = connection.CreateCommand();
                setup.CommandText = """
                    CREATE TABLE cloud_outages (
                        id INTEGER PRIMARY KEY, provider TEXT, service TEXT, title TEXT, description TEXT,
                        link TEXT, is_resolved INTEGER, updated_at DATETIME, external_id TEXT, status_code TEXT
                    );
                    CREATE UNIQUE INDEX uq_cloud_outages_provider_external_id ON cloud_outages(provider, external_id);
                    CREATE TABLE microsoft_365_status_state (
                        id INTEGER PRIMARY KEY, last_attempt_at DATETIME, last_success_at DATETIME,
                        last_duration_ms INTEGER, last_http_status INTEGER, last_error TEXT
                    );
                    """;
                await setup.ExecuteNonQueryAsync();
            }

            var published = DateTimeOffset.UtcNow.ToString("r", CultureInfo.InvariantCulture);
            var awsFeed = $"""
                <rss><channel>
                  <item><title>Amazon EC2 - API outage [Resolved] us-east-1</title><link>https://aws.example.test/1</link><description>Resolved incident</description><pubDate>{published}</pubDate><guid>aws-incident-1</guid></item>
                  <item><title>AWS - Scheduled maintenance us-east-1</title><description>Upcoming update</description><pubDate>{published}</pubDate></item>
                  <item><title>AWS - Singapore outage</title><description>Regional incident</description><pubDate>{published}</pubDate></item>
                </channel></rss>
                """;
            var microsoftFeed = $"""
                <rss><channel>
                  <item><title>Exchange Online service degradation</title><link>https://m365.example.test/1</link><description>&lt;p&gt;Service is degraded&lt;/p&gt;</description><pubDate>{published}</pubDate><guid>m365-incident-1</guid><status>Investigating</status></item>
                </channel></rss>
                """;
            var handler = new FeedHandler(awsFeed, microsoftFeed);
            using var httpClient = new HttpClient(handler);
            var client = new CloudStatusSyncClient(httpClient, new SqliteCloudStatusSyncStore(connections));

            var first = await client.SyncAsync(CancellationToken.None);

            Assert.Equal(2, first.AddedCount);
            Assert.Equal(0, first.ResolvedCount);
            Assert.Equal(2, first.FilteredCount);
            Assert.Empty(first.FailedProviders);
            await using (var connection = connections.Create())
            {
                await connection.OpenAsync();
                await using var outages = connection.CreateCommand();
                outages.CommandText = "SELECT provider, service, description, is_resolved, external_id, status_code FROM cloud_outages ORDER BY provider";
                await using var reader = await outages.ExecuteReaderAsync();
                Assert.True(await reader.ReadAsync());
                Assert.Equal("AWS", reader.GetString(0));
                Assert.Equal("Amazon EC2 [US-East (N. Virginia)]", reader.GetString(1));
                Assert.True(reader.GetBoolean(3));
                Assert.Equal("", reader.GetString(5));
                Assert.True(await reader.ReadAsync());
                Assert.Equal("Microsoft 365", reader.GetString(0));
                Assert.Equal("Microsoft 365 Service Health", reader.GetString(1));
                Assert.Equal("Service is degraded", reader.GetString(2));
                Assert.False(reader.GetBoolean(3));
                Assert.Equal("m365-incident-1", reader.GetString(4));
                Assert.Equal("investigating", reader.GetString(5));
                Assert.False(await reader.ReadAsync());
            }

            var second = await client.SyncAsync(CancellationToken.None);
            Assert.Equal(0, second.AddedCount);
            Assert.Equal(0, second.ResolvedCount);
            handler.MicrosoftFeed = $"""
                <rss><channel>
                  <item><title>Exchange Online service restored</title><link>https://m365.example.test/1</link><description>Service restored</description><pubDate>{DateTimeOffset.UtcNow.AddMinutes(1).ToString("r", CultureInfo.InvariantCulture)}</pubDate><guid>m365-incident-1</guid><status>ServiceOperational</status></item>
                </channel></rss>
                """;
            var resolved = await client.SyncAsync(CancellationToken.None);
            Assert.Equal(0, resolved.AddedCount);
            Assert.Equal(1, resolved.ResolvedCount);
            await using (var connection = connections.Create())
            {
                await connection.OpenAsync();
                await using (var incident = connection.CreateCommand())
                {
                    incident.CommandText = "SELECT is_resolved, status_code FROM cloud_outages WHERE provider='Microsoft 365' AND external_id='m365-incident-1'";
                    await using var reader = await incident.ExecuteReaderAsync();
                    Assert.True(await reader.ReadAsync());
                    Assert.True(reader.GetBoolean(0));
                    Assert.Equal("serviceoperational", reader.GetString(1));
                }
                await using var state = connection.CreateCommand();
                state.CommandText = "SELECT last_attempt_at, last_success_at, last_http_status, last_error FROM microsoft_365_status_state WHERE id=1";
                await using var stateReader = await state.ExecuteReaderAsync();
                Assert.True(await stateReader.ReadAsync());
                Assert.False(stateReader.IsDBNull(0));
                Assert.False(stateReader.IsDBNull(1));
                Assert.Equal(200, stateReader.GetInt32(2));
                Assert.True(stateReader.IsDBNull(3));
            }
        }
        finally
        {
            File.Delete(databasePath);
        }
    }

    private sealed class FeedHandler(string awsFeed, string microsoftFeed) : HttpMessageHandler
    {
        public string MicrosoftFeed { get; set; } = microsoftFeed;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var url = request.RequestUri?.ToString();
            var body = url switch
            {
                AwsUrl => awsFeed,
                MicrosoftUrl => MicrosoftFeed,
                _ => "<rss><channel /></rss>",
            };
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(body, Encoding.UTF8, "application/rss+xml"),
            });
        }
    }
}
