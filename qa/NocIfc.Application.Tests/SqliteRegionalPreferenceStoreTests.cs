using NocIfc.Infrastructure.Persistence.Sqlite;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class SqliteRegionalPreferenceStoreTests
{
    [Fact]
    public async Task ReplacesWeatherPreferencesOnlyForTheRequestedUser()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"nocifc-regional-prefs-{Guid.NewGuid():N}.sqlite");
        using (File.Create(databasePath)) { }
        try
        {
            var connections = new SqliteConnectionFactory($"sqlite:///{databasePath}");
            await using (var connection = connections.Create())
            {
                await connection.OpenAsync();
                await using var setup = connection.CreateCommand();
                setup.CommandText = """
                    CREATE TABLE user_weather_prefs (
                        id INTEGER PRIMARY KEY, username TEXT, alert_type TEXT
                    );
                    INSERT INTO user_weather_prefs (username, alert_type) VALUES
                        ('alice','TORNADO'), ('bob','FLOOD'), ('alice','WINTER_STORM');
                    """;
                await setup.ExecuteNonQueryAsync();
            }

            var store = new SqliteRegionalPreferenceStore(connections);
            await store.ReplaceWeatherPreferencesAsync("alice", ["FLOOD", "TORNADO"], CancellationToken.None);

            Assert.Equal(new[] { "FLOOD", "TORNADO" }, await store.GetWeatherPreferencesAsync("alice", CancellationToken.None));
            Assert.Equal(new[] { "FLOOD" }, await store.GetWeatherPreferencesAsync("bob", CancellationToken.None));
            await store.ReplaceWeatherPreferencesAsync("alice", [], CancellationToken.None);
            Assert.Empty(await store.GetWeatherPreferencesAsync("alice", CancellationToken.None));
        }
        finally
        {
            File.Delete(databasePath);
        }
    }
}
