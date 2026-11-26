using Microsoft.Data.Sqlite;
using NocIfc.Application.Abstractions.Regional;

namespace NocIfc.Infrastructure.Persistence.Sqlite;

public sealed class SqliteRegionalPreferenceStore(SqliteConnectionFactory connections) : IRegionalPreferenceStore
{
    public async Task<IReadOnlyList<string?>> GetWeatherPreferencesAsync(
        string username,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT alert_type
            FROM user_weather_prefs
            WHERE username = $username
            ORDER BY id
            """;
        command.Parameters.AddWithValue("$username", username);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var alertTypes = new List<string?>();
        while (await reader.ReadAsync(cancellationToken))
        {
            alertTypes.Add(reader.IsDBNull(0) ? null : reader.GetString(0));
        }
        return alertTypes;
    }

    public async Task ReplaceWeatherPreferencesAsync(
        string username,
        IReadOnlyList<string> alertTypes,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction();
        await using (var delete = connection.CreateCommand())
        {
            delete.Transaction = transaction;
            delete.CommandText = "DELETE FROM user_weather_prefs WHERE username = $username";
            delete.Parameters.AddWithValue("$username", username);
            await delete.ExecuteNonQueryAsync(cancellationToken);
        }
        foreach (var alertType in alertTypes)
        {
            await using var insert = connection.CreateCommand();
            insert.Transaction = transaction;
            insert.CommandText = "INSERT INTO user_weather_prefs (username, alert_type) VALUES ($username, $alert_type)";
            insert.Parameters.AddWithValue("$username", username);
            insert.Parameters.AddWithValue("$alert_type", alertType);
            await insert.ExecuteNonQueryAsync(cancellationToken);
        }
        transaction.Commit();
    }
}
