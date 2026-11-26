using NocIfc.Application.Abstractions.Identity;

namespace NocIfc.Infrastructure.Persistence.Sqlite;

public sealed class SqliteSiteTypeDirectory(SqliteConnectionFactory connections) : ISiteTypeDirectory
{
    public async Task<IReadOnlyList<string>> GetDatabaseSiteTypesAsync(CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT DISTINCT loc_type FROM monitored_locations";
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);

        var siteTypes = new List<string>();
        while (await reader.ReadAsync(cancellationToken))
        {
            if (!reader.IsDBNull(0))
            {
                var siteType = reader.GetString(0);
                if (siteType.Length > 0)
                {
                    siteTypes.Add(siteType);
                }
            }
        }

        return siteTypes;
    }
}
