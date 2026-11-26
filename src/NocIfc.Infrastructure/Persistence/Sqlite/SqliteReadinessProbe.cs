namespace NocIfc.Infrastructure.Persistence.Sqlite;

public sealed class SqliteReadinessProbe
{
    public const string ExpectedSchemaRevision = "20261125_0025";

    private readonly SqliteConnectionFactory _connections;

    public SqliteReadinessProbe(SqliteConnectionFactory connections) => _connections = connections;

    public async Task<bool> IsReadyAsync(CancellationToken cancellationToken)
    {
        await using var connection = _connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT 1";
        var result = await command.ExecuteScalarAsync(cancellationToken);
        if (Convert.ToInt32(result, System.Globalization.CultureInfo.InvariantCulture) != 1)
        {
            return false;
        }

        await using var schemaCommand = connection.CreateCommand();
        schemaCommand.CommandText = "SELECT version_num FROM alembic_version";
        await using var reader = await schemaCommand.ExecuteReaderAsync(cancellationToken);
        var revisions = new List<string>();
        while (await reader.ReadAsync(cancellationToken))
        {
            revisions.Add(reader.GetString(0));
        }

        return revisions.Count == 1 && revisions[0] == ExpectedSchemaRevision;
    }
}
