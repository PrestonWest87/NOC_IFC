using Microsoft.Data.Sqlite;
using NocIfc.Infrastructure.Persistence.Sqlite;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class SqliteReadinessProbeTests
{
    [Fact]
    public async Task ReadinessRequiresExactlyTheCurrentAlembicRevision()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"noc-ifc-schema-{Guid.NewGuid():N}.sqlite");
        try
        {
            await using (var connection = new SqliteConnection($"Data Source={databasePath}"))
            {
                await connection.OpenAsync();
                await using var command = connection.CreateCommand();
                command.CommandText = "CREATE TABLE alembic_version (version_num TEXT NOT NULL); " +
                    $"INSERT INTO alembic_version (version_num) VALUES ('{SqliteReadinessProbe.ExpectedSchemaRevision}');";
                await command.ExecuteNonQueryAsync();
            }

            var probe = new SqliteReadinessProbe(new SqliteConnectionFactory($"sqlite:///{databasePath}"));
            Assert.True(await probe.IsReadyAsync(CancellationToken.None));

            await using (var connection = new SqliteConnection($"Data Source={databasePath}"))
            {
                await connection.OpenAsync();
                await using var command = connection.CreateCommand();
                command.CommandText = "UPDATE alembic_version SET version_num = 'older_revision'";
                await command.ExecuteNonQueryAsync();
            }

            Assert.False(await probe.IsReadyAsync(CancellationToken.None));
        }
        finally
        {
            File.Delete(databasePath);
        }
    }
}
