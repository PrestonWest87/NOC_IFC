using System.Globalization;
using NocIfc.Infrastructure.Persistence.Sqlite;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class SqliteShiftLogbookStoreTests
{
    [Fact]
    public async Task ReadsFilteredVisibleEntriesAndCreatesSoftDeletesAndRestoresNotes()
    {
        var path = Path.Combine(Path.GetTempPath(), $"nocifc-logbook-{Guid.NewGuid():N}.sqlite");
        using (File.Create(path)) { }
        try
        {
            var connections = new SqliteConnectionFactory($"sqlite:///{path}");
            var now = Truncate(DateTime.UtcNow);
            await using (var connection = connections.Create())
            {
                await connection.OpenAsync();
                await using var setup = connection.CreateCommand();
                setup.CommandText = """
                    CREATE TABLE shift_logs (
                        id INTEGER PRIMARY KEY, analyst TEXT, author_role TEXT, shift_date DATETIME,
                        shift_period TEXT, content TEXT, created_at DATETIME, is_deleted INTEGER
                    );
                    CREATE TABLE roles (id INTEGER PRIMARY KEY, name TEXT);
                    CREATE TABLE users (id INTEGER PRIMARY KEY, full_name TEXT);
                    INSERT INTO roles VALUES (1,'admin'),(2,'analyst');
                    INSERT INTO users VALUES (1,'Jane Operator');
                    """;
                await setup.ExecuteNonQueryAsync();
                await using var insert = connection.CreateCommand();
                insert.CommandText = """
                    INSERT INTO shift_logs(id,analyst,author_role,shift_date,shift_period,content,created_at,is_deleted)
                    VALUES (1,'Jane Operator','analyst',$date,'Morning','Visible note',$date,0),
                           (2,'Other User','operator',$old,'Evening','Other role',$old,0),
                           (3,'Jane Operator','analyst',$date,'Morning','Deleted note',$date,1)
                    """;
                insert.Parameters.AddWithValue("$date", Format(now));
                insert.Parameters.AddWithValue("$old", Format(now.AddDays(-3)));
                await insert.ExecuteNonQueryAsync();
            }

            var store = new SqliteShiftLogbookStore(connections);
            var entries = await store.GetEntriesAsync("analyst", now.AddDays(-1), now.AddDays(1), CancellationToken.None);
            Assert.Single(entries);
            Assert.Equal("Visible note", entries[0].Content);
            Assert.Equal("Jane Operator", await store.GetUserFullNameAsync(1, CancellationToken.None));
            Assert.Equal(new[] { "admin", "analyst" }, await store.GetRoleNamesAsync(CancellationToken.None));

            var id = await store.CreateAsync("Jane Operator", "analyst", "Afternoon", "New note", now, now, CancellationToken.None);
            var created = await store.GetByIdAsync(id, CancellationToken.None);
            Assert.NotNull(created);
            Assert.False(created.IsDeleted);
            Assert.Equal("New note", created.Content);

            Assert.True(await store.SetDeletedAsync(id, true, CancellationToken.None));
            Assert.True((await store.GetByIdAsync(id, CancellationToken.None))!.IsDeleted);
            Assert.True(await store.SetDeletedAsync(id, false, CancellationToken.None));
            Assert.False((await store.GetByIdAsync(id, CancellationToken.None))!.IsDeleted);
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static DateTime Truncate(DateTime value) =>
        DateTime.ParseExact(Format(value), "yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture);

    private static string Format(DateTime value) =>
        value.ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture);
}
