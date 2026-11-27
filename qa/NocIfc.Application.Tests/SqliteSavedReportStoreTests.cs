using NocIfc.Infrastructure.Persistence.Sqlite;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class SqliteSavedReportStoreTests
{
    [Fact]
    public async Task SavesListsNewestFirstAndDeletesByReportId()
    {
        var path = Path.Combine(Path.GetTempPath(), $"nocifc-saved-reports-{Guid.NewGuid():N}.sqlite");
        using (File.Create(path)) { }
        try
        {
            var connections = new SqliteConnectionFactory($"sqlite:///{path}");
            await using (var connection = connections.Create())
            {
                await connection.OpenAsync();
                await using var setup = connection.CreateCommand();
                setup.CommandText = """
                    CREATE TABLE saved_reports (
                        id INTEGER PRIMARY KEY, title TEXT, author TEXT, content TEXT, created_at DATETIME
                    );
                    """;
                await setup.ExecuteNonQueryAsync();
            }

            var store = new SqliteSavedReportStore(connections);
            var oldTime = new DateTime(2026, 11, 25, 12, 0, 0, DateTimeKind.Utc);
            var newTime = oldTime.AddHours(1);
            Assert.Empty(await store.GetAllAsync(CancellationToken.None));
            await store.SaveAsync("Old report", "alice", "old body", oldTime, CancellationToken.None);
            await store.SaveAsync("New report", "bob", "new body", newTime, CancellationToken.None);

            var reports = await store.GetAllAsync(CancellationToken.None);

            Assert.Equal(new[] { "New report", "Old report" }, reports.Select(report => report.Title));
            Assert.Equal("bob", reports[0].Author);
            Assert.Equal("new body", reports[0].Content);
            await store.DeleteAsync(reports[0].Id, CancellationToken.None);
            await store.DeleteAsync(999, CancellationToken.None);
            Assert.Equal(new[] { "Old report" }, (await store.GetAllAsync(CancellationToken.None)).Select(report => report.Title));
        }
        finally
        {
            File.Delete(path);
        }
    }
}
