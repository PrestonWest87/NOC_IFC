using System.Globalization;
using NocIfc.Infrastructure.Persistence.Sqlite;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class SqliteDailyBriefingStoreTests
{
    [Fact]
    public async Task ListsArchivedDailyBriefingsNewestFirst()
    {
        var path = Path.Combine(Path.GetTempPath(), $"nocifc-daily-briefings-{Guid.NewGuid():N}.sqlite");
        using (File.Create(path)) { }
        try
        {
            var connections = new SqliteConnectionFactory($"sqlite:///{path}");
            var oldDate = new DateTime(2026, 11, 24);
            var newDate = oldDate.AddDays(1);
            await using (var connection = connections.Create())
            {
                await connection.OpenAsync();
                await using var setup = connection.CreateCommand();
                setup.CommandText = """
                    CREATE TABLE daily_briefings (
                        id INTEGER PRIMARY KEY, report_date DATETIME UNIQUE, content TEXT, created_at DATETIME
                    );
                    INSERT INTO daily_briefings VALUES
                        (1,$old,'Old Daily Fusion',$old),
                        (2,$new,'New Daily Fusion',$new);
                    """;
                setup.Parameters.AddWithValue("$old", Format(oldDate));
                setup.Parameters.AddWithValue("$new", Format(newDate));
                await setup.ExecuteNonQueryAsync();
            }

            var reports = await new SqliteDailyBriefingStore(connections).GetAllAsync(CancellationToken.None);

            Assert.Equal(new[] { "New Daily Fusion", "Old Daily Fusion" }, reports.Select(report => report.Content));
            Assert.Equal(newDate, reports[0].ReportDate);
            Assert.Equal(newDate, reports[0].CreatedAt);
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static string Format(DateTime value) =>
        DateTime.SpecifyKind(value, DateTimeKind.Unspecified)
            .ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture);
}
