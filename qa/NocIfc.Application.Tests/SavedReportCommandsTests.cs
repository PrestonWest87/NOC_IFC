using NocIfc.Application.Abstractions.Reporting;
using NocIfc.Application.Features.Reporting;
using NocIfc.Domain.Reporting;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class SavedReportCommandsTests
{
    [Fact]
    public async Task AppliesDefaultsAndRejectsOversizedFields()
    {
        var store = new StubStore();
        var commands = new SavedReportCommands(store);

        await commands.SaveAsync(null, null, null, CancellationToken.None);

        Assert.Equal(("Untitled Report", "Unknown", ""), store.Saved);
        await Assert.ThrowsAsync<ArgumentException>(() =>
            commands.SaveAsync("x", "author", new string('x', 200_001), CancellationToken.None));
    }

    private sealed class StubStore : ISavedReportStore
    {
        public (string Title, string Author, string Content)? Saved { get; private set; }
        public Task<IReadOnlyList<SavedReportEntry>> GetAllAsync(CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<SavedReportEntry>>([]);
        public Task SaveAsync(string title, string author, string content, DateTime createdAtUtc, CancellationToken cancellationToken)
        {
            Saved = (title, author, content);
            return Task.CompletedTask;
        }
        public Task DeleteAsync(int reportId, CancellationToken cancellationToken) => Task.CompletedTask;
    }
}
