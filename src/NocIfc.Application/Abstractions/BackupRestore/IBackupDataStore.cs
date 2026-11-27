using System.Text.Json.Nodes;

namespace NocIfc.Application.Abstractions.BackupRestore;

public interface IBackupDataStore
{
    Task<JsonObject> GetLegacySettingsBackupAsync(CancellationToken cancellationToken);
    Task<IReadOnlyDictionary<string, int>> RestoreLegacySettingsBackupAsync(
        JsonObject data,
        CancellationToken cancellationToken);
    Task<JsonObject> ExportAllTablesAsync(CancellationToken cancellationToken);
    Task<IReadOnlyDictionary<string, int>> ImportAllTablesAsync(
        JsonObject data,
        bool merge,
        CancellationToken cancellationToken);
    Task<IReadOnlyDictionary<string, int>> ImportDatabaseRowsAsync(
        string databasePath,
        CancellationToken cancellationToken);
}
