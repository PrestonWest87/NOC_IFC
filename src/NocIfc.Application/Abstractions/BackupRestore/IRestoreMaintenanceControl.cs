using NocIfc.Domain.BackupRestore;

namespace NocIfc.Application.Abstractions.BackupRestore;

public sealed record RestoreControlRequest(
    string RestoreId,
    string StageId,
    string RequestedBy,
    string State,
    DateTimeOffset StartedAt,
    DateTimeOffset UpdatedAt);

public sealed record RestoreProgressState(
    string RestoreId,
    string State,
    string Message,
    int? Percent,
    DateTimeOffset StartedAt,
    DateTimeOffset UpdatedAt,
    BackupRestoreResult? Result);

public sealed record RestoreProcessStatus(
    string Process,
    string? RestoreId,
    string State,
    int Active,
    IReadOnlyList<string> Jobs,
    DateTimeOffset UpdatedAt);

public sealed class RestoreInProgressException(string message) : InvalidOperationException(message);

public interface IRestoreMaintenanceControl
{
    bool MaintenanceRequested { get; }
    int ActiveApiRequests { get; }
    int ActiveApiBackgroundWriters { get; }
    bool TryBeginApiRequest();
    void EndApiRequest();
    bool TryBeginApiBackgroundWriter();
    void EndApiBackgroundWriter();
    RestoreControlRequest? GetActiveRestore();
    RestoreControlRequest BeginRestore(string stageId, string requestedBy);
    void UpdateRestore(string restoreId, string state, string message, int? percent = null, BackupRestoreResult? result = null);
    void FinishRestore(string restoreId, string state, string message, BackupRestoreResult? result = null);
    RestoreProgressState? GetRestoreStatus(string restoreId);
    void PublishWorkerStatus(string state, int active, IReadOnlyList<string>? jobs = null);
    void PublishProcessStatus(string process, string state, int active, IReadOnlyList<string>? jobs = null);
    RestoreProcessStatus? GetProcessStatus(string process, string restoreId);
}
