using System.Text.Json;
using NocIfc.Application.Abstractions.BackupRestore;
using NocIfc.Domain.BackupRestore;
using NocIfc.Infrastructure.Persistence.Sqlite;

namespace NocIfc.Infrastructure.BackupRestore;

public sealed class SqliteRestoreMaintenanceControl(SqliteConnectionFactory connections)
    : IRestoreMaintenanceControl
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly object sync = new();
    private int activeApiRequests;
    private int activeApiBackgroundWriters;

    public bool MaintenanceRequested => File.Exists(MarkerPath);

    public int ActiveApiRequests
    {
        get { lock (sync) return activeApiRequests; }
    }

    public int ActiveApiBackgroundWriters
    {
        get { lock (sync) return activeApiBackgroundWriters; }
    }

    public bool TryBeginApiRequest()
    {
        lock (sync)
        {
            if (MaintenanceRequested) return false;
            activeApiRequests++;
            return true;
        }
    }

    public void EndApiRequest()
    {
        lock (sync) activeApiRequests = Math.Max(0, activeApiRequests - 1);
    }

    public bool TryBeginApiBackgroundWriter()
    {
        lock (sync)
        {
            if (MaintenanceRequested) return false;
            activeApiBackgroundWriters++;
            return true;
        }
    }

    public void EndApiBackgroundWriter()
    {
        lock (sync) activeApiBackgroundWriters = Math.Max(0, activeApiBackgroundWriters - 1);
    }

    public RestoreControlRequest? GetActiveRestore() => ReadJson<RestoreControlRequest>(MarkerPath);

    public RestoreControlRequest BeginRestore(string stageId, string requestedBy)
    {
        lock (sync)
        {
            EnsureControlDirectories();
            if (MaintenanceRequested) throw new RestoreInProgressException("A full database restore is already in progress.");
            var now = DateTimeOffset.UtcNow;
            var request = new RestoreControlRequest(
                Guid.NewGuid().ToString("N"), stageId, Truncate(requestedBy, 128), "quiescing", now, now);
            try
            {
                AtomicWrite(MarkerPath, request, overwrite: false);
            }
            catch (IOException)
            {
                throw new RestoreInProgressException("A full database restore is already in progress.");
            }
            try
            {
                WriteStatus(new RestoreProgressState(
                    request.RestoreId, "quiescing", "Pausing database writers before restore.", 5, now, now, null));
            }
            catch
            {
                File.Delete(MarkerPath);
                throw;
            }
            return request;
        }
    }

    public void UpdateRestore(
        string restoreId,
        string state,
        string message,
        int? percent = null,
        BackupRestoreResult? result = null)
    {
        var request = GetActiveRestore();
        if (request is null || request.RestoreId != restoreId)
        {
            throw new RestoreInProgressException("The active restore request changed unexpectedly.");
        }
        var now = DateTimeOffset.UtcNow;
        var updatedRequest = request with { State = state, UpdatedAt = now };
        AtomicWrite(MarkerPath, updatedRequest, overwrite: true);
        var previous = GetRestoreStatus(restoreId);
        WriteStatus(new RestoreProgressState(
            restoreId,
            state,
            Truncate(message, 500),
            percent is null ? previous?.Percent : Math.Clamp(percent.Value, 0, 100),
            request.StartedAt,
            now,
            result ?? previous?.Result));
    }

    public void FinishRestore(string restoreId, string state, string message, BackupRestoreResult? result = null)
    {
        UpdateRestore(restoreId, state, message, state == "complete" ? 100 : null, result);
        lock (sync)
        {
            var active = GetActiveRestore();
            if (active?.RestoreId == restoreId) File.Delete(MarkerPath);
        }
    }

    public RestoreProgressState? GetRestoreStatus(string restoreId)
    {
        if (!Guid.TryParseExact(restoreId, "N", out var parsed)) return null;
        var status = ReadJson<RestoreProgressState>(Path.Combine(RequestsDirectory, $"{parsed:N}.json"));
        if (status is null || DateTimeOffset.UtcNow - status.UpdatedAt > TimeSpan.FromHours(24)) return null;
        return status;
    }

    public void PublishWorkerStatus(string state, int active, IReadOnlyList<string>? jobs = null)
    {
        EnsureControlDirectories();
        var restoreId = GetActiveRestore()?.RestoreId;
        var status = new RestoreProcessStatus(
            "worker", restoreId, state, Math.Max(0, active), jobs?.Take(32).ToArray() ?? [], DateTimeOffset.UtcNow);
        AtomicWrite(Path.Combine(ProcessStatusDirectory, "worker.json"), status, overwrite: true);
    }

    public RestoreProcessStatus? GetProcessStatus(string process, string restoreId)
    {
        if (process != "worker" || !Guid.TryParseExact(restoreId, "N", out _)) return null;
        var status = ReadJson<RestoreProcessStatus>(Path.Combine(ProcessStatusDirectory, $"{process}.json"));
        if (status?.RestoreId != restoreId || DateTimeOffset.UtcNow - status.UpdatedAt > TimeSpan.FromSeconds(10))
        {
            return null;
        }
        return status;
    }

    private string ControlDirectory => Path.Combine(Path.GetDirectoryName(connections.DatabasePath)!, ".restore-control");
    private string RequestsDirectory => Path.Combine(ControlDirectory, "requests");
    private string ProcessStatusDirectory => Path.Combine(ControlDirectory, "process-status");
    private string MarkerPath => Path.Combine(ControlDirectory, "active-restore.json");

    private void EnsureControlDirectories()
    {
        SetPrivateDirectory(ControlDirectory);
        SetPrivateDirectory(RequestsDirectory);
        SetPrivateDirectory(ProcessStatusDirectory);
    }

    private void WriteStatus(RestoreProgressState status)
    {
        EnsureControlDirectories();
        AtomicWrite(Path.Combine(RequestsDirectory, $"{status.RestoreId}.json"), status, overwrite: true);
    }

    private static T? ReadJson<T>(string path) where T : class
    {
        try
        {
            using var stream = File.OpenRead(path);
            return JsonSerializer.Deserialize<T>(stream, JsonOptions);
        }
        catch (FileNotFoundException) { return null; }
        catch (DirectoryNotFoundException) { return null; }
        catch (IOException) { return null; }
        catch (JsonException) { return null; }
    }

    private static void AtomicWrite<T>(string path, T value, bool overwrite)
    {
        var temporary = Path.Combine(Path.GetDirectoryName(path)!, $".{Path.GetFileName(path)}.{Guid.NewGuid():N}.tmp");
        try
        {
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                SetPrivateFile(temporary);
                JsonSerializer.Serialize(stream, value, JsonOptions);
                stream.Flush(true);
            }
            File.Move(temporary, path, overwrite);
        }
        finally
        {
            File.Delete(temporary);
        }
    }

    private static void SetPrivateDirectory(string path)
    {
        Directory.CreateDirectory(path);
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
    }

    private static void SetPrivateFile(string path)
    {
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }

    private static string Truncate(string value, int maximum) =>
        value.Length > maximum ? value[..maximum] : value;
}
