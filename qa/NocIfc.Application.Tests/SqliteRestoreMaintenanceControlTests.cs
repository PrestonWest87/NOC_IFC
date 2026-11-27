using NocIfc.Infrastructure.BackupRestore;
using NocIfc.Infrastructure.Persistence.Sqlite;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class SqliteRestoreMaintenanceControlTests
{
    [Fact]
    public void MaintenanceMarkerBlocksRequestsUntilMatchingRestoreFinishes()
    {
        var workspace = Directory.CreateTempSubdirectory("nocifc-restore-control-");
        var databasePath = Path.Combine(workspace.FullName, "database.sqlite");
        using (File.Create(databasePath)) { }
        try
        {
            var control = new SqliteRestoreMaintenanceControl(
                new SqliteConnectionFactory($"sqlite:///{databasePath}"));

            var request = control.BeginRestore("stage-0123456789abcdef0123456789abcdef.nocbackup", "admin");

            Assert.True(control.MaintenanceRequested);
            Assert.False(control.TryBeginApiRequest());
            control.PublishWorkerStatus("paused", 0);
            Assert.Equal("paused", control.GetProcessStatus("worker", request.RestoreId)?.State);
            control.PublishProcessStatus("webhook", "draining", 2, ["solarwinds_webhook"]);
            Assert.Equal(2, control.GetProcessStatus("webhook", request.RestoreId)?.Active);
            control.UpdateRestore(request.RestoreId, "restoring", "Installing database.", percent: 50);
            Assert.Equal("restoring", control.GetRestoreStatus(request.RestoreId)?.State);
            control.FinishRestore(request.RestoreId, "complete", "Restored.");

            Assert.False(control.MaintenanceRequested);
            Assert.Equal("complete", control.GetRestoreStatus(request.RestoreId)?.State);
            Assert.True(control.TryBeginApiRequest());
            control.EndApiRequest();
        }
        finally
        {
            Directory.Delete(workspace.FullName, true);
        }
    }
}
