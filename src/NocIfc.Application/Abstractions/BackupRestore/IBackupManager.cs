using NocIfc.Domain.BackupRestore;

namespace NocIfc.Application.Abstractions.BackupRestore;

public interface IBackupManager
{
    BackupStatus GetStatus();
    BackupEntry CreateBackup(string kind, string? reason = null, string? createdBy = null);
    IReadOnlyList<BackupEntry> ListBackups();
    FileStream OpenBackupRead(string backupId);
    void DeleteBackup(string backupId);
    StagedBackupEntry StageUpload(Stream source);
    IReadOnlyList<StagedBackupEntry> ListStagedBackups();
    void DeleteStagedBackup(string stageId);
    BackupValidationResult ValidateStagedBackup(string stageId);
    BackupRestoreResult RestoreStagedBackup(string stageId, bool maintenanceConfirmed);
    int ClearStagedBackups();
}
