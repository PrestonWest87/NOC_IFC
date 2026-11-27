namespace NocIfc.Domain.BackupRestore;

public sealed record BackupEncryptionSettings(string KeysJson, string ActiveKeyId, string MaxBytes);

public sealed record BackupStatus(bool EncryptionConfigured, long MaxBytes, string ScheduledPolicy);

public sealed record BackupEntry(
    string Id,
    string Filename,
    string Kind,
    string CreatedAt,
    long SizeBytes,
    int? TableCount = null,
    bool? ModelIncluded = null,
    string? Reason = null,
    long? EncryptedSizeBytes = null);

public sealed record StagedBackupEntry(
    string StageId,
    string CreatedAt,
    long SizeBytes,
    int? TableCount = null,
    bool? ModelIncluded = null);

public sealed record BackupValidationResult(
    string KeyId,
    int TableCount,
    long DatabaseSizeBytes,
    bool ModelIncluded,
    string? Reason,
    long EncryptedSizeBytes);

public sealed record BackupRestoreResult(
    string Status,
    string BackupCreatedAt,
    int TableCount,
    bool ModelRestored,
    IReadOnlyDictionary<string, int> CredentialsInvalidated,
    string? PreRestoreBackup,
    int StagedPackagesCleared);

public sealed class BackupException(string message, Exception? innerException = null)
    : Exception(message, innerException);
