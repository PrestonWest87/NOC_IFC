using System.Text.Json.Serialization;
using NocIfc.Domain.BackupRestore;

namespace NocIfc.Api.Contracts;

public sealed record BackupStatusResponse(
    [property: JsonPropertyName("encryption_configured")] bool EncryptionConfigured,
    [property: JsonPropertyName("max_bytes")] long MaxBytes,
    [property: JsonPropertyName("scheduled_policy")] string ScheduledPolicy)
{
    public static BackupStatusResponse From(BackupStatus status) =>
        new(status.EncryptionConfigured, status.MaxBytes, status.ScheduledPolicy);
}

public sealed record BackupEntryResponse(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("filename")] string Filename,
    [property: JsonPropertyName("kind")] string Kind,
    [property: JsonPropertyName("created_at")] string CreatedAt,
    [property: JsonPropertyName("size_bytes")] long SizeBytes,
    [property: JsonPropertyName("table_count"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] int? TableCount,
    [property: JsonPropertyName("model_included"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] bool? ModelIncluded,
    [property: JsonPropertyName("reason"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Reason,
    [property: JsonPropertyName("encrypted_size_bytes"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] long? EncryptedSizeBytes)
{
    public static BackupEntryResponse From(BackupEntry entry) => new(
        entry.Id, entry.Filename, entry.Kind, entry.CreatedAt, entry.SizeBytes,
        entry.TableCount, entry.ModelIncluded, entry.Reason, entry.EncryptedSizeBytes);
}

public sealed record StagedBackupEntryResponse(
    [property: JsonPropertyName("stage_id")] string StageId,
    [property: JsonPropertyName("created_at")] string CreatedAt,
    [property: JsonPropertyName("size_bytes")] long SizeBytes,
    [property: JsonPropertyName("table_count"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] int? TableCount,
    [property: JsonPropertyName("model_included"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] bool? ModelIncluded)
{
    public static StagedBackupEntryResponse From(StagedBackupEntry entry) => new(
        entry.StageId, entry.CreatedAt, entry.SizeBytes, entry.TableCount, entry.ModelIncluded);
}

public sealed record BackupRestoreResultResponse(
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("backup_created_at")] string BackupCreatedAt,
    [property: JsonPropertyName("table_count")] int TableCount,
    [property: JsonPropertyName("model_restored")] bool ModelRestored,
    [property: JsonPropertyName("credentials_invalidated")] IReadOnlyDictionary<string, int> CredentialsInvalidated,
    [property: JsonPropertyName("pre_restore_backup")] string? PreRestoreBackup,
    [property: JsonPropertyName("staged_packages_cleared")] int StagedPackagesCleared)
{
    public static BackupRestoreResultResponse From(BackupRestoreResult result) => new(
        result.Status, result.BackupCreatedAt, result.TableCount, result.ModelRestored,
        result.CredentialsInvalidated, result.PreRestoreBackup, result.StagedPackagesCleared);
}
