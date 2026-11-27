using System.Buffers.Binary;
using System.Globalization;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using Microsoft.Data.Sqlite;
using NocIfc.Application.Abstractions.BackupRestore;
using NocIfc.Domain.BackupRestore;
using NocIfc.Infrastructure.Persistence.Sqlite;

namespace NocIfc.Infrastructure.BackupRestore;

public sealed class SqliteBackupManager(
    SqliteConnectionFactory connections,
    BackupEncryptionSettings configuration) : IBackupManager
{
    private const int FormatVersion = 1;
    private const int ChunkSize = 1024 * 1024;
    private const int TagSize = 16;
    private const int MaxHeaderBytes = 16 * 1024;
    private const int MaxManifestBytes = 1024 * 1024;
    private const long DefaultMaxBytes = 10L * 1024 * 1024 * 1024;
    private const long HardMaxBytes = 100L * 1024 * 1024 * 1024;
    private const string Magic = "NOCIFCBK";
    private const string ScheduledPolicy = "Sunday at 00:00 America/Chicago; retain the latest three scheduled backups.";
    private const string ExpectedSchemaRevision = "20261125_0025";
    private static readonly byte[] MagicBytes = Encoding.ASCII.GetBytes(Magic);
    private static readonly Regex BackupNamePattern = new(
        @"^noc-ifc-(manual|pre-restore|scheduled)-(\d{8}T\d{6}Z)-([0-9a-f]{32})\.nocbackup$",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex StagedNamePattern = new(
        @"^stage-([0-9a-f]{32})\.nocbackup$",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex KeyIdPattern = new(
        @"^[A-Za-z0-9_.-]{1,64}$",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex Sha256Pattern = new(
        @"^[0-9a-f]{64}$",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public BackupStatus GetStatus() => new(TryGetEncryptionKeys(out _), GetMaxBytes(), ScheduledPolicy);

    public BackupEntry CreateBackup(string kind, string? reason = null, string? createdBy = null)
    {
        if (kind is not ("manual" or "scheduled"))
        {
            throw new BackupException("Backup kind must be 'manual' or 'scheduled'.");
        }
        var keys = GetEncryptionKeys();
        var maxBytes = GetMaxBytes();
        var root = EnsureDirectory(BackupDirectory());
        using var backupLock = AcquireLock(root);
        using var workspace = TemporaryWorkspace.Create("noc-ifc-backup-");
        var snapshotPath = Path.Combine(workspace.Path, "database.sqlite");
        var database = CreateSqliteSnapshot(snapshotPath);
        var createdAt = DateTimeOffset.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);
        var category = reason == "pre-restore safety snapshot" ? "pre-restore" : kind;
        var manifest = new BackupManifest(
            FormatVersion,
            createdAt,
            kind,
            category,
            Truncate(reason, 200),
            Truncate(createdBy, 128),
            new BackupFileManifest("ok", database.Tables, database.TableCount,
                database.SizeBytes, database.Sha256, "database.sqlite"),
            null);
        var archivePath = Path.Combine(workspace.Path, "payload.zip");
        CreateArchive(snapshotPath, archivePath, manifest);
        if (new FileInfo(archivePath).Length > maxBytes)
        {
            throw new BackupException("The full backup archive exceeds BACKUP_MAX_BYTES.");
        }

        var backupId = Guid.NewGuid().ToString("N");
        var filename = BackupFilename(category, createdAt, backupId);
        var finalPath = Path.Combine(root, filename);
        var partialPath = Path.Combine(root, $".{filename}.{Guid.NewGuid():N}.part");
        try
        {
            var encryptedSize = EncryptFile(archivePath, partialPath, maxBytes, keys);
            File.Move(partialPath, finalPath);
            SetPrivateFile(finalPath);
            if (kind == "scheduled") PruneScheduled(root, 3);
            return new BackupEntry(
                filename, filename, category, createdAt, new FileInfo(finalPath).Length,
                database.TableCount, false, manifest.Reason, encryptedSize);
        }
        finally
        {
            File.Delete(partialPath);
        }
    }

    public IReadOnlyList<BackupEntry> ListBackups()
    {
        var root = EnsureDirectory(BackupDirectory());
        return Directory.EnumerateFiles(root, "noc-ifc-*.nocbackup", SearchOption.TopDirectoryOnly)
            .Select(path => TryBackupRecord(path))
            .Where(record => record is not null)
            .Cast<BackupEntry>()
            .OrderByDescending(record => record.CreatedAt, StringComparer.Ordinal)
            .ToArray();
    }

    public FileStream OpenBackupRead(string backupId)
    {
        var path = GetBackupPath(backupId);
        return new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1024 * 1024, FileOptions.SequentialScan);
    }

    public void DeleteBackup(string backupId)
    {
        var path = GetBackupPath(backupId);
        var kind = BackupNamePattern.Match(Path.GetFileName(path)).Groups[1].Value;
        if (kind == "scheduled")
        {
            throw new BackupException("Scheduled backups are managed by the three-backup retention policy.");
        }
        File.Delete(path);
    }

    public StagedBackupEntry StageUpload(Stream source)
    {
        ArgumentNullException.ThrowIfNull(source);
        _ = GetEncryptionKeys();
        var maxBytes = GetMaxBytes();
        var root = EnsureDirectory(Path.Combine(BackupDirectory(), "staged"));
        using var backupLock = AcquireLock(BackupDirectory());
        var temporary = Path.Combine(root, $".upload-{Guid.NewGuid():N}.part");
        try
        {
            long size = 0;
            using (var output = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1024 * 1024, FileOptions.WriteThrough))
            {
                SetPrivateFile(temporary);
                var buffer = new byte[1024 * 1024];
                while (true)
                {
                    var read = source.Read(buffer, 0, buffer.Length);
                    if (read == 0) break;
                    size += read;
                    if (size > maxBytes) throw new BackupException("The uploaded backup exceeds BACKUP_MAX_BYTES.");
                    output.Write(buffer, 0, read);
                }
                output.Flush(true);
            }
            if (size == 0) throw new BackupException("The uploaded backup is empty.");
            using var validation = ValidatePackage(temporary, maxBytes);
            EnsureCurrentSchema(validation.DatabasePath);
            var stageId = $"stage-{Guid.NewGuid():N}.nocbackup";
            var stagedPath = Path.Combine(root, stageId);
            File.Move(temporary, stagedPath);
            SetPrivateFile(stagedPath);
            return new StagedBackupEntry(
                stageId,
                DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture),
                size,
                validation.Summary.TableCount,
                validation.Summary.ModelIncluded);
        }
        finally
        {
            File.Delete(temporary);
        }
    }

    public IReadOnlyList<StagedBackupEntry> ListStagedBackups()
    {
        var directory = EnsureDirectory(Path.Combine(BackupDirectory(), "staged"));
        return Directory.EnumerateFiles(directory, "stage-*.nocbackup", SearchOption.TopDirectoryOnly)
            .Select(path =>
            {
                if (!IsRegularFile(path) || !StagedNamePattern.IsMatch(Path.GetFileName(path))) return null;
                var info = new FileInfo(path);
                return new StagedBackupEntry(
                    info.Name,
                    info.LastWriteTimeUtc.ToString("O", CultureInfo.InvariantCulture),
                    info.Length);
            })
            .Where(entry => entry is not null)
            .Cast<StagedBackupEntry>()
            .OrderByDescending(entry => entry.CreatedAt, StringComparer.Ordinal)
            .ToArray();
    }

    public void DeleteStagedBackup(string stageId) => File.Delete(GetStagedBackupPath(stageId));

    public BackupValidationResult ValidateStagedBackup(string stageId)
    {
        using var package = ValidatePackage(GetStagedBackupPath(stageId), GetMaxBytes());
        return package.Summary;
    }

    public BackupRestoreResult RestoreStagedBackup(string stageId, bool maintenanceConfirmed)
    {
        if (!maintenanceConfirmed)
        {
            throw new BackupException("Restore requires maintenance mode with database writers stopped.");
        }
        var maxBytes = GetMaxBytes();
        var stagedPath = GetStagedBackupPath(stageId);
        using var package = ValidatePackage(stagedPath, maxBytes);
        EnsureCurrentSchema(package.DatabasePath);
        var invalidated = InvalidateRestoredCredentials(package.DatabasePath);
        VerifyDatabase(package.DatabasePath);

        var livePath = connections.DatabasePath;
        var parent = Path.GetDirectoryName(livePath)!;
        EnsureDirectory(parent);
        BackupEntry? safety = null;
        var hadDatabase = File.Exists(livePath);
        if (hadDatabase)
        {
            safety = CreateBackup("manual", "pre-restore safety snapshot", "ui-restore");
        }

        using var backupLock = AcquireLock(EnsureDirectory(BackupDirectory()));
        var rollbackPath = Path.Combine(package.Workspace.Path, "rollback.sqlite");
        if (hadDatabase) CreateSqliteSnapshot(rollbackPath, livePath);
        string? newDatabase = null;
        string? rollback = null;
        var touched = false;
        try
        {
            newDatabase = CopyToTemporarySibling(package.DatabasePath, livePath, ".restore-tmp");
            rollback = hadDatabase ? CopyToTemporarySibling(rollbackPath, livePath, ".rollback-tmp") : null;
            touched = true;
            RemoveSidecars(livePath);
            File.Move(newDatabase, livePath, true);
        }
        catch (Exception exception)
        {
            if (touched)
            {
                RemoveSidecars(livePath);
                if (rollback is not null && File.Exists(rollback)) File.Move(rollback, livePath, true);
                else File.Delete(livePath);
            }
            throw new BackupException(touched
                ? "Restore failed while installing the database; the prior database was rolled back."
                : "Restore could not prepare the replacement database; the current database was preserved.", exception);
        }
        finally
        {
            if (newDatabase is not null) File.Delete(newDatabase);
            if (rollback is not null) File.Delete(rollback);
        }

        var stagedCleared = ClearStagedBackups();
        return new BackupRestoreResult(
            "restored", package.Manifest.CreatedAt, package.Summary.TableCount, false, invalidated,
            safety?.Filename, stagedCleared);
    }

    public int ClearStagedBackups()
    {
        var directory = EnsureDirectory(Path.Combine(BackupDirectory(), "staged"));
        var count = 0;
        foreach (var path in Directory.EnumerateFiles(directory, "stage-*.nocbackup", SearchOption.TopDirectoryOnly))
        {
            if (!IsRegularFile(path) || !StagedNamePattern.IsMatch(Path.GetFileName(path))) continue;
            File.Delete(path);
            count++;
        }
        return count;
    }

    private long EncryptFile(string sourcePath, string destinationPath, long maxBytes, EncryptionKeySet keySet)
    {
        var prefix = RandomNumberGenerator.GetBytes(8);
        var header = new BackupHeader(FormatVersion, "AES-256-GCM", keySet.ActiveKeyId, Convert.ToHexString(prefix).ToLowerInvariant(), ChunkSize);
        var headerBytes = JsonSerializer.SerializeToUtf8Bytes(header, JsonOptions);
        if (headerBytes.Length is < 1 or > MaxHeaderBytes) throw new BackupException("The encrypted backup header is invalid.");
        var lengthBytes = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(lengthBytes, (uint)headerBytes.Length);
        var frame = new byte[MagicBytes.Length + lengthBytes.Length + headerBytes.Length];
        MagicBytes.CopyTo(frame, 0);
        lengthBytes.CopyTo(frame, MagicBytes.Length);
        headerBytes.CopyTo(frame, MagicBytes.Length + lengthBytes.Length);
        var key = keySet.Keys[keySet.ActiveKeyId];
        using var aes = new AesGcm(key, TagSize);
        using var input = File.OpenRead(sourcePath);
        using var output = new FileStream(destinationPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, ChunkSize, FileOptions.WriteThrough);
        SetPrivateFile(destinationPath);
        output.Write(frame);
        var buffer = new byte[ChunkSize];
        ulong index = 0;
        long plainSize = 0;
        while (true)
        {
            var read = input.Read(buffer, 0, buffer.Length);
            if (read == 0) break;
            plainSize += read;
            if (plainSize > maxBytes) throw new BackupException("The unencrypted backup archive exceeds BACKUP_MAX_BYTES.");
            var cipher = new byte[read];
            var tag = new byte[TagSize];
            aes.Encrypt(Nonce(prefix, index), buffer.AsSpan(0, read), cipher, tag, RecordAad(frame, 1, index));
            WriteRecord(output, 1, cipher, tag);
            index++;
            if (output.Position > maxBytes) throw new BackupException("The encrypted backup exceeds BACKUP_MAX_BYTES.");
        }
        var finalTag = new byte[TagSize];
        aes.Encrypt(Nonce(prefix, index), ReadOnlySpan<byte>.Empty, Span<byte>.Empty, finalTag,
            RecordAad(frame, 2, index));
        WriteRecord(output, 2, [], finalTag);
        output.Flush(true);
        if (output.Length > maxBytes) throw new BackupException("The encrypted backup exceeds BACKUP_MAX_BYTES.");
        return output.Length;
    }

    private string DecryptFile(string sourcePath, string destinationPath, long maxBytes)
    {
        var info = new FileInfo(sourcePath);
        if (info.Length <= 0 || info.Length > maxBytes) throw new BackupException("The encrypted backup is empty or exceeds BACKUP_MAX_BYTES.");
        var keySet = GetEncryptionKeys();
        Directory.CreateDirectory(Path.GetDirectoryName(destinationPath)!);
        try
        {
            using var input = File.OpenRead(sourcePath);
            if (!ReadExact(input, MagicBytes.Length).SequenceEqual(MagicBytes))
            {
                throw new BackupException("This is not a NOC Fusion encrypted backup.");
            }
            var lengthBytes = ReadExact(input, 4);
            var headerLength = BinaryPrimitives.ReadUInt32BigEndian(lengthBytes);
            if (headerLength is 0 or > MaxHeaderBytes) throw new BackupException("The encrypted backup header is invalid.");
            var headerBytes = ReadExact(input, (int)headerLength);
            var frame = new byte[MagicBytes.Length + lengthBytes.Length + headerBytes.Length];
            MagicBytes.CopyTo(frame, 0);
            lengthBytes.CopyTo(frame, MagicBytes.Length);
            headerBytes.CopyTo(frame, MagicBytes.Length + lengthBytes.Length);
            var header = JsonSerializer.Deserialize<BackupHeader>(headerBytes)
                ?? throw new BackupException("The encrypted backup header is invalid.");
            if (header.FormatVersion != FormatVersion) throw new BackupException("This encrypted backup format version is not supported.");
            if (header.Algorithm != "AES-256-GCM") throw new BackupException("The encrypted backup algorithm is not supported.");
            if (!keySet.Keys.TryGetValue(header.KeyId, out var key))
            {
                throw new BackupException("The encryption key required by this backup is not configured.");
            }
            byte[] prefix;
            try { prefix = Convert.FromHexString(header.NoncePrefix); }
            catch (FormatException exception) { throw new BackupException("The encrypted backup nonce is invalid.", exception); }
            if (prefix.Length != 8 || header.ChunkSize is < 64 * 1024 or > 8 * 1024 * 1024)
            {
                throw new BackupException("The encrypted backup header is invalid.");
            }

            using var aes = new AesGcm(key, TagSize);
            using var output = new FileStream(destinationPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, ChunkSize, FileOptions.WriteThrough);
            SetPrivateFile(destinationPath);
            long plainSize = 0;
            ulong index = 0;
            while (true)
            {
                var recordType = input.ReadByte();
                if (recordType < 0) throw new BackupException("The encrypted backup is truncated.");
                var recordSize = BinaryPrimitives.ReadUInt32BigEndian(ReadExact(input, 4));
                if (recordType == 1)
                {
                    if (recordSize <= TagSize || recordSize > header.ChunkSize + TagSize)
                    {
                        throw new BackupException("The encrypted backup contains an invalid data chunk.");
                    }
                    var record = ReadExact(input, checked((int)recordSize));
                    var cipherLength = record.Length - TagSize;
                    var plaintext = new byte[cipherLength];
                    aes.Decrypt(Nonce(prefix, index), record.AsSpan(0, cipherLength), record.AsSpan(cipherLength),
                        plaintext, RecordAad(frame, 1, index));
                    plainSize += plaintext.Length;
                    if (plainSize > maxBytes) throw new BackupException("The decrypted backup exceeds BACKUP_MAX_BYTES.");
                    output.Write(plaintext);
                    index++;
                    continue;
                }
                if (recordType != 2 || recordSize != TagSize)
                {
                    throw new BackupException("The encrypted backup contains an invalid final record.");
                }
                var finalTag = ReadExact(input, TagSize);
                aes.Decrypt(Nonce(prefix, index), ReadOnlySpan<byte>.Empty, finalTag, Span<byte>.Empty,
                    RecordAad(frame, 2, index));
                if (input.ReadByte() != -1) throw new BackupException("The encrypted backup has unexpected trailing data.");
                output.Flush(true);
                break;
            }
            return header.KeyId;
        }
        catch (CryptographicException exception)
        {
            File.Delete(destinationPath);
            throw new BackupException("Backup authentication failed; the file or encryption key is invalid.", exception);
        }
        catch
        {
            File.Delete(destinationPath);
            throw;
        }
    }

    private (long SizeBytes, string Sha256, int TableCount, string[] Tables) CreateSqliteSnapshot(string destinationPath, string? sourcePath = null)
    {
        var database = sourcePath ?? connections.DatabasePath;
        if (!File.Exists(database)) throw new BackupException("SQLite database file does not exist.");
        var connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = destinationPath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Pooling = false,
        }.ToString();
        try
        {
            using var source = sourcePath is null ? connections.Create() : new SqliteConnection(
                new SqliteConnectionStringBuilder { DataSource = database, Mode = SqliteOpenMode.ReadWrite, Pooling = false }.ToString());
            using var destination = new SqliteConnection(connectionString);
            source.Open();
            destination.Open();
            using (var timeout = source.CreateCommand())
            {
                timeout.CommandText = "PRAGMA busy_timeout=60000";
                timeout.ExecuteNonQuery();
            }
            source.BackupDatabase(destination);
            destination.Close();
        }
        catch (SqliteException exception)
        {
            File.Delete(destinationPath);
            throw new BackupException("SQLite could not create a consistent online database snapshot.", exception);
        }
        SetPrivateFile(destinationPath);
        return ReadDatabaseMetadata(destinationPath);
    }

    private static (long SizeBytes, string Sha256, int TableCount, string[] Tables) ReadDatabaseMetadata(string path)
    {
        var connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = SqliteOpenMode.ReadOnly,
            Pooling = false,
        }.ToString();
        using var connection = new SqliteConnection(connectionString);
        try
        {
            connection.Open();
            using var integrity = connection.CreateCommand();
            integrity.CommandText = "PRAGMA integrity_check";
            if (!string.Equals((string?)integrity.ExecuteScalar(), "ok", StringComparison.Ordinal))
            {
                throw new BackupException("The SQLite database failed PRAGMA integrity_check.");
            }
            using var tablesCommand = connection.CreateCommand();
            tablesCommand.CommandText = "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name";
            using var reader = tablesCommand.ExecuteReader();
            var tables = new List<string>();
            while (reader.Read()) tables.Add(reader.GetString(0));
            var info = new FileInfo(path);
            return (info.Length, Sha256(path), tables.Count, tables.ToArray());
        }
        catch (SqliteException exception)
        {
            throw new BackupException("The SQLite database could not be read or verified.", exception);
        }
    }

    private ValidatedPackage ValidatePackage(string packagePath, long maxBytes)
    {
        var encrypted = new FileInfo(packagePath);
        if (!encrypted.Exists || encrypted.Length <= 0 || encrypted.Length > maxBytes)
        {
            throw new BackupException("The encrypted backup is empty or exceeds BACKUP_MAX_BYTES.");
        }
        var workspace = TemporaryWorkspace.Create("noc-ifc-validate-");
        try
        {
            var zipPath = Path.Combine(workspace.Path, "payload.zip");
            var keyId = DecryptFile(packagePath, zipPath, maxBytes);
            using var archiveStream = File.OpenRead(zipPath);
            using var archive = new ZipArchive(archiveStream, ZipArchiveMode.Read);
            var entries = archive.Entries;
            var names = entries.Select(entry => entry.FullName).ToArray();
            if (names.Length != names.Distinct(StringComparer.Ordinal).Count()
                || !names.Contains("manifest.json", StringComparer.Ordinal))
            {
                throw new BackupException("The backup archive has duplicate entries or no manifest.");
            }
            if (entries.Any(entry => entry.FullName.EndsWith('/') || entry.FullName.StartsWith('/')
                    || entry.FullName.StartsWith('\\') || entry.FullName.Contains('\\')
                    || entry.FullName.Split('/').Contains("..", StringComparer.Ordinal)
                    || entry.Length != entry.CompressedLength || entry.Length > maxBytes))
            {
                throw new BackupException("The backup archive contains an unsafe or unsupported entry.");
            }
            var manifestEntry = archive.GetEntry("manifest.json")!;
            if (manifestEntry.Length > MaxManifestBytes) throw new BackupException("The backup manifest is too large.");
            var manifest = ParseManifest(ReadEntryBounded(manifestEntry, MaxManifestBytes), names, maxBytes);
            var databasePath = Path.Combine(workspace.Path, "database.sqlite");
            CopyEntryVerified(archive.GetEntry("database.sqlite")!, databasePath,
                manifest.Database!.SizeBytes, manifest.Database.Sha256!, maxBytes);
            if (manifest.Model is not null)
            {
                var modelPath = Path.Combine(workspace.Path, "legacy-model.bin");
                CopyEntryVerified(archive.GetEntry("model/ml_model.pkl")!, modelPath,
                    manifest.Model.SizeBytes, manifest.Model.Sha256!, maxBytes);
                File.Delete(modelPath);
            }
            var dbMetadata = ReadDatabaseMetadata(databasePath);
            if (!dbMetadata.Tables.SequenceEqual(manifest.Database.Tables!, StringComparer.Ordinal))
            {
                throw new BackupException("The SQLite table inventory does not match the backup manifest.");
            }
            return new ValidatedPackage(workspace, databasePath, manifest,
                new BackupValidationResult(keyId, manifest.Database.TableCount, manifest.Database.SizeBytes,
                    manifest.Model is not null, manifest.Reason, encrypted.Length));
        }
        catch (InvalidDataException exception)
        {
            workspace.Dispose();
            throw new BackupException("The encrypted backup archive is corrupt or unsupported.", exception);
        }
        catch
        {
            workspace.Dispose();
            throw;
        }
    }

    private static BackupManifest ParseManifest(byte[] bytes, string[] names, long maxBytes)
    {
        BackupManifest manifest;
        try
        {
            manifest = JsonSerializer.Deserialize<BackupManifest>(bytes)
                ?? throw new BackupException("The backup manifest is corrupt.");
        }
        catch (JsonException exception)
        {
            throw new BackupException("The backup manifest is corrupt.", exception);
        }
        if (manifest.FormatVersion != FormatVersion) throw new BackupException("This backup manifest version is not supported.");
        if (manifest.BackupKind is not ("manual" or "scheduled")) throw new BackupException("The backup kind is invalid.");
        if (!DateTimeOffset.TryParse(manifest.CreatedAt, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out _))
        {
            throw new BackupException("The backup manifest creation timestamp is invalid.");
        }
        var database = manifest.Database;
        if (database is null || database.File != "database.sqlite" || database.Integrity != "ok"
            || !ValidFileMetadata(database.SizeBytes, database.Sha256, maxBytes)
            || database.Tables is null || database.TableCount != database.Tables.Length)
        {
            throw new BackupException("The backup manifest database metadata is invalid.");
        }
        var category = manifest.BackupCategory ?? manifest.BackupKind;
        if (category is not ("manual" or "pre-restore" or "scheduled"))
        {
            throw new BackupException("The backup manifest category is invalid.");
        }
        if (category == "pre-restore" && manifest.BackupKind != "manual")
        {
            throw new BackupException("A pre-restore safety package must have manual retention.");
        }
        var expectedNames = new HashSet<string>(["manifest.json", "database.sqlite"], StringComparer.Ordinal);
        if (manifest.Model is { } model)
        {
            if (model.File != "model/ml_model.pkl" || !ValidFileMetadata(model.SizeBytes, model.Sha256, maxBytes))
            {
                throw new BackupException("The backup manifest model payload is invalid.");
            }
            expectedNames.Add(model.File);
        }
        if (!expectedNames.SetEquals(names)) throw new BackupException("The backup archive contains missing or unexpected files.");
        var payload = database.SizeBytes + (manifest.Model?.SizeBytes ?? 0);
        if (payload > maxBytes) throw new BackupException("The backup payload exceeds BACKUP_MAX_BYTES.");
        return manifest with { BackupCategory = category };
    }

    private static bool ValidFileMetadata(long size, string? digest, long maxBytes) =>
        size > 0 && size <= maxBytes && digest is not null && Sha256Pattern.IsMatch(digest);

    private static byte[] ReadEntryBounded(ZipArchiveEntry entry, int maximum)
    {
        if (entry.Length > maximum) throw new BackupException("The backup manifest is too large.");
        using var source = entry.Open();
        using var buffer = new MemoryStream();
        var bytes = new byte[64 * 1024];
        while (true)
        {
            var read = source.Read(bytes, 0, bytes.Length);
            if (read == 0) break;
            if (buffer.Length + read > maximum) throw new BackupException("The backup manifest is too large.");
            buffer.Write(bytes, 0, read);
        }
        return buffer.ToArray();
    }

    private static void CopyEntryVerified(
        ZipArchiveEntry entry,
        string destinationPath,
        long expectedSize,
        string expectedDigest,
        long maxBytes)
    {
        if (entry.Length != expectedSize || expectedSize > maxBytes)
        {
            throw new BackupException($"The backup payload size is invalid for {entry.FullName}.");
        }
        using var source = entry.Open();
        using var output = new FileStream(destinationPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1024 * 1024, FileOptions.WriteThrough);
        SetPrivateFile(destinationPath);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[1024 * 1024];
        long size = 0;
        while (true)
        {
            var read = source.Read(buffer, 0, buffer.Length);
            if (read == 0) break;
            size += read;
            if (size > expectedSize || size > maxBytes)
            {
                throw new BackupException($"The backup payload size is invalid for {entry.FullName}.");
            }
            hash.AppendData(buffer, 0, read);
            output.Write(buffer, 0, read);
        }
        output.Flush(true);
        var digest = Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
        if (size != expectedSize || digest != expectedDigest)
        {
            File.Delete(destinationPath);
            throw new BackupException($"The backup checksum does not match for {entry.FullName}.");
        }
    }

    private static void CreateArchive(string databasePath, string archivePath, BackupManifest manifest)
    {
        using var output = new FileStream(archivePath, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None);
        using (var archive = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: true))
        {
            var databaseEntry = archive.CreateEntry("database.sqlite", CompressionLevel.NoCompression);
            databaseEntry.ExternalAttributes = 0x180 << 16;
            using (var target = databaseEntry.Open())
            using (var source = File.OpenRead(databasePath)) source.CopyTo(target);
            var manifestEntry = archive.CreateEntry("manifest.json", CompressionLevel.NoCompression);
            manifestEntry.ExternalAttributes = 0x180 << 16;
            using var manifestStream = manifestEntry.Open();
            JsonSerializer.Serialize(manifestStream, manifest, JsonOptions);
        }
        output.Flush(true);
    }

    private static IReadOnlyDictionary<string, int> InvalidateRestoredCredentials(string databasePath)
    {
        var connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = databasePath,
            Mode = SqliteOpenMode.ReadWrite,
            Pooling = false,
        }.ToString();
        using var connection = new SqliteConnection(connectionString);
        connection.Open();
        using var transaction = connection.BeginTransaction();
        var now = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture);
        var counts = new Dictionary<string, int>(StringComparer.Ordinal);
        counts["legacy_sessions"] = ExecuteCount(connection, transaction,
            "UPDATE users SET session_token = NULL WHERE session_token IS NOT NULL");
        counts["sessions"] = ExecuteCount(connection, transaction, "DELETE FROM user_sessions");
        counts["registration_invites"] = ExecuteCount(connection, transaction,
            "UPDATE registration_invites SET revoked_at = $now WHERE revoked_at IS NULL AND used_at IS NULL", ("$now", now));
        counts["password_reset_tokens"] = ExecuteCount(connection, transaction,
            "UPDATE password_reset_tokens SET used_at = $now WHERE used_at IS NULL", ("$now", now));
        counts["recovery_email_tokens"] = ExecuteCount(connection, transaction,
            "UPDATE email_change_requests SET status = 'invalidated', verification_token_hash = NULL, verification_expires_at = NULL WHERE status = 'pending_verification' AND verification_token_hash IS NOT NULL");
        transaction.Commit();
        VerifyDatabase(databasePath);
        return counts;
    }

    private static int ExecuteCount(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string sql,
        params (string Name, object Value)[] parameters)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        foreach (var (name, value) in parameters) command.Parameters.AddWithValue(name, value);
        return command.ExecuteNonQuery();
    }

    private void EnsureCurrentSchema(string databasePath)
    {
        // shortcut: C# restores current-head snapshots; use the host offline tool to upgrade older packages before staging.
        var connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = databasePath,
            Mode = SqliteOpenMode.ReadOnly,
            Pooling = false,
        }.ToString();
        using var connection = new SqliteConnection(connectionString);
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT version_num FROM alembic_version";
        var revision = command.ExecuteScalar() as string;
        if (revision != ExpectedSchemaRevision)
        {
            throw new BackupException("This C# restore requires schema revision 20261125_0025; run tools/offline-python/upgrade_backup.py before staging this package.");
        }
    }

    private static void VerifyDatabase(string path) => _ = ReadDatabaseMetadata(path);

    private static void RemoveSidecars(string databasePath)
    {
        foreach (var suffix in new[] { "-wal", "-shm", "-journal" }) File.Delete(databasePath + suffix);
    }

    private static string? Truncate(string? value, int maximum) =>
        string.IsNullOrWhiteSpace(value) ? null : value[..Math.Min(value.Length, maximum)];

    private static string BackupFilename(string category, string createdAt, string id)
    {
        var timestamp = DateTimeOffset.Parse(createdAt, CultureInfo.InvariantCulture).UtcDateTime
            .ToString("yyyyMMdd'T'HHmmss'Z'", CultureInfo.InvariantCulture);
        return $"noc-ifc-{category}-{timestamp}-{id}.nocbackup";
    }

    private static void WriteRecord(Stream output, byte recordType, byte[] ciphertext, byte[] tag)
    {
        output.WriteByte(recordType);
        Span<byte> length = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)(ciphertext.Length + tag.Length)));
        output.Write(length);
        output.Write(ciphertext);
        output.Write(tag);
    }

    private static byte[] Nonce(byte[] prefix, ulong index)
    {
        if (index >= 1UL << 32) throw new BackupException("The backup exceeds the supported encrypted chunk count.");
        var nonce = new byte[12];
        prefix.CopyTo(nonce, 0);
        BinaryPrimitives.WriteUInt32BigEndian(nonce.AsSpan(8), (uint)index);
        return nonce;
    }

    private static byte[] RecordAad(byte[] headerFrame, byte recordType, ulong index)
    {
        var aad = new byte[headerFrame.Length + 9];
        headerFrame.CopyTo(aad, 0);
        aad[headerFrame.Length] = recordType;
        BinaryPrimitives.WriteUInt64BigEndian(aad.AsSpan(headerFrame.Length + 1), index);
        return aad;
    }

    private static byte[] ReadExact(Stream source, int count)
    {
        var result = new byte[count];
        var readTotal = 0;
        while (readTotal < count)
        {
            var read = source.Read(result, readTotal, count - readTotal);
            if (read == 0) throw new BackupException("The encrypted backup is truncated.");
            readTotal += read;
        }
        return result;
    }

    private long GetMaxBytes()
    {
        var raw = configuration.MaxBytes;
        if (string.IsNullOrWhiteSpace(raw)) return DefaultMaxBytes;
        if (!long.TryParse(raw, NumberStyles.None, CultureInfo.InvariantCulture, out var bytes)
            || bytes <= 0 || bytes > HardMaxBytes)
        {
            throw new BackupException("BACKUP_MAX_BYTES must be a positive integer no larger than 107374182400.");
        }
        return bytes;
    }

    private EncryptionKeySet GetEncryptionKeys()
    {
        var raw = configuration.KeysJson;
        var activeId = string.IsNullOrWhiteSpace(configuration.ActiveKeyId) ? "primary" : configuration.ActiveKeyId;
        if (string.IsNullOrWhiteSpace(raw))
        {
            throw new BackupException("Encrypted backups are unavailable until BACKUP_ENCRYPTION_KEYS is configured.");
        }
        if (!KeyIdPattern.IsMatch(activeId))
        {
            throw new BackupException("BACKUP_ENCRYPTION_ACTIVE_KEY_ID must be a valid backup key ID.");
        }
        Dictionary<string, string> parsed;
        try
        {
            parsed = JsonSerializer.Deserialize<Dictionary<string, string>>(raw)
                ?? throw new BackupException("BACKUP_ENCRYPTION_KEYS must be a JSON object.");
        }
        catch (JsonException exception)
        {
            throw new BackupException("BACKUP_ENCRYPTION_KEYS must be a JSON object of key IDs and hex keys.", exception);
        }
        if (parsed.Count == 0) throw new BackupException("BACKUP_ENCRYPTION_KEYS must be a non-empty JSON object.");
        var keys = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        foreach (var (keyId, hex) in parsed)
        {
            if (!KeyIdPattern.IsMatch(keyId) || hex is null || !Regex.IsMatch(hex, "^[0-9a-fA-F]{64}$", RegexOptions.CultureInvariant))
            {
                throw new BackupException("Backup encryption key IDs and values must use valid IDs and 64-character hex keys.");
            }
            keys[keyId] = Convert.FromHexString(hex);
        }
        if (!keys.ContainsKey(activeId))
        {
            throw new BackupException("The active backup encryption key ID is not present in BACKUP_ENCRYPTION_KEYS.");
        }
        return new EncryptionKeySet(keys, activeId);
    }

    private bool TryGetEncryptionKeys(out EncryptionKeySet? keySet)
    {
        try
        {
            keySet = GetEncryptionKeys();
            return true;
        }
        catch (BackupException)
        {
            keySet = null;
            return false;
        }
    }

    private string BackupDirectory() =>
        Path.Combine(Path.GetDirectoryName(connections.DatabasePath)!, "backups");

    private string EnsureDirectory(string path)
    {
        Directory.CreateDirectory(path);
        SetPrivateDirectory(path);
        return Path.GetFullPath(path);
    }

    private string GetBackupPath(string backupId)
    {
        if (!BackupNamePattern.IsMatch(backupId)) throw new BackupException("Backup not found.");
        var path = Path.Combine(EnsureDirectory(BackupDirectory()), backupId);
        if (!IsRegularFile(path)) throw new BackupException("Backup not found.");
        return path;
    }

    private string GetStagedBackupPath(string stageId)
    {
        if (!StagedNamePattern.IsMatch(stageId)) throw new BackupException("Staged backup not found.");
        var path = Path.Combine(EnsureDirectory(Path.Combine(BackupDirectory(), "staged")), stageId);
        if (!IsRegularFile(path)) throw new BackupException("Staged backup not found.");
        return path;
    }

    private static FileStream AcquireLock(string root)
    {
        var path = Path.Combine(root, ".backup.lock");
        try
        {
            var stream = new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            SetPrivateFile(path);
            return stream;
        }
        catch (IOException exception)
        {
            throw new BackupException("Another backup operation is in progress.", exception);
        }
    }

    private static BackupEntry? TryBackupRecord(string path)
    {
        var filename = Path.GetFileName(path);
        var match = BackupNamePattern.Match(filename);
        if (!match.Success || !IsRegularFile(path)) return null;
        var createdAt = DateTime.ParseExact(match.Groups[2].Value, "yyyyMMdd'T'HHmmss'Z'", CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal)
            .ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);
        return new BackupEntry(filename, filename, match.Groups[1].Value, createdAt, new FileInfo(path).Length);
    }

    private static bool IsRegularFile(string path)
    {
        try
        {
            var attributes = File.GetAttributes(path);
            return (attributes & FileAttributes.Directory) == 0 && (attributes & FileAttributes.ReparsePoint) == 0;
        }
        catch (FileNotFoundException) { return false; }
        catch (DirectoryNotFoundException) { return false; }
    }

    private static void PruneScheduled(string root, int keep)
    {
        var scheduled = Directory.EnumerateFiles(root, "noc-ifc-scheduled-*.nocbackup", SearchOption.TopDirectoryOnly)
            .Where(path => BackupNamePattern.IsMatch(Path.GetFileName(path)) && IsRegularFile(path))
            .OrderByDescending(path => File.GetLastWriteTimeUtc(path)).ToArray();
        foreach (var path in scheduled.Skip(keep)) File.Delete(path);
    }

    private static void SetPrivateDirectory(string path)
    {
        if (OperatingSystem.IsWindows()) return;
        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
    }

    private static void SetPrivateFile(string path)
    {
        if (OperatingSystem.IsWindows()) return;
        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }

    private static string Sha256(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
    }

    private static string CopyToTemporarySibling(string sourcePath, string targetPath, string suffix)
    {
        var directory = Path.GetDirectoryName(targetPath)!;
        var temporary = Path.Combine(directory, $".{Path.GetFileName(targetPath)}.{Guid.NewGuid():N}{suffix}");
        try
        {
            using var source = File.OpenRead(sourcePath);
            using var target = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                1024 * 1024, FileOptions.WriteThrough);
            SetPrivateFile(temporary);
            source.CopyTo(target);
            target.Flush(true);
        }
        catch
        {
            File.Delete(temporary);
            throw;
        }
        return temporary;
    }

    private sealed record EncryptionKeySet(IReadOnlyDictionary<string, byte[]> Keys, string ActiveKeyId);
    private sealed record BackupHeader(
        [property: JsonPropertyName("format_version")] int FormatVersion,
        [property: JsonPropertyName("algorithm")] string Algorithm,
        [property: JsonPropertyName("key_id")] string KeyId,
        [property: JsonPropertyName("nonce_prefix")] string NoncePrefix,
        [property: JsonPropertyName("chunk_size")] int ChunkSize);
    private sealed record BackupFileManifest(
        [property: JsonPropertyName("integrity")] string Integrity,
        [property: JsonPropertyName("tables")] string[]? Tables,
        [property: JsonPropertyName("table_count")] int TableCount,
        [property: JsonPropertyName("size_bytes")] long SizeBytes,
        [property: JsonPropertyName("sha256")] string? Sha256,
        [property: JsonPropertyName("file")] string File);
    private sealed record BackupManifest(
        [property: JsonPropertyName("format_version")] int FormatVersion,
        [property: JsonPropertyName("created_at")] string CreatedAt,
        [property: JsonPropertyName("backup_kind")] string BackupKind,
        [property: JsonPropertyName("backup_category")] string? BackupCategory,
        [property: JsonPropertyName("reason")] string? Reason,
        [property: JsonPropertyName("created_by")] string? CreatedBy,
        [property: JsonPropertyName("database")] BackupFileManifest? Database,
        [property: JsonPropertyName("model")] BackupFileManifest? Model);

    private sealed class TemporaryWorkspace(string path) : IDisposable
    {
        public string Path { get; } = path;
        public static TemporaryWorkspace Create(string prefix) =>
            new(Directory.CreateTempSubdirectory(prefix).FullName);
        public void Dispose()
        {
            try { Directory.Delete(Path, true); }
            catch (DirectoryNotFoundException) { }
        }
    }

    private sealed class ValidatedPackage(
        TemporaryWorkspace workspace,
        string databasePath,
        BackupManifest manifest,
        BackupValidationResult summary) : IDisposable
    {
        public TemporaryWorkspace Workspace { get; } = workspace;
        public string DatabasePath { get; } = databasePath;
        public BackupManifest Manifest { get; } = manifest;
        public BackupValidationResult Summary { get; } = summary;
        public void Dispose() => Workspace.Dispose();
    }
}
