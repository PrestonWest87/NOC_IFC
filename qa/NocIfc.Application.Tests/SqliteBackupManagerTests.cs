using Microsoft.Data.Sqlite;
using NocIfc.Domain.BackupRestore;
using NocIfc.Infrastructure.BackupRestore;
using NocIfc.Infrastructure.Persistence.Sqlite;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class SqliteBackupManagerTests
{
    private const string CurrentSchema = "20261125_0025";
    private static readonly BackupEncryptionSettings Encryption = new(
        "{\"test-key\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}",
        "test-key",
        "10485760");

    [Fact]
    public void CreatesAndStagesAuthenticatedFullBackupAndRejectsTampering()
    {
        using var workspace = new TemporaryDirectory("nocifc-backup-");
        var databasePath = Path.Combine(workspace.Path, "database.sqlite");
        CreateDatabase(databasePath, includeRestoreTables: false);
        var manager = CreateManager(databasePath);

        var backup = manager.CreateBackup("manual", createdBy: "admin");
        Assert.Equal("manual", backup.Kind);
        Assert.True(backup.SizeBytes > 0);
        Assert.True(manager.GetStatus().EncryptionConfigured);
        using (var download = manager.OpenBackupRead(backup.Id))
        {
            var staged = manager.StageUpload(download);
            Assert.Equal(2, staged.TableCount);
            Assert.Equal(staged.StageId, Assert.Single(manager.ListStagedBackups()).StageId);
            Assert.Equal(2, manager.ValidateStagedBackup(staged.StageId).TableCount);
            manager.DeleteStagedBackup(staged.StageId);
        }

        var backupPath = Path.Combine(workspace.Path, "backups", backup.Filename);
        using (var tamper = new FileStream(backupPath, FileMode.Open, FileAccess.Write, FileShare.None))
        {
            tamper.Position = tamper.Length - 1;
            tamper.WriteByte(0x01);
        }
        using var corrupted = File.OpenRead(backupPath);
        Assert.Throws<BackupException>(() => manager.StageUpload(corrupted));
        Assert.Empty(manager.ListStagedBackups());
        manager.DeleteBackup(backup.Id);
        Assert.Empty(manager.ListBackups());
    }

    [Fact]
    public void RejectsOlderSchemaAtUploadWithOfflineUpgradeInstruction()
    {
        using var workspace = new TemporaryDirectory("nocifc-old-backup-");
        var databasePath = Path.Combine(workspace.Path, "database.sqlite");
        CreateDatabase(databasePath, includeRestoreTables: false, schemaRevision: "20261123_0023");
        var manager = CreateManager(databasePath);
        var backup = manager.CreateBackup("manual");

        using var package = manager.OpenBackupRead(backup.Id);
        var error = Assert.Throws<BackupException>(() => manager.StageUpload(package));

        Assert.Contains("upgrade_backup.py", error.Message);
        Assert.Empty(manager.ListStagedBackups());
    }

    [Fact]
    public void RestoreValidatesSchemaInvalidatesCredentialsAndCreatesSafetyBackup()
    {
        using var workspace = new TemporaryDirectory("nocifc-restore-");
        var databasePath = Path.Combine(workspace.Path, "database.sqlite");
        CreateDatabase(databasePath, includeRestoreTables: true);
        var manager = CreateManager(databasePath);
        var backup = manager.CreateBackup("manual", createdBy: "admin");
        using (var live = CreateConnection(databasePath))
        {
            using var update = live.CreateCommand();
            update.CommandText = "UPDATE application_data SET value = 'live version' WHERE id = 1";
            update.ExecuteNonQuery();
        }
        string stageId;
        using (var package = manager.OpenBackupRead(backup.Id)) stageId = manager.StageUpload(package).StageId;

        var result = manager.RestoreStagedBackup(stageId, maintenanceConfirmed: true);

        Assert.Equal("restored", result.Status);
        Assert.Equal(7, result.TableCount);
        Assert.False(result.ModelRestored);
        Assert.NotNull(result.PreRestoreBackup);
        Assert.Equal(1, result.StagedPackagesCleared);
        Assert.Empty(manager.ListStagedBackups());
        Assert.Equal("snapshot version", Scalar(databasePath, "SELECT value FROM application_data WHERE id = 1"));
        Assert.Null(Scalar(databasePath, "SELECT session_token FROM users WHERE id = 1"));
        Assert.Equal(0, Convert.ToInt32(Scalar(databasePath, "SELECT COUNT(*) FROM user_sessions")));
        Assert.NotNull(Scalar(databasePath, "SELECT revoked_at FROM registration_invites WHERE id = 1"));
        Assert.NotNull(Scalar(databasePath, "SELECT used_at FROM password_reset_tokens WHERE id = 1"));
        Assert.Equal("invalidated", Scalar(databasePath, "SELECT status FROM email_change_requests WHERE id = 1"));
        Assert.Contains(manager.ListBackups(), item => item.Kind == "pre-restore");
        Assert.Empty(Directory.EnumerateFiles(workspace.Path, "*.restore-tmp"));
        Assert.Empty(Directory.EnumerateFiles(workspace.Path, "*.rollback-tmp"));
    }

    private static SqliteBackupManager CreateManager(string databasePath) =>
        new(new SqliteConnectionFactory($"sqlite:///{databasePath}"), Encryption);

    private static void CreateDatabase(
        string path,
        bool includeRestoreTables,
        string schemaRevision = CurrentSchema)
    {
        using var connection = CreateConnection(path);
        using var command = connection.CreateCommand();
        command.CommandText = includeRestoreTables
            ? """
              CREATE TABLE alembic_version (version_num TEXT NOT NULL);
              INSERT INTO alembic_version VALUES ($revision);
              CREATE TABLE application_data (id INTEGER PRIMARY KEY, value TEXT);
              INSERT INTO application_data VALUES (1, 'snapshot version');
              CREATE TABLE users (id INTEGER PRIMARY KEY, session_token TEXT);
              INSERT INTO users VALUES (1, 'restored-session');
              CREATE TABLE user_sessions (id INTEGER PRIMARY KEY, token_hash TEXT);
              INSERT INTO user_sessions VALUES (1, 'hash');
              CREATE TABLE registration_invites (id INTEGER PRIMARY KEY, revoked_at DATETIME, used_at DATETIME);
              INSERT INTO registration_invites VALUES (1, NULL, NULL);
              CREATE TABLE password_reset_tokens (id INTEGER PRIMARY KEY, used_at DATETIME);
              INSERT INTO password_reset_tokens VALUES (1, NULL);
              CREATE TABLE email_change_requests (
                  id INTEGER PRIMARY KEY, status TEXT, verification_token_hash TEXT, verification_expires_at DATETIME
              );
              INSERT INTO email_change_requests VALUES (1, 'pending_verification', 'token', '2026-11-30 00:00:00');
              """
            : """
              CREATE TABLE alembic_version (version_num TEXT NOT NULL);
              INSERT INTO alembic_version VALUES ($revision);
              CREATE TABLE application_data (id INTEGER PRIMARY KEY, value TEXT);
              INSERT INTO application_data VALUES (1, 'snapshot version');
              """;
        command.Parameters.AddWithValue("$revision", schemaRevision);
        command.ExecuteNonQuery();
    }

    private static SqliteConnection CreateConnection(string path)
    {
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Pooling = false,
        }.ToString());
        connection.Open();
        return connection;
    }

    private static object? Scalar(string databasePath, string query)
    {
        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = databasePath,
            Mode = SqliteOpenMode.ReadWrite,
            Pooling = false,
        }.ToString());
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = query;
        var result = command.ExecuteScalar();
        return result is DBNull ? null : result;
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        public string Path { get; }

        public TemporaryDirectory(string prefix) => Path = Directory.CreateTempSubdirectory(prefix).FullName;

        public void Dispose() => Directory.Delete(Path, true);
    }
}
