using Microsoft.Data.Sqlite;

namespace NocIfc.Infrastructure.Persistence.Sqlite;

public sealed class SqliteConnectionFactory
{
    private readonly string _connectionString;
    public string DatabasePath { get; }

    public SqliteConnectionFactory(string databaseUrl)
    {
        const string prefix = "sqlite:///";
        if (!databaseUrl.StartsWith(prefix, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("DATABASE_URL must be an absolute SQLite URL.");
        }

        var dataSource = Uri.UnescapeDataString(databaseUrl[prefix.Length..]);
        if (!Path.IsPathRooted(dataSource))
        {
            throw new InvalidOperationException("DATABASE_URL must use an absolute SQLite path.");
        }

        DatabasePath = Path.GetFullPath(dataSource);
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = DatabasePath,
            Mode = SqliteOpenMode.ReadWrite,
            Pooling = false,
        }.ToString();
    }

    public SqliteConnection Create() => new(_connectionString);
}
