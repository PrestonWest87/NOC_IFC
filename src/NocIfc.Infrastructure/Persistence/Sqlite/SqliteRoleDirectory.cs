using NocIfc.Application.Abstractions.Identity;
using NocIfc.Domain.Identity;
using System.Text.Json;

namespace NocIfc.Infrastructure.Persistence.Sqlite;

public sealed class SqliteRoleDirectory(SqliteConnectionFactory connections) : IRoleDirectory, IRoleWriter
{
    public async Task<IReadOnlyList<RoleDefinition>> GetAllAsync(CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT id, name, allowed_pages, allowed_actions, allowed_site_types
            FROM roles
            ORDER BY id
            """;

        var roles = new List<RoleDefinition>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            roles.Add(new RoleDefinition(
                reader.GetInt32(0),
                reader.GetString(1),
                SqliteJson.ReadStringList(reader, 2),
                SqliteJson.ReadStringList(reader, 3),
                SqliteJson.ReadStringList(reader, 4)));
        }

        return roles;
    }

    public async Task<bool> CreateAsync(RoleDefinition role, CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO roles (name, allowed_pages, allowed_actions, allowed_site_types)
            SELECT $name, $pages, $actions, $site_types
            WHERE NOT EXISTS (SELECT 1 FROM roles WHERE lower(name) = lower($name))
            """;
        AddRoleParameters(command, role);
        return await command.ExecuteNonQueryAsync(cancellationToken) == 1;
    }

    public async Task<bool> UpdateAsync(RoleDefinition role, CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            UPDATE roles
            SET allowed_pages = $pages,
                allowed_actions = $actions,
                allowed_site_types = $site_types
            WHERE name = $name
            """;
        AddRoleParameters(command, role);
        return await command.ExecuteNonQueryAsync(cancellationToken) == 1;
    }

    private static void AddRoleParameters(Microsoft.Data.Sqlite.SqliteCommand command, RoleDefinition role)
    {
        command.Parameters.AddWithValue("$name", role.Name);
        command.Parameters.AddWithValue("$pages", JsonSerializer.Serialize(role.AllowedPages));
        command.Parameters.AddWithValue("$actions", JsonSerializer.Serialize(role.AllowedActions));
        command.Parameters.AddWithValue("$site_types", JsonSerializer.Serialize(role.AllowedSiteTypes));
    }
}
