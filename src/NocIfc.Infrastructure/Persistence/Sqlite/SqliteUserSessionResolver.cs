using System.Globalization;
using Microsoft.Data.Sqlite;
using NocIfc.Application.Abstractions.Identity;
using NocIfc.Application.Features.Identity;
using NocIfc.Domain.Identity;

namespace NocIfc.Infrastructure.Persistence.Sqlite;

public sealed class SqliteUserSessionResolver(SqliteConnectionFactory connections, SiteTypeQueries siteTypes) : IUserSessionResolver
{
    private const string UserQuery = """
        SELECT u.id, u.username, COALESCE(NULLIF(u.role, ''), 'analyst'), u.is_active,
               u.last_activity_at, r.allowed_pages, r.allowed_actions, r.allowed_site_types
        FROM users AS u
        LEFT JOIN roles AS r ON r.name = u.role
        WHERE u.is_active = 1
          AND (
            EXISTS (SELECT 1 FROM user_sessions AS s WHERE s.user_id = u.id AND s.token = $token)
            OR u.session_token = $token
          )
        LIMIT 1
        """;

    public async Task<AuthenticatedUser?> ResolveAsync(string token, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            return null;
        }

        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        AuthenticatedUser user;
        string? lastActivity;

        await using (var command = connection.CreateCommand())
        {
            command.CommandText = UserQuery;
            command.Parameters.AddWithValue("$token", token);
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken))
            {
                return null;
            }

            user = new AuthenticatedUser(
                reader.GetInt32(0),
                reader.GetString(1),
                reader.GetString(2),
                SqliteJson.ReadStringList(reader, 5),
                SqliteJson.ReadStringList(reader, 6),
                SqliteJson.ReadStringList(reader, 7));
            lastActivity = reader.IsDBNull(4)
                ? null
                : Convert.ToString(reader.GetValue(4), CultureInfo.InvariantCulture);
        }

        if (NeedsActivityRefresh(lastActivity))
        {
            await using var update = connection.CreateCommand();
            update.CommandText = "UPDATE users SET last_activity_at = $last_activity WHERE id = $user_id";
            update.Parameters.AddWithValue(
                "$last_activity",
                DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture));
            update.Parameters.AddWithValue("$user_id", user.Id);
            await update.ExecuteNonQueryAsync(cancellationToken);
        }

        if (user.IsAdministrator)
        {
            user = user with
            {
                AllowedPages = PermissionCatalog.PageKeys,
                AllowedActions = PermissionCatalog.AdministratorActionKeys,
                AllowedSiteTypes = await siteTypes.ExecuteAsync(cancellationToken),
            };
        }

        return user;
    }

    private static bool NeedsActivityRefresh(string? value) =>
        !DateTime.TryParse(
            value,
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
            out var lastActivity)
        || lastActivity <= DateTime.UtcNow.AddMinutes(-5);
}
