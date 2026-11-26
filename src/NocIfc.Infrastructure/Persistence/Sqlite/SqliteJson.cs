using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace NocIfc.Infrastructure.Persistence.Sqlite;

internal static class SqliteJson
{
    public static IReadOnlyList<string> ReadStringList(SqliteDataReader reader, int ordinal)
    {
        if (reader.IsDBNull(ordinal))
        {
            return Array.Empty<string>();
        }

        try
        {
            return JsonSerializer.Deserialize<string[]>(reader.GetString(ordinal)) ?? Array.Empty<string>();
        }
        catch (JsonException)
        {
            return Array.Empty<string>();
        }
    }
}
