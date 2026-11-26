using System.Text.Json;

namespace NocIfc.Application.Features.Identity;

public static class PermissionCatalog
{
    private static readonly JsonDocument Document = Load();
    private static readonly string[] PageKeysValue = Document.RootElement.GetProperty("pages")
        .EnumerateArray()
        .Select(item => item.GetProperty("key").GetString()!)
        .ToArray();
    private static readonly string[] AdministratorActionKeysValue = Document.RootElement
        .GetProperty("actions")
        .EnumerateArray()
        .Select(item => item.GetProperty("key").GetString()!)
        .Concat(Document.RootElement.GetProperty("tabs").EnumerateObject()
            .SelectMany(group => group.Value.EnumerateArray())
            .Select(item => item.GetProperty("key").GetString()!))
        .ToArray();

    public static JsonElement Value => Document.RootElement;
    public static IReadOnlyList<string> PageKeys => PageKeysValue;
    public static IReadOnlyList<string> AdministratorActionKeys => AdministratorActionKeysValue;

    public static bool ContainsPage(string key) =>
        Contains(Document.RootElement.GetProperty("pages"), key);

    public static bool ContainsGrant(string key)
    {
        var root = Document.RootElement;
        if (Contains(root.GetProperty("actions"), key))
        {
            return true;
        }

        foreach (var tabs in root.GetProperty("tabs").EnumerateObject())
        {
            if (Contains(tabs.Value, key))
            {
                return true;
            }
        }

        return false;
    }

    private static bool Contains(JsonElement entries, string key) =>
        entries.EnumerateArray().Any(item =>
            string.Equals(item.GetProperty("key").GetString(), key, StringComparison.Ordinal));

    private static JsonDocument Load()
    {
        using var stream = typeof(PermissionCatalog).Assembly
            .GetManifestResourceStream("NocIfc.Application.permission_catalog.json")
            ?? throw new InvalidOperationException("Embedded permission catalog is missing.");
        return JsonDocument.Parse(stream);
    }
}
