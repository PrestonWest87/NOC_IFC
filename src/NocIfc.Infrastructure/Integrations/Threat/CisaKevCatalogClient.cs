using System.Globalization;
using System.Net.Http.Headers;
using System.Text.Json;
using NocIfc.Application.Abstractions.Threat;
using NocIfc.Domain.Threat;

namespace NocIfc.Infrastructure.Integrations.Threat;

public sealed class CisaKevCatalogClient(HttpClient httpClient) : ICisaKevCatalogProvider
{
    private const string CatalogUrl = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
    private const int MaxResponseBytes = 16 * 1024 * 1024;

    public async Task<IReadOnlyList<CisaKevEntry>> FetchAsync(CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, CatalogUrl);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.UserAgent.ParseAdd("NOC-IFC/2.0");
        using var response = await httpClient.SendAsync(
            request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        response.EnsureSuccessStatusCode();
        if (response.Content.Headers.ContentLength is > MaxResponseBytes)
        {
            throw new InvalidDataException("CISA KEV catalog exceeded the 16 MB response limit.");
        }

        var body = await ReadBodyAsync(response, cancellationToken);
        using var document = JsonDocument.Parse(body);
        if (document.RootElement.ValueKind != JsonValueKind.Object
            || !document.RootElement.TryGetProperty("vulnerabilities", out var vulnerabilities)
            || vulnerabilities.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidDataException("CISA KEV catalog did not contain a vulnerabilities array.");
        }

        var entries = new List<CisaKevEntry>(vulnerabilities.GetArrayLength());
        foreach (var vulnerability in vulnerabilities.EnumerateArray())
        {
            if (vulnerability.ValueKind != JsonValueKind.Object)
            {
                throw new InvalidDataException("CISA KEV catalog contained a malformed vulnerability entry.");
            }
            var cveId = ReadString(vulnerability, "cveID", null);
            if (string.IsNullOrEmpty(cveId)) continue;
            var dateText = ReadString(vulnerability, "dateAdded", null);
            var dateAdded = string.IsNullOrEmpty(dateText)
                ? DateTime.UtcNow
                : DateTime.TryParseExact(dateText, "yyyy-MM-dd", CultureInfo.InvariantCulture,
                    DateTimeStyles.None, out var parsed)
                    ? DateTime.SpecifyKind(parsed, DateTimeKind.Unspecified)
                    : throw new InvalidDataException($"CISA KEV entry {cveId} has an invalid dateAdded value.");
            entries.Add(new CisaKevEntry(
                0,
                cveId,
                ReadString(vulnerability, "vendorProject", "Unknown"),
                ReadString(vulnerability, "product", "Unknown"),
                ReadString(vulnerability, "vulnerabilityName", "Unknown"),
                dateAdded,
                ReadString(vulnerability, "shortDescription", ""),
                ReadString(vulnerability, "requiredAction", ""),
                ReadString(vulnerability, "dueDate", "")));
        }
        return entries;
    }

    private static string? ReadString(JsonElement source, string property, string? missingValue)
    {
        if (!source.TryGetProperty(property, out var value)) return missingValue;
        if (value.ValueKind == JsonValueKind.Null) return null;
        if (value.ValueKind == JsonValueKind.String) return value.GetString();
        throw new InvalidDataException($"CISA KEV field '{property}' must be a string.");
    }

    private static async Task<byte[]> ReadBodyAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var buffer = new MemoryStream();
        var chunk = new byte[8192];
        while (true)
        {
            var count = await stream.ReadAsync(chunk, cancellationToken);
            if (count == 0) break;
            if (buffer.Length + count > MaxResponseBytes)
            {
                throw new InvalidDataException("CISA KEV catalog exceeded the 16 MB response limit.");
            }
            buffer.Write(chunk, 0, count);
        }
        return buffer.ToArray();
    }
}
