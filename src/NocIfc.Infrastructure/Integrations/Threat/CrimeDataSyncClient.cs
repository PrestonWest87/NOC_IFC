using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using NocIfc.Application.Abstractions.Email;
using NocIfc.Application.Abstractions.Settings;
using NocIfc.Application.Abstractions.Threat;
using NocIfc.Domain.Threat;
using NocIfc.Infrastructure.Persistence.Sqlite;

namespace NocIfc.Infrastructure.Integrations.Threat;

public sealed class CrimeDataSyncClient(
    HttpClient httpClient,
    SqliteCrimeDataSyncStore store,
    IOperationalIntegrationSettingsStore integrationSettings,
    IEmailSender emailSender) : ICrimeDataSyncProvider
{
    private const string CadUrl = "https://web.littlerock.state.ar.us/pub/Home/CadEvents";
    private const string GeocodeUrl = "https://geocode.arcgis.com/arcgis/rest/services/World/GeocodeServer/findAddressCandidates";
    private const double HeadquartersLatitude = 34.6755;
    private const double HeadquartersLongitude = -92.3235;
    private const int MaxCadResponseBytes = 16 * 1024 * 1024;
    private const int MaxGeocodeResponseBytes = 1024 * 1024;
    private const int GeocodeCacheCapacity = 500;
    private static readonly TimeZoneInfo CentralTimeZone = TimeZoneInfo.FindSystemTimeZoneById("America/Chicago");
    private static readonly object GeocodeCacheLock = new();
    private static readonly Dictionary<string, LinkedListNode<GeocodeCacheEntry>> GeocodeCache = new(StringComparer.Ordinal);
    private static readonly LinkedList<GeocodeCacheEntry> GeocodeLru = new();

    public async Task<CrimeDataSyncOutcome> SyncAsync(CancellationToken cancellationToken)
    {
        var now = DateTime.UtcNow;
        var cutoff = now.AddHours(-168);
        using var request = new HttpRequestMessage(HttpMethod.Post, CadUrl);
        using var response = await httpClient.SendAsync(
            request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        response.EnsureSuccessStatusCode();
        var payload = await ReadBodyAsync(response, MaxCadResponseBytes, cancellationToken);
        using var document = JsonDocument.Parse(payload);
        if (document.RootElement.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidDataException("Little Rock CAD response must be a JSON array.");
        }

        var incidents = new List<CrimeIncidentEntry>();
        var seenIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (var entry in document.RootElement.EnumerateArray())
        {
            try
            {
                if (entry.ValueKind != JsonValueKind.Object) continue;
                var description = (ReadString(entry, "typeDescription", "UNKNOWN") ?? "UNKNOWN").ToUpperInvariant();
                var location = ReadString(entry, "location", "UNKNOWN") ?? "UNKNOWN";
                var rawDate = ReadString(entry, "dispatchDate", "");
                if (string.IsNullOrEmpty(rawDate)
                    || !DateTime.TryParseExact(rawDate, "MM/dd/yyyy HH:mm:ss", CultureInfo.InvariantCulture,
                        DateTimeStyles.None, out var localDate))
                {
                    continue;
                }
                var incidentDate = TimeZoneInfo.ConvertTimeToUtc(
                    DateTime.SpecifyKind(localDate, DateTimeKind.Unspecified), CentralTimeZone);
                if (incidentDate < cutoff) continue;

                var geocoded = await GeocodeAsync(location, cancellationToken);
                var distance = Math.Round(CalculateDistance(
                    HeadquartersLatitude, HeadquartersLongitude, geocoded.Latitude, geocoded.Longitude), 2);
                var locationHash = Convert.ToHexString(MD5.HashData(Encoding.UTF8.GetBytes(location)))[..6].ToLowerInvariant();
                var id = $"LR_{incidentDate:yyyyMMddHHmmss}_{locationHash}";
                if (!seenIds.Add(id)) continue;

                var (category, severity) = Classify(description);
                var title = CultureInfo.InvariantCulture.TextInfo.ToTitleCase(description.ToLowerInvariant());
                if (geocoded.IsApproximate) title += " (Approx Loc)";
                incidents.Add(new CrimeIncidentEntry(
                    id, category, title, incidentDate, distance, severity,
                    geocoded.Latitude, geocoded.Longitude));
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception)
            {
                // Ignore malformed individual CAD rows, as the source worker does.
            }
        }

        var added = await store.SaveNewIncidentsAsync(incidents, cutoff, cancellationToken);
        var alerts = await DispatchPerimeterAlertsAsync(cancellationToken);
        return new CrimeDataSyncOutcome(added, alerts);
    }

    private async Task<int> DispatchPerimeterAlertsAsync(CancellationToken cancellationToken)
    {
        var settings = await integrationSettings.GetAsync(cancellationToken);
        var recipients = settings.CrimeAlertSms;
        if (string.IsNullOrEmpty(recipients)) recipients = settings.CrimeAlertEmail;
        if (string.IsNullOrEmpty(recipients)) return 0;
        recipients = string.Join(", ", recipients.Split(',').Select(value => value.Trim()));

        var incidents = await store.GetUndispatchedHighSeverityAsync(0.4, cancellationToken);
        var sentCount = 0;
        foreach (var incident in incidents)
        {
            var distance = (incident.DistanceMiles ?? 0).ToString("0.##", CultureInfo.InvariantCulture);
            var latitude = incident.Latitude?.ToString(CultureInfo.InvariantCulture) ?? "None";
            var longitude = incident.Longitude?.ToString(CultureInfo.InvariantCulture) ?? "None";
            var map = $"https://www.google.com/maps?q={latitude},{longitude}";
            var body = $"[ALERT] PERIMETER ALERT [ALERT]\n{incident.RawTitle}\nDist: {distance} mi\nTime: {FormatCentralShort(incident.Timestamp)}\nMap: {map}";
            var result = await emailSender.SendPlainTextAsync(
                recipients, $"Crime Alert: {distance}mi", body, cancellationToken);
            if (!result.Success) continue;
            await store.MarkAlertDispatchedAsync(incident.Id, cancellationToken);
            sentCount++;
        }
        return sentCount;
    }

    private async Task<GeocodedLocation> GeocodeAsync(string address, CancellationToken cancellationToken)
    {
        if (TryGetCached(address, out var cached)) return cached;
        var cleanAddress = address.Replace("/", " and ", StringComparison.Ordinal)
            .Replace(" BLK ", " ", StringComparison.Ordinal)
            .Replace(" BLOCK ", " ", StringComparison.Ordinal)
            .Trim();
        cleanAddress = string.Join(' ', cleanAddress.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
        var singleLine = Uri.EscapeDataString($"{cleanAddress}, Little Rock, AR");
        var uri = $"{GeocodeUrl}?SingleLine={singleLine}&f=json&maxLocations=1";

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(5));
        try
        {
            using var response = await httpClient.GetAsync(
                uri, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
            if (response.StatusCode == HttpStatusCode.OK)
            {
                var body = await ReadBodyAsync(response, MaxGeocodeResponseBytes, timeout.Token);
                using var document = JsonDocument.Parse(body);
                if (document.RootElement.TryGetProperty("candidates", out var candidates)
                    && candidates.ValueKind == JsonValueKind.Array
                    && candidates.GetArrayLength() > 0)
                {
                    var candidate = candidates[0];
                    if (candidate.TryGetProperty("location", out var point)
                        && point.TryGetProperty("x", out var longitudeValue)
                        && longitudeValue.TryGetDouble(out var longitude)
                        && point.TryGetProperty("y", out var latitudeValue)
                        && latitudeValue.TryGetDouble(out var latitude)
                        && double.IsFinite(latitude) && double.IsFinite(longitude))
                    {
                        var score = candidate.TryGetProperty("score", out var scoreValue)
                            && scoreValue.TryGetDouble(out var parsedScore)
                                ? parsedScore
                                : 0;
                        var location = new GeocodedLocation(latitude, longitude, score < 75);
                        Cache(address, location);
                        return location;
                    }
                }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            // Use the same approximate-location fallback when ArcGIS is unavailable or times out.
        }
        catch (Exception)
        {
            // CAD incidents are retained with an approximate headquarters-proximate point if geocoding fails.
        }

        var radiusDegrees = 0.009 + Random.Shared.NextDouble() * 0.009;
        var angle = Random.Shared.NextDouble() * Math.PI * 2;
        var fallback = new GeocodedLocation(
            HeadquartersLatitude + radiusDegrees * Math.Cos(angle),
            HeadquartersLongitude + radiusDegrees * Math.Sin(angle),
            true);
        Cache(address, fallback);
        return fallback;
    }

    private static bool TryGetCached(string address, out GeocodedLocation location)
    {
        lock (GeocodeCacheLock)
        {
            if (!GeocodeCache.TryGetValue(address, out var node))
            {
                location = default;
                return false;
            }
            GeocodeLru.Remove(node);
            GeocodeLru.AddLast(node);
            location = node.Value.Location;
            return true;
        }
    }

    private static void Cache(string address, GeocodedLocation location)
    {
        lock (GeocodeCacheLock)
        {
            if (GeocodeCache.TryGetValue(address, out var existing))
            {
                GeocodeLru.Remove(existing);
            }
            var node = GeocodeLru.AddLast(new GeocodeCacheEntry(address, location));
            GeocodeCache[address] = node;
            if (GeocodeCache.Count <= GeocodeCacheCapacity) return;
            var oldest = GeocodeLru.First!;
            GeocodeLru.RemoveFirst();
            GeocodeCache.Remove(oldest.Value.Address);
        }
    }

    private static (string Category, string Severity) Classify(string description)
    {
        if (HasAny(description, "ARSON", "EXPLOSIVE", "TERROR", "SABOTAGE", "SHOOTING"))
            return ("Critical Infrastructure Threat", "Critical");
        if (HasAny(description, "THEFT", "BURGLARY", "ROBBERY", "BREAKING"))
            return ("Asset/Copper Theft Risk", "High");
        if (HasAny(description, "ASSAULT", "BATTERY", "HOMICIDE", "WEAPON", "SHOTS"))
            return ("Violent Proximity Threat", "High");
        if (HasAny(description, "VANDALISM", "TRESPASS", "PROWLER", "DISTURBANCE", "SUSPICIOUS"))
            return ("Perimeter Breach/Vandalism", "Medium");
        return ("General Police Activity", "Low");
    }

    private static bool HasAny(string value, params string[] keywords) =>
        keywords.Any(value.Contains);

    private static double CalculateDistance(double latitude1, double longitude1, double latitude2, double longitude2)
    {
        const double earthRadiusMiles = 3958.8;
        var lat1 = latitude1 * Math.PI / 180;
        var lat2 = latitude2 * Math.PI / 180;
        var deltaLatitude = (latitude2 - latitude1) * Math.PI / 180;
        var deltaLongitude = (longitude2 - longitude1) * Math.PI / 180;
        var value = Math.Pow(Math.Sin(deltaLatitude / 2), 2)
            + Math.Cos(lat1) * Math.Cos(lat2) * Math.Pow(Math.Sin(deltaLongitude / 2), 2);
        return earthRadiusMiles * 2 * Math.Asin(Math.Sqrt(Math.Clamp(value, 0, 1)));
    }

    private static string FormatCentralShort(DateTime? value)
    {
        if (value is null) return "Unknown";
        var utc = DateTime.SpecifyKind(value.Value, DateTimeKind.Utc);
        return TimeZoneInfo.ConvertTimeFromUtc(utc, CentralTimeZone)
            .ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture);
    }

    private static string? ReadString(JsonElement source, string property, string? defaultValue)
    {
        if (!source.TryGetProperty(property, out var value)) return defaultValue;
        if (value.ValueKind == JsonValueKind.Null) return null;
        if (value.ValueKind == JsonValueKind.String) return value.GetString();
        throw new InvalidDataException($"CAD field '{property}' must be text.");
    }

    private static async Task<byte[]> ReadBodyAsync(
        HttpResponseMessage response,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        if (response.Content.Headers.ContentLength is > 0 && response.Content.Headers.ContentLength > maximumBytes)
        {
            throw new InvalidDataException("Crime-data provider response exceeded its size limit.");
        }
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var buffer = new MemoryStream();
        var chunk = new byte[8192];
        while (true)
        {
            var count = await stream.ReadAsync(chunk, cancellationToken);
            if (count == 0) break;
            if (buffer.Length + count > maximumBytes)
            {
                throw new InvalidDataException("Crime-data provider response exceeded its size limit.");
            }
            buffer.Write(chunk, 0, count);
        }
        return buffer.ToArray();
    }

    private readonly record struct GeocodedLocation(double Latitude, double Longitude, bool IsApproximate);
    private sealed record GeocodeCacheEntry(string Address, GeocodedLocation Location);
}
