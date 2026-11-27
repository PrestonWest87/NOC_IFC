using System.Globalization;
using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using NocIfc.Application.Abstractions.Regional;
using NocIfc.Infrastructure.Persistence.Sqlite;

namespace NocIfc.Infrastructure.Integrations.Weather;

public sealed class TelemetrySyncClient(
    HttpClient httpClient,
    SqliteConnectionFactory connections) : ITelemetrySyncProvider
{
    private const int MaxResponseBytes = 8 * 1024 * 1024;
    private const string IodaUrl = "https://api.ioda.inetintel.cc.gatech.edu/v2/outages/alerts";
    private static readonly IReadOnlyDictionary<string, (double Latitude, double Longitude)> CountyCoordinates =
        new Dictionary<string, (double, double)>(StringComparer.Ordinal)
        {
            ["PULASKI"] = (34.76, -92.28), ["SALINE"] = (34.64, -92.68), ["GARLAND"] = (34.58, -93.18),
            ["BENTON"] = (36.33, -94.25), ["WASHINGTON"] = (35.97, -94.18), ["FAULKNER"] = (35.15, -92.37),
            ["CRAIGHEAD"] = (35.83, -90.70), ["SEBASTIAN"] = (35.18, -94.27), ["LONOKE"] = (34.75, -91.87),
        };

    public async Task<TelemetrySyncResult> SyncAsync(CancellationToken cancellationToken)
    {
        var asns = await ReadMonitoredAsnsAsync(cancellationToken);
        var power = SyncOrnlAsync(cancellationToken);
        var bgp = SyncBgpAsync(asns, cancellationToken);
        var ioda = SyncIodaAsync(asns, cancellationToken);
        await Task.WhenAll(power, bgp, ioda);
        return new TelemetrySyncResult(await power, await bgp, await ioda);
    }

    private async Task<int> SyncOrnlAsync(CancellationToken cancellationToken)
    {
        try
        {
            using var document = await FetchJsonAsync(
                "https://ornl.opendatasoft.com/api/explore/v2.1/catalog/datasets/odin-real-time-outages-county/records?limit=100&refine=state%3AArkansas",
                cancellationToken);
            if (document is null
                || !document.RootElement.TryGetProperty("results", out var results)
                || results.ValueKind != JsonValueKind.Array)
            {
                return 0;
            }

            var now = DateTime.UtcNow;
            var rows = new List<RegionalOutageRow>();
            foreach (var item in results.EnumerateArray())
            {
                var county = ReadString(item, "county")?.ToUpperInvariant() ?? "";
                var customersOut = ReadDouble(item, "customers_out");
                if (customersOut <= 100) continue;
                var coordinates = CountyCoordinates.GetValueOrDefault(county, (34.8, -92.2));
                rows.Add(new RegionalOutageRow(
                    "Power", "ORNL ODIN", $"{customersOut:0} customers without power in {county} County.",
                    $"{county} County, AR", coordinates.Item1, coordinates.Item2,
                    10.0 + customersOut / 1000.0, now));
            }
            await ReplaceOutagesAsync("ORNL ODIN", rows, cancellationToken);
            return rows.Count;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine($"ORNL telemetry synchronization failed; existing rows were kept: {exception.Message}");
            return 0;
        }
    }

    private async Task<int> SyncBgpAsync(IReadOnlyList<string> asns, CancellationToken cancellationToken)
    {
        if (asns.Count == 0) return 0;
        using var parallelism = new SemaphoreSlim(5, 5);
        var results = await Task.WhenAll(asns.Select(async asn =>
        {
            await parallelism.WaitAsync(cancellationToken);
            try
            {
                using var document = await FetchJsonAsync(
                    $"https://stat.ripe.net/data/routing-status/data.json?resource={Uri.EscapeDataString(asn)}",
                    cancellationToken);
                if (document is null
                    || !document.RootElement.TryGetProperty("data", out var data)
                    || !data.TryGetProperty("visibility", out var visibility)
                    || !visibility.TryGetProperty("v4", out var ipv4))
                {
                    return null;
                }
                var risk = ReadDouble(ipv4, "risk");
                return risk > 0.5
                    ? new BgpAnomalyRow(asn, risk, DateTime.UtcNow)
                    : null;
            }
            finally
            {
                parallelism.Release();
            }
        }));
        var anomalies = results.Where(result => result is not null).Cast<BgpAnomalyRow>().ToArray();
        if (anomalies.Length == 0) return 0;

        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction();
        var added = 0;
        foreach (var anomaly in anomalies)
        {
            await using var exists = connection.CreateCommand();
            exists.Transaction = transaction;
            exists.CommandText = "SELECT 1 FROM bgp_anomalies WHERE asn = $asn AND is_resolved = 0 LIMIT 1";
            exists.Parameters.AddWithValue("$asn", anomaly.Asn);
            if (await exists.ExecuteScalarAsync(cancellationToken) is not null) continue;

            await using var insert = connection.CreateCommand();
            insert.Transaction = transaction;
            insert.CommandText = """
                INSERT INTO bgp_anomalies (asn, event_type, description, detected_at, is_resolved)
                VALUES ($asn, 'BGP Visibility Drop', $description, $detected, 0)
                """;
            insert.Parameters.AddWithValue("$asn", anomaly.Asn);
            insert.Parameters.AddWithValue("$description",
                $"Routing visibility for {anomaly.Asn} has degraded. Risk score: {anomaly.Risk:0.###}");
            insert.Parameters.AddWithValue("$detected", FormatDate(anomaly.DetectedAtUtc));
            added += await insert.ExecuteNonQueryAsync(cancellationToken);
        }
        transaction.Commit();
        return added;
    }

    private async Task<int> SyncIodaAsync(IReadOnlyList<string> asns, CancellationToken cancellationToken)
    {
        try
        {
            var now = DateTime.UtcNow;
            var until = new DateTimeOffset(now).ToUnixTimeSeconds();
            var from = new DateTimeOffset(now.AddHours(-12)).ToUnixTimeSeconds();
            using var parallelism = new SemaphoreSlim(5, 5);
            var requests = new List<(string Entity, string Code)>
            {
                ("region", "US-AR"),
            };
            requests.AddRange(asns.Select(asn => ("asn", asn[2..])));
            var results = await Task.WhenAll(requests.Select(async request =>
            {
                await parallelism.WaitAsync(cancellationToken);
                try
                {
                    var url = $"{IodaUrl}?entityType={request.Entity}&entityCode={Uri.EscapeDataString(request.Code)}&from={from}&until={until}";
                    using var document = await FetchJsonAsync(url, cancellationToken);
                    return ParseIodaRows(document, request, now);
                }
                finally
                {
                    parallelism.Release();
                }
            }));
            var rows = results.SelectMany(result => result).ToArray();
            await ReplaceOutagesAsync("IODA", rows, cancellationToken);
            return rows.Length;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine($"IODA telemetry synchronization failed; existing rows were kept: {exception.Message}");
            return 0;
        }
    }

    private static IReadOnlyList<RegionalOutageRow> ParseIodaRows(
        JsonDocument? document,
        (string Entity, string Code) request,
        DateTime detectedAtUtc)
    {
        if (document is null
            || !document.RootElement.TryGetProperty("data", out var alerts)
            || alerts.ValueKind != JsonValueKind.Array)
        {
            return [];
        }
        return alerts.EnumerateArray().Take(1000).Select(alert =>
        {
            var source = ReadString(alert, "datasource") ?? "Unknown source";
            var isRegion = request.Entity == "region";
            var affectedArea = isRegion ? "Arkansas, US" : $"Global ASN {request.Code}";
            return new RegionalOutageRow(
                "ISP", "IODA",
                isRegion
                    ? $"IODA detected ISP degradation via {source} in Arkansas."
                    : $"IODA detected global routing drops via {source} for ASN {request.Code}.",
                affectedArea, 34.8, -92.2, isRegion ? 200.0 : 300.0, detectedAtUtc);
        }).ToArray();
    }

    private async Task<IReadOnlyList<string>> ReadMonitoredAsnsAsync(CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT monitored_asns FROM system_config ORDER BY id LIMIT 1";
        var value = await command.ExecuteScalarAsync(cancellationToken);
        if (value is not string raw || string.IsNullOrWhiteSpace(raw)) return [];
        return raw.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
            .Select(value => value.StartsWith("AS", StringComparison.OrdinalIgnoreCase) ? value[2..] : value)
            .Where(value => value.Length is > 0 and <= 10 && value.All(char.IsAsciiDigit))
            .Select(value => $"AS{value}")
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private async Task<JsonDocument?> FetchJsonAsync(string url, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.UserAgent.ParseAdd("NOC-IFC/2.0 (https://test.weasts.net)");
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        using var response = await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        if (!response.IsSuccessStatusCode) return null;
        if (response.Content.Headers.ContentLength is > MaxResponseBytes)
        {
            throw new InvalidDataException("Telemetry response exceeded the 8 MB limit.");
        }
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var buffer = new MemoryStream();
        var chunk = new byte[16 * 1024];
        while (true)
        {
            var read = await stream.ReadAsync(chunk, cancellationToken);
            if (read == 0) break;
            if (buffer.Length + read > MaxResponseBytes)
            {
                throw new InvalidDataException("Telemetry response exceeded the 8 MB limit.");
            }
            buffer.Write(chunk, 0, read);
        }
        return JsonDocument.Parse(buffer.ToArray());
    }

    private async Task ReplaceOutagesAsync(
        string provider,
        IReadOnlyList<RegionalOutageRow> rows,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction();
        await using (var delete = connection.CreateCommand())
        {
            delete.Transaction = transaction;
            delete.CommandText = "DELETE FROM regional_outages WHERE provider = $provider";
            delete.Parameters.AddWithValue("$provider", provider);
            await delete.ExecuteNonQueryAsync(cancellationToken);
        }
        foreach (var row in rows)
        {
            await using var insert = connection.CreateCommand();
            insert.Transaction = transaction;
            insert.CommandText = """
                INSERT INTO regional_outages
                    (outage_type, provider, description, affected_area, lat, lon, radius_km, detected_at, is_resolved)
                VALUES
                    ($type, $provider, $description, $area, $lat, $lon, $radius, $detected, 0)
                """;
            insert.Parameters.AddWithValue("$type", row.Type);
            insert.Parameters.AddWithValue("$provider", row.Provider);
            insert.Parameters.AddWithValue("$description", row.Description);
            insert.Parameters.AddWithValue("$area", row.AffectedArea);
            insert.Parameters.AddWithValue("$lat", row.Latitude);
            insert.Parameters.AddWithValue("$lon", row.Longitude);
            insert.Parameters.AddWithValue("$radius", row.RadiusKilometers);
            insert.Parameters.AddWithValue("$detected", FormatDate(row.DetectedAtUtc));
            await insert.ExecuteNonQueryAsync(cancellationToken);
        }
        transaction.Commit();
    }

    private static string? ReadString(JsonElement value, string property) =>
        value.TryGetProperty(property, out var item) && item.ValueKind == JsonValueKind.String
            ? item.GetString()
            : null;

    private static double ReadDouble(JsonElement value, string property) =>
        value.TryGetProperty(property, out var item) && item.TryGetDouble(out var number) && double.IsFinite(number)
            ? number
            : 0;

    private static string FormatDate(DateTime value) =>
        value.ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture);

    private sealed record RegionalOutageRow(
        string Type,
        string Provider,
        string Description,
        string AffectedArea,
        double Latitude,
        double Longitude,
        double RadiusKilometers,
        DateTime DetectedAtUtc);

    private sealed record BgpAnomalyRow(string Asn, double Risk, DateTime DetectedAtUtc);
}
