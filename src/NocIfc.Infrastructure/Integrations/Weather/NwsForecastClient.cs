using System.Globalization;
using System.Net.Http.Headers;
using System.Text.Json;
using NocIfc.Application.Abstractions.Regional;

namespace NocIfc.Infrastructure.Integrations.Weather;

public sealed record NwsForecastConfiguration(string UserAgent, string DefaultAdminEmail);

public sealed class NwsForecastClient(HttpClient httpClient, NwsForecastConfiguration configuration)
    : INwsForecastProvider
{
    private const int MaxResponseBytes = 4 * 1024 * 1024;
    private static readonly TimeSpan CacheDuration = TimeSpan.FromHours(1);
    private static readonly Dictionary<string, ForecastCacheEntry> ForecastCache = new(StringComparer.Ordinal);
    private static readonly object CacheLock = new();

    public async Task<string?> GetForecastPeriodsJsonAsync(
        double latitude,
        double longitude,
        CancellationToken cancellationToken)
    {
        var key = $"{latitude.ToString("R", CultureInfo.InvariantCulture)},{longitude.ToString("R", CultureInfo.InvariantCulture)}";
        var now = DateTime.UtcNow;
        lock (CacheLock)
        {
            if (ForecastCache.TryGetValue(key, out var cached))
            {
                if (cached.ExpiresAtUtc > now)
                {
                    return cached.PeriodsJson;
                }
                ForecastCache.Remove(key);
            }
        }

        var forecast = await FetchAsync(latitude, longitude, cancellationToken);
        lock (CacheLock)
        {
            if (ForecastCache.Count >= 128 && !ForecastCache.ContainsKey(key))
            {
                var oldest = ForecastCache.MinBy(item => item.Value.CreatedAtUtc);
                ForecastCache.Remove(oldest.Key);
            }
            var createdAt = DateTime.UtcNow;
            ForecastCache[key] = new ForecastCacheEntry(forecast, createdAt, createdAt.Add(CacheDuration));
        }
        return forecast;
    }

    private async Task<string?> FetchAsync(double latitude, double longitude, CancellationToken cancellationToken)
    {
        try
        {
            var pointUri = new Uri(
                $"https://api.weather.gov/points/{latitude.ToString("R", CultureInfo.InvariantCulture)},{longitude.ToString("R", CultureInfo.InvariantCulture)}");
            using var point = await GetJsonAsync(pointUri, cancellationToken);
            var forecastUrl = point?.RootElement.GetProperty("properties").GetProperty("forecast").GetString();
            if (!TryGetForecastUri(forecastUrl, out var forecastUri))
            {
                return null;
            }

            using var forecast = await GetJsonAsync(forecastUri, cancellationToken);
            if (forecast is null
                || !forecast.RootElement.TryGetProperty("properties", out var properties)
                || !properties.TryGetProperty("periods", out var periods)
                || periods.ValueKind != JsonValueKind.Array)
            {
                return null;
            }
            return periods.GetRawText();
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return null;
        }
    }

    private async Task<JsonDocument?> GetJsonAsync(Uri uri, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, uri);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/geo+json"));
        var userAgent = configuration.UserAgent;
        if (!string.IsNullOrWhiteSpace(configuration.DefaultAdminEmail)
            && !userAgent.Contains(configuration.DefaultAdminEmail, StringComparison.OrdinalIgnoreCase))
        {
            userAgent = $"{userAgent} ({configuration.DefaultAdminEmail})";
        }
        request.Headers.TryAddWithoutValidation("User-Agent", userAgent);

        using var response = await httpClient.SendAsync(
            request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        if (!response.IsSuccessStatusCode
            || response.Content.Headers.ContentLength is > MaxResponseBytes)
        {
            return null;
        }
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var buffer = new MemoryStream();
        var chunk = new byte[8192];
        while (true)
        {
            var read = await stream.ReadAsync(chunk, cancellationToken);
            if (read == 0)
            {
                break;
            }
            if (buffer.Length + read > MaxResponseBytes)
            {
                return null;
            }
            buffer.Write(chunk, 0, read);
        }
        return JsonDocument.Parse(buffer.ToArray());
    }

    private static bool TryGetForecastUri(string? value, out Uri uri)
    {
        uri = new Uri("about:blank");
        if (!Uri.TryCreate(value, UriKind.Absolute, out var parsed)
            || parsed.Scheme != Uri.UriSchemeHttps
            || !string.Equals(parsed.IdnHost, "api.weather.gov", StringComparison.OrdinalIgnoreCase)
            || parsed.UserInfo.Length > 0
            || parsed.Query.Length > 0
            || parsed.Fragment.Length > 0
            || !parsed.AbsolutePath.StartsWith("/gridpoints/", StringComparison.Ordinal))
        {
            return false;
        }
        uri = parsed;
        return true;
    }

    private sealed record ForecastCacheEntry(string? PeriodsJson, DateTime CreatedAtUtc, DateTime ExpiresAtUtc);
}
