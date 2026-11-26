using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using NocIfc.Application.Abstractions.Elastic;
using NocIfc.Application.Features.Settings;
using NocIfc.Domain.Threat;

namespace NocIfc.Infrastructure.Integrations.Elastic;

public sealed class ElasticSearchClient : IElasticEventSource
{
    private const int MaxResponseBytes = 32 * 1024 * 1024;
    private readonly HttpMessageHandler? handlerOverride;

    public ElasticSearchClient(HttpMessageHandler? handlerOverride = null) =>
        this.handlerOverride = handlerOverride;

    public async Task<IReadOnlyList<ElasticEventEntry>> SearchHighSeverityAsync(
        ElasticClientSettings settings,
        DateTime sinceUtc,
        CancellationToken cancellationToken)
    {
        var configuredEndpoint = settings.Endpoint.Trim();
        if (!Uri.TryCreate(configuredEndpoint, UriKind.Absolute, out var endpoint)
            || endpoint.Scheme is not ("http" or "https")
            || endpoint.UserInfo.Length > 0
            || endpoint.Query.Length > 0
            || endpoint.Fragment.Length > 0
            || settings.MaxResults is < 1 or > 5000
            || !double.IsFinite(settings.RequestTimeoutSeconds)
            || settings.RequestTimeoutSeconds is <= 0 or > 120)
        {
            throw new InvalidOperationException("Elasticsearch client settings are invalid.");
        }

        var caCertificates = LoadCaCertificates(settings);
        try
        {
            using var handler = handlerOverride ?? CreateHandler(settings, caCertificates);
            using var client = new HttpClient(handler)
            {
                Timeout = TimeSpan.FromSeconds(settings.RequestTimeoutSeconds),
            };
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            if (!string.IsNullOrWhiteSpace(settings.ApiKey))
            {
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("ApiKey", settings.ApiKey);
            }

            var baseUri = new Uri(configuredEndpoint.TrimEnd('/') + "/", UriKind.Absolute);
            var searchUri = new Uri(baseUri,
                "*,-.*/_search?scroll=1m&ignore_unavailable=true&allow_no_indices=true");
            var body = new
            {
                _source = new[]
                {
                    "@timestamp", "log.level", "event.severity", "message", "event.original",
                    "source.ip", "log.source.address", "event.category",
                },
                query = new
                {
                    @bool = new
                    {
                        must = new[]
                        {
                            new { range = new Dictionary<string, object>
                                { ["@timestamp"] = new { gte = sinceUtc.ToString("O", CultureInfo.InvariantCulture) } } },
                        },
                        minimum_should_match = 1,
                        should = new object[]
                        {
                            new { terms = new Dictionary<string, string[]>
                                { ["log.level"] = ["emergency", "alert", "critical", "error", "severe"] } },
                            new { range = new Dictionary<string, object>
                                { ["event.severity"] = new { lte = 3 } } },
                        },
                    },
                },
                size = settings.MaxResults,
                sort = new[] { new Dictionary<string, object>
                    { ["@timestamp"] = new { order = "desc", unmapped_type = "date" } } },
            };

            var events = new List<ElasticEventEntry>();
            JsonDocument? response = null;
            string? scrollId = null;
            try
            {
                response = await SendJsonAsync(client, HttpMethod.Post, searchUri, body, cancellationToken);
                scrollId = ReadString(response.RootElement, "_scroll_id");
                for (var page = 0; page < 20; page++)
                {
                    if (!TryGetHits(response.RootElement, out var hits) || hits.Length == 0)
                    {
                        break;
                    }
                    foreach (var hit in hits)
                    {
                        var mapped = MapHit(hit);
                        if (mapped is not null)
                        {
                            events.Add(mapped);
                        }
                    }
                    if (hits.Length < settings.MaxResults || string.IsNullOrEmpty(scrollId))
                    {
                        break;
                    }

                    response.Dispose();
                    response = await SendJsonAsync(
                        client,
                        HttpMethod.Post,
                        new Uri(baseUri, "_search/scroll"),
                        new { scroll = "1m", scroll_id = scrollId },
                        cancellationToken);
                    scrollId = ReadString(response.RootElement, "_scroll_id") ?? scrollId;
                }
            }
            finally
            {
                response?.Dispose();
                if (!string.IsNullOrEmpty(scrollId))
                {
                    try
                    {
                        var cleared = await SendJsonAsync(
                            client,
                            HttpMethod.Delete,
                            new Uri(baseUri, "_search/scroll"),
                            new { scroll_id = scrollId },
                            cancellationToken);
                        cleared.Dispose();
                    }
                    catch (Exception)
                    {
                    }
                }
            }
            return events;
        }
        finally
        {
            foreach (var certificate in caCertificates)
            {
                certificate.Dispose();
            }
        }
    }

    private static SocketsHttpHandler CreateHandler(
        ElasticClientSettings settings,
        X509Certificate2Collection caCertificates)
    {
        var handler = new SocketsHttpHandler { AllowAutoRedirect = false };
        if (!settings.VerifyCertificates)
        {
            handler.SslOptions.RemoteCertificateValidationCallback = (_, _, _, _) => true;
        }
        else if (caCertificates.Count > 0)
        {
            handler.SslOptions.RemoteCertificateValidationCallback = (_, certificate, _, errors) =>
            {
                if (errors == SslPolicyErrors.None)
                {
                    return true;
                }
                if (certificate is null || (errors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0)
                {
                    return false;
                }
                using var serverCertificate = certificate is X509Certificate2 certificate2
                    ? new X509Certificate2(certificate2)
                    : new X509Certificate2(certificate);
                using var chain = new X509Chain();
                chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                chain.ChainPolicy.CustomTrustStore.AddRange(caCertificates);
                return chain.Build(serverCertificate);
            };
        }
        return handler;
    }

    private static X509Certificate2Collection LoadCaCertificates(ElasticClientSettings settings)
    {
        var certificates = new X509Certificate2Collection();
        if (!settings.VerifyCertificates || string.IsNullOrWhiteSpace(settings.CaCertificates))
        {
            return certificates;
        }
        var pem = File.ReadAllText(settings.CaCertificates);
        if (pem.Contains("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal))
        {
            certificates.ImportFromPem(pem);
        }
        else
        {
            certificates.Add(X509CertificateLoader.LoadCertificateFromFile(settings.CaCertificates));
        }
        return certificates;
    }

    private static async Task<JsonDocument> SendJsonAsync(
        HttpClient client,
        HttpMethod method,
        Uri uri,
        object? body,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(method, uri);
        if (body is not null)
        {
            request.Content = JsonContent.Create(body);
        }
        using var response = await client.SendAsync(
            request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            throw new HttpRequestException($"Elasticsearch returned HTTP {(int)response.StatusCode}.");
        }
        if (response.Content.Headers.ContentLength is > MaxResponseBytes)
        {
            throw new InvalidDataException("Elasticsearch response exceeded the size limit.");
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
                throw new InvalidDataException("Elasticsearch response exceeded the size limit.");
            }
            buffer.Write(chunk, 0, read);
        }
        return JsonDocument.Parse(buffer.ToArray());
    }

    private static bool TryGetHits(JsonElement root, out JsonElement[] hits)
    {
        hits = [];
        if (!root.TryGetProperty("hits", out var hitsObject)
            || !hitsObject.TryGetProperty("hits", out var hitArray)
            || hitArray.ValueKind != JsonValueKind.Array)
        {
            return false;
        }
        hits = hitArray.EnumerateArray().ToArray();
        return true;
    }

    private static ElasticEventEntry? MapHit(JsonElement hit)
    {
        var documentId = ReadValue(hit, "_id");
        if (string.IsNullOrEmpty(documentId))
        {
            return null;
        }
        var indexName = ReadValue(hit, "_index") ?? "unknown";
        var source = GetObject(hit, "_source");
        var log = GetObject(source, "log");
        var eventData = GetObject(source, "event");

        var level = GetElement(log, "level");
        var numericSeverity = GetElement(eventData, "severity");
        var finalSeverity = IsTruthy(level)
            ? (ReadValue(level) ?? "UNKNOWN").ToUpperInvariant()
            : TryReadDouble(numericSeverity, out var number)
                ? number <= 2 ? "CRITICAL" : number <= 3 ? "HIGH" : "WARNING"
                : "UNKNOWN";

        var message = GetElement(source, "message");
        if (!IsTruthy(message))
        {
            message = GetElement(eventData, "original");
        }
        var messageText = message.ValueKind == JsonValueKind.Undefined
            ? "No payload provided"
            : ReadValue(message) ?? "None";

        var sourceData = GetObject(source, "source");
        var logSource = GetObject(log, "source");
        var sourceIp = GetElement(sourceData, "ip");
        if (!IsTruthy(sourceIp))
        {
            sourceIp = GetElement(logSource, "address");
        }
        var category = GetElement(eventData, "category");
        var categoryText = category.ValueKind switch
        {
            JsonValueKind.Undefined => "Unknown",
            JsonValueKind.Array when category.GetArrayLength() > 0 => ReadValue(category[0]) ?? "None",
            JsonValueKind.Array => "[]",
            _ => ReadValue(category) ?? "None",
        };

        var timestamp = ReadValue(source, "@timestamp");
        var parsedTimestamp = DateTimeOffset.TryParse(
            timestamp,
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
            out var parsed)
                ? parsed.UtcDateTime
                : DateTime.UtcNow;
        return new ElasticEventEntry(
            $"{indexName}:{documentId}",
            parsedTimestamp,
            indexName,
            finalSeverity,
            messageText[..Math.Min(250, messageText.Length)],
            IsTruthy(sourceIp) ? ReadValue(sourceIp) : "Unknown",
            categoryText.ToUpperInvariant(),
            documentId);
    }

    private static JsonElement GetObject(JsonElement value, string property) =>
        value.ValueKind == JsonValueKind.Object
        && value.TryGetProperty(property, out var result)
        && result.ValueKind == JsonValueKind.Object
            ? result
            : default;

    private static JsonElement GetElement(JsonElement value, string property) =>
        value.ValueKind == JsonValueKind.Object && value.TryGetProperty(property, out var result)
            ? result
            : default;

    private static string? ReadString(JsonElement value, string property) =>
        value.ValueKind == JsonValueKind.Object
        && value.TryGetProperty(property, out var result)
        && result.ValueKind == JsonValueKind.String
            ? result.GetString()
            : null;

    private static string? ReadValue(JsonElement value, string property) =>
        value.ValueKind == JsonValueKind.Object && value.TryGetProperty(property, out var result)
            ? ReadValue(result)
            : null;

    private static string? ReadValue(JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.String => value.GetString(),
        JsonValueKind.Number => value.GetRawText(),
        JsonValueKind.True => "True",
        JsonValueKind.False => "False",
        JsonValueKind.Object or JsonValueKind.Array => value.GetRawText(),
        _ => null,
    };

    private static bool IsTruthy(JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.String => !string.IsNullOrEmpty(value.GetString()),
        JsonValueKind.Number => double.TryParse(value.GetRawText(), NumberStyles.Float, CultureInfo.InvariantCulture, out var number) && number != 0,
        JsonValueKind.True or JsonValueKind.Object or JsonValueKind.Array => true,
        _ => false,
    };

    private static bool TryReadDouble(JsonElement value, out double result)
    {
        var raw = ReadValue(value);
        return double.TryParse(raw, NumberStyles.Float, CultureInfo.InvariantCulture, out result);
    }
}
