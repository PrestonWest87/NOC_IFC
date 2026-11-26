using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Text.Json;
using NocIfc.Application.Abstractions.Llm;

namespace NocIfc.Infrastructure.Integrations.Llm;

public sealed record LlmEndpointPolicy(bool AllowPrivateEndpoints);

public sealed class ProviderAwareLlmConnectionTester(HttpClient httpClient, LlmEndpointPolicy policy)
    : ILlmConnectionTester
{
    private const int MaxResponseBytes = 1_000_000;
    private static readonly HashSet<string> LocalProviders =
        new(["ollama_openai", "ollama_native", "vllm"], StringComparer.Ordinal);

    public async Task<LlmConnectionTestResult> TestAsync(
        LlmConnectionTestSettings settings,
        CancellationToken cancellationToken)
    {
        if (!TryBuildChatUri(settings.Endpoint, settings.Provider, out var uri)
            || !await IsAllowedEndpointAsync(uri, settings.Provider, cancellationToken))
        {
            return new LlmConnectionTestResult(false,
                "Endpoint is not allowed. Use a valid HTTP(S) URL; local/private endpoints require an explicit local provider or ALLOW_PRIVATE_LLM_ENDPOINTS.");
        }

        object[] messages =
        [
            new { role = "system", content = "You are a helpful assistant." },
            new { role = "user", content = "Reply with exactly: CONNECTION_OK" },
        ];
        object payload = settings.Provider == "ollama_native"
            ? new
            {
                model = settings.ModelName,
                messages,
                stream = false,
                options = new { temperature = 0.0, num_predict = 20 },
            }
            : new
            {
                model = settings.ModelName,
                messages,
                temperature = 0.0,
                max_tokens = 20,
            };

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(30));
        using var request = new HttpRequestMessage(HttpMethod.Post, uri)
        {
            Content = JsonContent.Create(payload),
        };
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        if (!string.IsNullOrEmpty(settings.ApiKey))
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", settings.ApiKey);
        }

        try
        {
            using var response = await httpClient.SendAsync(
                request, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
            if (!response.IsSuccessStatusCode)
            {
                return new LlmConnectionTestResult(false,
                    $"The {settings.Provider} endpoint returned HTTP {(int)response.StatusCode}. Check the provider selection and API path.");
            }
            var responseBytes = await ReadBoundedResponseAsync(response, timeout.Token);
            if (responseBytes is null)
            {
                return new LlmConnectionTestResult(false, "The model endpoint response was too large.");
            }
            using var document = JsonDocument.Parse(responseBytes);
            var content = ReadContent(document.RootElement, settings.Provider);
            if (string.IsNullOrWhiteSpace(content))
            {
                return new LlmConnectionTestResult(false, "The model endpoint returned an empty response.");
            }
            var responseText = content.Trim();
            return new LlmConnectionTestResult(true,
                $"Connection successful. Model response: {responseText[..Math.Min(240, responseText.Length)]}");
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new LlmConnectionTestResult(false, "Request timed out after 30 seconds.");
        }
        catch (HttpRequestException)
        {
            return new LlmConnectionTestResult(false,
                "Could not connect to the model endpoint. Check its hostname, port, and reachability from the API container.");
        }
        catch (JsonException)
        {
            return new LlmConnectionTestResult(false,
                $"The {settings.Provider} endpoint returned an unexpected chat response. Check that the selected API type matches the server.");
        }
        catch (Exception)
        {
            return new LlmConnectionTestResult(false, "Connection failed unexpectedly. Check the API server logs.");
        }
    }

    private async Task<bool> IsAllowedEndpointAsync(Uri uri, string provider, CancellationToken cancellationToken)
    {
        if (policy.AllowPrivateEndpoints)
        {
            return true;
        }

        IPAddress[] addresses;
        try
        {
            addresses = await Dns.GetHostAddressesAsync(uri.DnsSafeHost, cancellationToken);
        }
        catch (Exception exception) when (exception is SocketException or ArgumentException)
        {
            return false;
        }
        if (addresses.Length == 0)
        {
            return false;
        }

        var allowsPrivate = LocalProviders.Contains(provider);
        return addresses.All(address => !IsReservedOrUnsafe(address)
            && (allowsPrivate || !IsPrivateOrLoopback(address)));
    }

    private static bool TryBuildChatUri(string endpoint, string provider, out Uri uri)
    {
        uri = new Uri("about:blank");
        if (provider is not ("openai_compatible" or "ollama_openai" or "ollama_native" or "vllm"))
        {
            return false;
        }
        var baseUrl = (endpoint ?? "").Trim().TrimEnd('/');
        if (!Uri.TryCreate(baseUrl, UriKind.Absolute, out var parsed)
            || parsed.Scheme is not ("http" or "https")
            || string.IsNullOrEmpty(parsed.Host)
            || parsed.UserInfo.Length > 0
            || parsed.Query.Length > 0
            || parsed.Fragment.Length > 0)
        {
            return false;
        }

        string target;
        if (provider == "ollama_native")
        {
            if (baseUrl.EndsWith("/api/chat", StringComparison.Ordinal))
            {
                target = baseUrl;
            }
            else if (baseUrl.EndsWith("/api", StringComparison.Ordinal))
            {
                target = $"{baseUrl}/chat";
            }
            else
            {
                var nativeBase = baseUrl.EndsWith("/v1", StringComparison.Ordinal)
                    ? baseUrl[..^3].TrimEnd('/')
                    : baseUrl;
                target = $"{nativeBase}/api/chat";
            }
        }
        else if (baseUrl.EndsWith("/chat/completions", StringComparison.Ordinal))
        {
            target = baseUrl;
        }
        else
        {
            var isLocalOpenAiProvider = provider is "ollama_openai" or "vllm";
            var apiBase = isLocalOpenAiProvider
                && !baseUrl.EndsWith("/v1", StringComparison.Ordinal)
                    ? $"{baseUrl}/v1"
                    : baseUrl;
            target = $"{apiBase}/chat/completions";
        }
        if (!Uri.TryCreate(target, UriKind.Absolute, out var built) || built is null)
        {
            return false;
        }
        uri = built;
        return true;
    }

    private static bool IsReservedOrUnsafe(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6)
        {
            return IsReservedOrUnsafe(address.MapToIPv4());
        }
        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            var bytes = address.GetAddressBytes();
            var documentation = bytes[0] == 0x20 && bytes[1] == 0x01
                && bytes[2] == 0x0d && bytes[3] == 0xb8;
            return address.IsIPv6LinkLocal
                || address.IsIPv6Multicast
                || address.IsIPv6SiteLocal
                || address.Equals(IPAddress.IPv6Any)
                || documentation;
        }

        var ipv4 = address.GetAddressBytes();
        var first = ipv4[0];
        var second = ipv4[1];
        var third = ipv4[2];
        return first == 0
            || first == 169 && second == 254
            || first >= 224
            || first == 100 && second is >= 64 and <= 127
            || first == 192 && second == 0
            || first == 192 && second == 88 && third == 99
            || first == 198 && second is 18 or 19
            || first == 198 && second == 51 && third == 100
            || first == 203 && second == 0 && third == 113;
    }

    private static bool IsPrivateOrLoopback(IPAddress address)
    {
        if (IPAddress.IsLoopback(address))
        {
            return true;
        }
        if (address.IsIPv4MappedToIPv6)
        {
            return IsPrivateOrLoopback(address.MapToIPv4());
        }
        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            var bytes = address.GetAddressBytes();
            return (bytes[0] & 0xfe) == 0xfc;
        }
        var octets = address.GetAddressBytes();
        return octets[0] == 10
            || octets[0] == 172 && octets[1] is >= 16 and <= 31
            || octets[0] == 192 && octets[1] == 168;
    }

    private static string? ReadContent(JsonElement root, string provider)
    {
        if (provider == "ollama_native")
        {
            return root.GetProperty("message").GetProperty("content").GetString();
        }
        return root.GetProperty("choices")[0].GetProperty("message").GetProperty("content").GetString();
    }

    private static async Task<byte[]?> ReadBoundedResponseAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        if (response.Content.Headers.ContentLength is > MaxResponseBytes)
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
        return buffer.ToArray();
    }
}
