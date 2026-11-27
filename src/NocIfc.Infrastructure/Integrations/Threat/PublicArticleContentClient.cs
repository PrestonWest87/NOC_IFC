using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using NocIfc.Application.Abstractions.Threat;

namespace NocIfc.Infrastructure.Integrations.Threat;

public sealed class PublicArticleContentClient : IArticleContentFetcher, IDisposable
{
    private const int MaxResponseBytes = 5 * 1024 * 1024;
    private const int MaxRedirects = 3;
    private static readonly Regex NonContentElements = new(
        @"<(script|style|noscript|svg|nav|footer|header|form)\b[^>]*>[\s\S]*?</\1\s*>",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex Tags = new("<[^>]+>", RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex Whitespace = new(@"\s+", RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private readonly HttpClient _client;

    public PublicArticleContentClient()
    {
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate | DecompressionMethods.Brotli,
            UseProxy = false,
            ConnectCallback = ConnectToPublicAddressAsync,
        };
        _client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
    }

    public async Task<string?> FetchAndExtractAsync(string url, CancellationToken cancellationToken)
    {
        if (!TryAllowedUri(url, out var target)) return null;
        for (var redirect = 0; redirect <= MaxRedirects; redirect++)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, target);
            request.Headers.UserAgent.ParseAdd("NOC-Fusion/2.0");
            using var response = await _client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            if ((int)response.StatusCode is >= 300 and < 400 && response.Headers.Location is { } location)
            {
                if (redirect == MaxRedirects || !TryAllowedUri(new Uri(target, location).AbsoluteUri, out target)) return null;
                continue;
            }
            if (!response.IsSuccessStatusCode) return null;
            var mediaType = response.Content.Headers.ContentType?.MediaType ?? "";
            if (!(mediaType.StartsWith("text/", StringComparison.OrdinalIgnoreCase)
                || mediaType.Equals("application/xhtml+xml", StringComparison.OrdinalIgnoreCase)))
            {
                return null;
            }
            var html = await ReadBoundedAsync(response.Content, cancellationToken);
            return html is null ? null : ExtractText(html);
        }
        return null;
    }

    public static bool IsAllowedUri(string value) => TryAllowedUri(value, out _);

    public void Dispose() => _client.Dispose();

    public static bool IsPublicAddress(IPAddress address)
    {
        if (IPAddress.IsLoopback(address) || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any)
            || address.IsIPv6LinkLocal || address.IsIPv6SiteLocal || address.IsIPv6Multicast)
        {
            return false;
        }
        if (address.IsIPv4MappedToIPv6) return IsPublicAddress(address.MapToIPv4());
        var bytes = address.GetAddressBytes();
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var first = bytes[0];
            var second = bytes[1];
            return first != 0 && first < 224
                && first != 10 && first != 127
                && !(first == 100 && second is >= 64 and <= 127)
                && !(first == 169 && second == 254)
                && !(first == 172 && second is >= 16 and <= 31)
                && !(first == 192 && second == 168)
                && !(first == 192 && second is 0 or 2)
                && !(first == 192 && second == 88 && bytes[2] == 99)
                && !(first == 198 && second is 18 or 19 or 51)
                && !(first == 203 && second == 0 && bytes[2] == 113)
                && !(first == 168 && second == 63 && bytes[2] == 129 && bytes[3] == 16);
        }
        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (bytes[0] is < 0x20 or > 0x3f) return false;
            if ((bytes[0] & 0xFE) == 0xFC) return false;
            if (bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] <= 0x01) return false;
            if (bytes[0] == 0x20 && bytes[1] == 0x02) return false;
            if (bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0x0D && bytes[3] == 0xB8) return false;
            if (bytes[0] == 0x3F && bytes[1] == 0xFF) return false;
            return true;
        }
        return false;
    }

    private static bool TryAllowedUri(string value, out Uri uri)
    {
        if (Uri.TryCreate(value, UriKind.Absolute, out var parsed)
            && parsed.Scheme is "http" or "https"
            && string.IsNullOrEmpty(parsed.UserInfo)
            && (parsed.IsDefaultPort || parsed.Port is 80 or 443)
            && (parsed.Scheme == "http" ? parsed.Port == 80 : parsed.Port == 443)
            && !parsed.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase)
            && !parsed.Host.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase)
            && !parsed.Host.EndsWith(".local", StringComparison.OrdinalIgnoreCase)
            && Uri.CheckHostName(parsed.Host) != UriHostNameType.Unknown
            && (!IPAddress.TryParse(parsed.Host, out var address) || IsPublicAddress(address)))
        {
            uri = parsed;
            return true;
        }
        uri = null!;
        return false;
    }

    private static async ValueTask<Stream> ConnectToPublicAddressAsync(
        SocketsHttpConnectionContext context,
        CancellationToken cancellationToken)
    {
        var addresses = await Dns.GetHostAddressesAsync(context.DnsEndPoint.Host, cancellationToken);
        if (addresses.Length == 0 || addresses.Any(address => !IsPublicAddress(address)))
        {
            throw new HttpRequestException("Article host resolved to a non-public IP address.");
        }
        Exception? lastError = null;
        foreach (var address in addresses)
        {
            var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            try
            {
                await socket.ConnectAsync(address, context.DnsEndPoint.Port, cancellationToken);
                return new NetworkStream(socket, ownsSocket: true);
            }
            catch (Exception exception) when (exception is SocketException or OperationCanceledException)
            {
                socket.Dispose();
                if (exception is OperationCanceledException) throw;
                lastError = exception;
            }
        }
        throw new HttpRequestException("Unable to connect to the public article host.", lastError);
    }

    private static async Task<string?> ReadBoundedAsync(HttpContent content, CancellationToken cancellationToken)
    {
        if (content.Headers.ContentLength is > MaxResponseBytes) return null;
        await using var source = await content.ReadAsStreamAsync(cancellationToken);
        using var output = new MemoryStream();
        var buffer = new byte[16 * 1024];
        while (true)
        {
            var read = await source.ReadAsync(buffer, cancellationToken);
            if (read == 0) break;
            if (output.Length + read > MaxResponseBytes) return null;
            output.Write(buffer, 0, read);
        }
        return Encoding.UTF8.GetString(output.GetBuffer(), 0, checked((int)output.Length));
    }

    private static string? ExtractText(string html)
    {
        // shortcut: regex removes common boilerplate; use a DOM parser if extraction quality proves inadequate.
        var text = Whitespace.Replace(Tags.Replace(NonContentElements.Replace(html, " "), " "), " ").Trim();
        text = WebUtility.HtmlDecode(text);
        return text.Length > 0 ? text[..Math.Min(text.Length, 200_000)] : null;
    }
}
