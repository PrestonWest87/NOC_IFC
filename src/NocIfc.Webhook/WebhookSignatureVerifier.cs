using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;

namespace NocIfc.Webhook;

public sealed class WebhookRejectionException(int statusCode, string message) : Exception(message)
{
    public int StatusCode { get; } = statusCode;
}

public sealed class WebhookSignatureVerifier(WebhookSecurityOptions options)
{
    private const int MaxReplayEntries = 10_000;
    private readonly object _sync = new();
    private readonly Dictionary<string, DateTimeOffset> _seen = new(StringComparer.Ordinal);

    public void Verify(IHeaderDictionary headers, byte[] body, DateTimeOffset now)
    {
        if (options.HmacSecret.Length == 0)
        {
            if (!options.AllowUnsigned)
            {
                throw new WebhookRejectionException(StatusCodes.Status503ServiceUnavailable,
                    "Webhook signing is not configured.");
            }
            return;
        }

        var signature = headers[options.SignatureHeader].ToString();
        if (signature.Length == 0)
        {
            throw new WebhookRejectionException(StatusCodes.Status401Unauthorized, "Missing webhook signature.");
        }

        var timestamp = headers[options.TimestampHeader].ToString();
        var signedValues = new List<byte[]> { body };
        if (timestamp.Length > 0)
        {
            if (!double.TryParse(timestamp, NumberStyles.Float, CultureInfo.InvariantCulture, out var seconds)
                || !double.IsFinite(seconds)
                || Math.Abs(now.ToUnixTimeMilliseconds() / 1000d - seconds) > options.ReplayWindowSeconds)
            {
                throw new WebhookRejectionException(StatusCodes.Status401Unauthorized,
                    "Invalid or expired webhook timestamp.");
            }
            var prefix = Encoding.UTF8.GetBytes($"{timestamp}.");
            var timestampBody = new byte[prefix.Length + body.Length];
            prefix.CopyTo(timestampBody, 0);
            body.CopyTo(timestampBody, prefix.Length);
            signedValues.Insert(0, timestampBody);
        }
        else if (options.ReplayWindowSeconds > 0)
        {
            throw new WebhookRejectionException(StatusCodes.Status401Unauthorized, "Missing webhook timestamp.");
        }

        var supplied = signature.StartsWith("sha256=", StringComparison.Ordinal)
            ? signature[7..].Trim()
            : signature.Trim();
        var key = Encoding.UTF8.GetBytes(options.HmacSecret);
        var suppliedBytes = Encoding.ASCII.GetBytes(supplied);
        if (!signedValues.Any(value => CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(Convert.ToHexString(HMACSHA256.HashData(key, value)).ToLowerInvariant()),
                suppliedBytes)))
        {
            throw new WebhookRejectionException(StatusCodes.Status401Unauthorized, "Invalid webhook signature.");
        }

        if (timestamp.Length > 0) RecordNonce(timestamp, supplied, now);
    }

    private void RecordNonce(string timestamp, string signature, DateTimeOffset now)
    {
        lock (_sync)
        {
            foreach (var expired in _seen.Where(entry => (now - entry.Value).TotalSeconds > options.ReplayWindowSeconds)
                         .Select(entry => entry.Key).ToArray())
            {
                _seen.Remove(expired);
            }
            var nonce = $"{timestamp}:{signature}";
            if (_seen.ContainsKey(nonce))
            {
                throw new WebhookRejectionException(StatusCodes.Status409Conflict, "Replayed webhook request.");
            }
            if (_seen.Count >= MaxReplayEntries)
            {
                var oldest = _seen.OrderBy(entry => entry.Value).Take(_seen.Count - MaxReplayEntries + 1)
                    .Select(entry => entry.Key).ToArray();
                foreach (var key in oldest) _seen.Remove(key);
            }
            _seen[nonce] = now;
        }
    }
}
