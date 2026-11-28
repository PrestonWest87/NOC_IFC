using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using NocIfc.Application.Features.AIOps;
using NocIfc.Infrastructure.BackupRestore;
using NocIfc.Infrastructure.Persistence.Sqlite;
using NocIfc.Domain.AIOps;
using NocIfc.Webhook;
using Xunit;

namespace NocIfc.Api.Tests;

public sealed class WebhookGatewayTests
{
    [Fact]
    public void AcceptsTimestampPrefixAndLegacyBodyOnlyHmacThenRejectsReplay()
    {
        const string secret = "solarwinds-test-secret";
        var now = DateTimeOffset.FromUnixTimeSeconds(1_780_000_000);
        var body = Encoding.UTF8.GetBytes("{\"AlertName\":\"Node Down\"}");
        var timestamp = now.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
        var prefixedSignature = Sign(secret, [.. Encoding.UTF8.GetBytes($"{timestamp}."), .. body]);
        var options = Options(secret);
        var verifier = new WebhookSignatureVerifier(options);
        var headers = new HeaderDictionary
        {
            [options.TimestampHeader] = timestamp,
            [options.SignatureHeader] = $"sha256={prefixedSignature}",
        };

        verifier.Verify(headers, body, now);
        var replay = Assert.Throws<WebhookRejectionException>(() => verifier.Verify(headers, body, now));
        Assert.Equal(StatusCodes.Status409Conflict, replay.StatusCode);

        var legacyHeaders = new HeaderDictionary
        {
            [options.TimestampHeader] = timestamp,
            [options.SignatureHeader] = Sign(secret, body),
        };
        new WebhookSignatureVerifier(options).Verify(legacyHeaders, body, now);
    }

    [Fact]
    public void RejectsUnsignedRequestsUnlessTheMigrationSwitchIsEnabled()
    {
        var body = Encoding.UTF8.GetBytes("{}");
        var blocked = Assert.Throws<WebhookRejectionException>(() =>
            new WebhookSignatureVerifier(Options("", allowUnsigned: false))
                .Verify(new HeaderDictionary(), body, DateTimeOffset.UtcNow));
        Assert.Equal(StatusCodes.Status503ServiceUnavailable, blocked.StatusCode);

        new WebhookSignatureVerifier(Options("", allowUnsigned: true))
            .Verify(new HeaderDictionary(), body, DateTimeOffset.UtcNow);
    }

    [Fact]
    public void RejectsInvalidSignaturesAndExpiredTimestamps()
    {
        const string secret = "solarwinds-test-secret";
        var now = DateTimeOffset.FromUnixTimeSeconds(1_780_000_000);
        var body = Encoding.UTF8.GetBytes("{}");
        var options = Options(secret);
        var verifier = new WebhookSignatureVerifier(options);
        var expiredTimestamp = (now.ToUnixTimeSeconds() - 301).ToString(CultureInfo.InvariantCulture);
        var expiredHeaders = new HeaderDictionary
        {
            [options.TimestampHeader] = expiredTimestamp,
            [options.SignatureHeader] = Sign(secret, [.. Encoding.UTF8.GetBytes($"{expiredTimestamp}."), .. body]),
        };
        var expired = Assert.Throws<WebhookRejectionException>(() => verifier.Verify(expiredHeaders, body, now));
        Assert.Equal(StatusCodes.Status401Unauthorized, expired.StatusCode);

        var invalidHeaders = new HeaderDictionary
        {
            [options.TimestampHeader] = now.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture),
            [options.SignatureHeader] = new string('0', 64),
        };
        var invalid = Assert.Throws<WebhookRejectionException>(() => verifier.Verify(invalidHeaders, body, now));
        Assert.Equal(StatusCodes.Status401Unauthorized, invalid.StatusCode);
    }

    [Fact]
    public void NormalizesSolarWindsFieldsAndResolutionSignals()
    {
        using var payload = JsonDocument.Parse("""
            {
              "Node_Details": {
                "NodeName": "router-a",
                "IP_Address": "10.20.30.40",
                "MachineType": "Cisco Router",
                "StatusDescription": "Operational"
              },
              "severity": "Critical",
              "Alert_Level": "P1 - High",
              "AlertName": "Link Recovered",
              "description": "The service is now recovered.",
              "Custom_Properties_Universal": {
                "Site": "Central NOC",
                "Primary_Comms": "Fiber",
                "Secondary_Comms": "LTE"
              }
            }
            """);

        var normalized = SolarWindsWebhookNormalizer.Normalize(payload.RootElement);
        var raw = SolarWindsWebhookNormalizer.AddNormalizedAlertLevel(payload.RootElement, normalized.AlertLevel);

        Assert.Equal("router-a", normalized.NodeName);
        Assert.Equal("10.20.30.40", normalized.IpAddress);
        Assert.Equal("Critical", normalized.Severity);
        Assert.Equal("P1 - High", normalized.AlertLevel);
        Assert.Equal("Link Recovered", normalized.EventType);
        Assert.Equal("Central NOC", normalized.SiteName);
        Assert.Equal("Resolved", normalized.Status);
        Assert.True(normalized.IsResolution);
        Assert.Equal("P1 - High", raw["Normalized_Alert_Level"]!.GetValue<string>());
    }

    [Fact]
    public void DoesNotTreatNegatedOperationalStatusAsRecovery()
    {
        using var payload = JsonDocument.Parse("""
            {
              "Node_Details": {
                "NodeName": "router-a",
                "StatusDescription": "Not operational"
              },
              "description": "The device is not currently operational."
            }
            """);

        var normalized = SolarWindsWebhookNormalizer.Normalize(payload.RootElement);

        Assert.False(normalized.IsResolution);
        Assert.Equal("Not operational", normalized.Status);
    }

    [Fact]
    public void WebhookQueueIsBoundedAndRejectsNewWorkDuringRestore()
    {
        using var workspace = new TemporaryDirectory();
        var databasePath = Path.Combine(workspace.Path, "database.sqlite");
        using (File.Create(databasePath)) { }
        var control = new SqliteRestoreMaintenanceControl(new SqliteConnectionFactory($"sqlite:///{databasePath}"));
        var queue = new SolarWindsWebhookQueue(Options("", allowUnsigned: true) with { MaxBodyBytes = 16 * 1024 * 1024 });

        Assert.True(queue.TryEnqueue([1], control));
        Assert.True(queue.TryEnqueue([2], control));
        Assert.True(queue.TryEnqueue([3], control));
        Assert.True(queue.TryEnqueue([4], control));
        Assert.False(queue.TryEnqueue([5], control));
        Assert.Equal(4, queue.Pending);
        queue.CompleteOne();
        Assert.Equal(3, queue.Pending);

        control.BeginRestore("stage-0123456789abcdef0123456789abcdef.nocbackup", "admin");
        Assert.False(queue.TryEnqueue([6], control));
    }

    [Fact]
    public void ReadinessProbeCannotStartDuringRestoreAndTracksActiveProbe()
    {
        using var workspace = new TemporaryDirectory();
        var databasePath = Path.Combine(workspace.Path, "database.sqlite");
        using (File.Create(databasePath)) { }
        var control = new SqliteRestoreMaintenanceControl(new SqliteConnectionFactory($"sqlite:///{databasePath}"));
        var readiness = new WebhookReadinessState();

        Assert.False(readiness.IsReady);
        Assert.True(readiness.TryBeginProbe(control));
        Assert.Equal(1, readiness.ActiveProbes);
        readiness.EndProbe();
        Assert.Equal(0, readiness.ActiveProbes);

        control.BeginRestore("stage-0123456789abcdef0123456789abcdef.nocbackup", "admin");
        Assert.False(readiness.TryBeginProbe(control));
        Assert.Equal(0, readiness.ActiveProbes);
    }

    private static WebhookSecurityOptions Options(string secret, bool allowUnsigned = false) =>
        new(secret, "X-SolarWinds-Signature", "X-SolarWinds-Timestamp", 300, 1024 * 1024, allowUnsigned);

    private static string Sign(string secret, byte[] data) =>
        Convert.ToHexString(HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), data)).ToLowerInvariant();

    private sealed class TemporaryDirectory : IDisposable
    {
        public string Path { get; } = Directory.CreateTempSubdirectory("nocifc-webhook-").FullName;
        public void Dispose() => Directory.Delete(Path, true);
    }
}
