using System.Text.Json;
using Microsoft.AspNetCore.Http.Features;
using NocIfc.Application.Abstractions.AIOps;
using NocIfc.Application.Abstractions.BackupRestore;
using NocIfc.Application.Features.AIOps;
using NocIfc.Infrastructure.BackupRestore;
using NocIfc.Infrastructure.Persistence.Sqlite;
using NocIfc.Webhook;

var builder = WebApplication.CreateBuilder(args);
var databaseUrl = builder.Configuration["DATABASE_URL"]
    ?? throw new InvalidOperationException("DATABASE_URL is required.");
var security = WebhookSecurityOptions.FromConfiguration(builder.Configuration);

builder.Services.AddSingleton(new SqliteConnectionFactory(databaseUrl));
builder.Services.AddSingleton<IRestoreMaintenanceControl, SqliteRestoreMaintenanceControl>();
builder.Services.AddSingleton<SqliteReadinessProbe>();
builder.Services.AddSingleton<WebhookReadinessState>();
builder.Services.AddSingleton(security);
builder.Services.AddSingleton<WebhookSignatureVerifier>();
builder.Services.AddSingleton<SolarWindsWebhookQueue>();
builder.Services.AddScoped<ISolarWindsWebhookStore, SqliteSolarWindsWebhookStore>();
builder.Services.AddScoped<SolarWindsWebhookCommands>();
builder.Services.AddHostedService<SolarWindsWebhookProcessor>();
builder.Services.AddHostedService<SolarWindsWebhookStatusWorker>();

var app = builder.Build();
app.MapGet("/health", () => Results.Ok(new { status = "ok" }));
app.MapPost("/webhook/solarwinds", async (
    HttpContext context,
    WebhookSecurityOptions options,
    WebhookSignatureVerifier signatures,
    SolarWindsWebhookQueue queue,
    WebhookReadinessState readiness,
    IRestoreMaintenanceControl restore,
    ILogger<Program> logger) =>
{
    try
    {
        if (restore.MaintenanceRequested)
        {
            return Results.Json(new { detail = "Database restore in progress." }, statusCode: StatusCodes.Status503ServiceUnavailable);
        }
        if (!readiness.IsReady)
        {
            return Results.Json(new { detail = "Webhook database is not ready." }, statusCode: StatusCodes.Status503ServiceUnavailable);
        }
        var sizeLimit = context.Features.Get<IHttpMaxRequestBodySizeFeature>();
        if (sizeLimit is { IsReadOnly: false }) sizeLimit.MaxRequestBodySize = options.MaxBodyBytes;
        if (context.Request.ContentLength is { } contentLength && contentLength > options.MaxBodyBytes)
        {
            return Results.Json(new { detail = "Webhook payload too large." }, statusCode: StatusCodes.Status413PayloadTooLarge);
        }

        var body = await ReadBodyAsync(context.Request.Body, options.MaxBodyBytes, context.RequestAborted);
        signatures.Verify(context.Request.Headers, body, DateTimeOffset.UtcNow);
        using (var document = JsonDocument.Parse(body))
        {
            if (document.RootElement.ValueKind != JsonValueKind.Object
                || !document.RootElement.EnumerateObject().Any())
            {
                return Results.Json(new { detail = "Webhook payload must be a non-empty JSON object." },
                    statusCode: StatusCodes.Status422UnprocessableEntity);
            }
            if (document.RootElement.EnumerateObject().Take(101).Count() > 100)
            {
                return Results.Json(new { detail = "Webhook payload has too many fields." },
                    statusCode: StatusCodes.Status422UnprocessableEntity);
            }
        }

        if (!queue.TryEnqueue(body, restore))
        {
            var detail = restore.MaintenanceRequested
                ? "Database restore in progress."
                : "Webhook processing queue is full.";
            return Results.Json(new { detail }, statusCode: StatusCodes.Status503ServiceUnavailable);
        }
        return Results.Ok(new { status = "accepted", message = "Payload queued for AI processing." });
    }
    catch (WebhookRejectionException exception)
    {
        return Results.Json(new { detail = exception.Message }, statusCode: exception.StatusCode);
    }
    catch (JsonException)
    {
        return Results.Json(new { detail = "Invalid JSON payload." }, statusCode: StatusCodes.Status400BadRequest);
    }
    catch (WebhookBodyTooLargeException)
    {
        return Results.Json(new { detail = "Webhook payload too large." }, statusCode: StatusCodes.Status413PayloadTooLarge);
    }
    catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested)
    {
        throw;
    }
    catch (Exception exception)
    {
        logger.LogError(exception, "SolarWinds webhook gateway failed before queueing.");
        return Results.Json(new { detail = "Internal Gateway Error." }, statusCode: StatusCodes.Status500InternalServerError);
    }
});

app.Run();

static async Task<byte[]> ReadBodyAsync(Stream source, int maximumBytes, CancellationToken cancellationToken)
{
    using var buffer = new MemoryStream(Math.Min(maximumBytes, 64 * 1024));
    var chunk = new byte[16 * 1024];
    while (true)
    {
        var read = await source.ReadAsync(chunk, cancellationToken);
        if (read == 0) return buffer.ToArray();
        if (buffer.Length + read > maximumBytes) throw new WebhookBodyTooLargeException();
        buffer.Write(chunk, 0, read);
    }
}

public sealed class WebhookBodyTooLargeException : Exception { }
public partial class Program { }
