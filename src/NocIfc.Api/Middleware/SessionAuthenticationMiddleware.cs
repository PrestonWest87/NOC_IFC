using System.Text.Json;
using NocIfc.Api.Authentication;
using NocIfc.Application.Abstractions.BackupRestore;
using NocIfc.Application.Abstractions.Identity;

namespace NocIfc.Api.Middleware;

public sealed class SessionAuthenticationMiddleware(
    RequestDelegate next,
    ILogger<SessionAuthenticationMiddleware> logger)
{
    private static readonly HashSet<string> PublicRoutes = new(StringComparer.Ordinal)
    {
        "/api/v1/auth/login",
        "/api/v1/auth/register",
        "/api/v1/auth/register/validate",
        "/api/v1/auth/request-password-reset",
        "/api/v1/auth/reset-password",
        "/api/v1/auth/verify-recovery-email",
        "/api/v1/restore-status",
    };

    public async Task InvokeAsync(
        HttpContext context,
        IUserSessionResolver sessions,
        IRestoreMaintenanceControl? restore = null)
    {
        var path = context.Request.Path.Value?.TrimEnd('/') ?? string.Empty;
        var apiPath = path.StartsWith("/api/v1", StringComparison.Ordinal);
        var restoreStart = path.StartsWith("/api/v1/admin/backups/staged/", StringComparison.Ordinal)
            && path.EndsWith("/restore", StringComparison.Ordinal);
        var maintenanceExempt = path is "/health" or "/ready" or "/api/v1/restore-status" || restoreStart;
        if (restore?.MaintenanceRequested == true && apiPath && !maintenanceExempt)
        {
            await WriteRestoreInProgress(context, "A full database restore is in progress. Retry after maintenance completes.");
            return;
        }

        var trackRequest = HttpMethods.IsOptions(context.Request.Method) is false
            && apiPath && path != "/ready" && path != "/api/v1/restore-status" && !restoreStart;
        if (trackRequest && restore is not null && !restore.TryBeginApiRequest())
        {
            await WriteRestoreInProgress(context, "A full database restore is in progress. Retry after maintenance completes.");
            return;
        }

        try
        {
            if (HttpMethods.IsOptions(context.Request.Method)
                || !apiPath
                || PublicRoutes.Contains(path))
            {
                await next(context);
                return;
            }

            var token = TokenFromRequest(context, path);
            var user = await sessions.ResolveAsync(token, context.RequestAborted);
            if (user is null)
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await context.Response.WriteAsJsonAsync(
                    new { detail = new { code = "unauthenticated", message = "Not authenticated" } },
                    context.RequestAborted);
                return;
            }

            AuthenticatedUserContext.Set(context, user, token);
            logger.LogDebug("Authenticated API request for user id {UserId}.", user.Id);
            await next(context);
        }
        finally
        {
            if (trackRequest) restore?.EndApiRequest();
        }
    }

    private static Task WriteRestoreInProgress(HttpContext context, string message)
    {
        context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
        context.Response.Headers.RetryAfter = "5";
        return context.Response.WriteAsJsonAsync(
            new { detail = new { code = "restore_in_progress", message } }, context.RequestAborted);
    }

    private static string TokenFromRequest(HttpContext context, string path)
    {
        var authorization = context.Request.Headers["Authorization"].ToString();
        if (authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            return authorization[7..].Trim();
        }

        if (path.StartsWith("/api/v1/admin/backups/", StringComparison.Ordinal)
            && path.EndsWith("/download", StringComparison.Ordinal))
        {
            var downloadToken = context.Request.Cookies["noc_backup_download"];
            if (!string.IsNullOrEmpty(downloadToken))
            {
                return downloadToken;
            }
        }

        return context.Request.Query["token"].ToString()
            is { Length: > 0 } token
                ? token
                : context.Request.Query["session_token"].ToString();
    }
}
