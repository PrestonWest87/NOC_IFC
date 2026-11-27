using System.Collections.Concurrent;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using NocIfc.Api.Contracts;
using NocIfc.Application.Abstractions.BackupRestore;
using NocIfc.Application.Abstractions.Identity;
using NocIfc.Application.Features.AIOps;
using NocIfc.Domain.Identity;

namespace NocIfc.Api.Services;

public sealed class AiopsWebSocketHub(
    IServiceScopeFactory scopes,
    IRestoreMaintenanceControl restore,
    IConfiguration configuration,
    ILogger<AiopsWebSocketHub> logger) : BackgroundService
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly TimeSpan BroadcastInterval = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan RevalidationInterval = TimeSpan.FromSeconds(30);
    private static readonly WebSocketCloseStatus ServiceRestart = (WebSocketCloseStatus)1012;
    private readonly ConcurrentDictionary<Guid, Client> _clients = new();
    private readonly int _maxMessageBytes = ReadMaxMessageBytes(configuration["WEBSOCKET_MAX_MESSAGE_BYTES"]);

    public int Count => _clients.Count;

    public static bool HasBoardAccess(AuthenticatedUser? user) =>
        user is not null && (user.IsAdministrator
            || user.AllowedPages.Contains("AIOps RCA", StringComparer.Ordinal)
            && user.AllowedActions.Contains("Tab: AIOps RCA -> Active Board", StringComparer.Ordinal));

    public static string? RequiredCommandAction(string? messageType) => messageType switch
    {
        "INVESTIGATING_UPDATE" or "RCA_UPDATE" => "Action: Dispatch RCA Tickets",
        _ => null,
    };

    public async Task HandleAsync(HttpContext context)
    {
        if (!context.WebSockets.IsWebSocketRequest)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }

        var socket = await context.WebSockets.AcceptWebSocketAsync();
        Client? client = null;
        try
        {
            if (restore.MaintenanceRequested || !restore.TryBeginApiBackgroundWriter())
            {
                await CloseUnregisteredAsync(socket, ServiceRestart, "Database restore in progress");
                return;
            }

            AuthenticatedUser? user;
            var token = context.Request.Query["token"].ToString();
            try
            {
                user = await ResolveUserAsync(token, context.RequestAborted);
            }
            finally
            {
                restore.EndApiBackgroundWriter();
            }

            if (!HasBoardAccess(user))
            {
                await CloseUnregisteredAsync(socket, WebSocketCloseStatus.PolicyViolation,
                    "AIOps Active Board permission required");
                return;
            }

            client = new Client(socket, token, user!);
            if (restore.MaintenanceRequested || !_clients.TryAdd(client.Id, client))
            {
                await CloseClientAsync(client, ServiceRestart, "Database restore in progress", context.RequestAborted);
                return;
            }
            if (restore.MaintenanceRequested)
            {
                await CloseClientAsync(client, ServiceRestart, "Database restore in progress", context.RequestAborted);
                return;
            }

            using var revalidation = CancellationTokenSource.CreateLinkedTokenSource(context.RequestAborted);
            var revalidationTask = RevalidateAsync(client, revalidation.Token);
            try
            {
                await ReceiveAsync(client, context.RequestAborted);
            }
            finally
            {
                revalidation.Cancel();
                try { await revalidationTask; }
                catch (OperationCanceledException) { }
            }
        }
        catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested)
        {
        }
        catch (WebSocketException exception)
        {
            logger.LogDebug(exception, "AIOps WebSocket disconnected.");
        }
        catch (Exception exception)
        {
            logger.LogWarning(exception, "AIOps WebSocket handler failed.");
        }
        finally
        {
            if (client is not null) _clients.TryRemove(client.Id, out _);
            if (socket.State is not (WebSocketState.Closed or WebSocketState.Aborted)) socket.Abort();
            socket.Dispose();
        }
    }

    public Task BroadcastRefreshAsync(CancellationToken cancellationToken = default) =>
        BroadcastAsync(JsonSerializer.SerializeToUtf8Bytes(new { type = "RCA_UPDATE" }, JsonOptions),
            _ => true, cancellationToken);

    public async Task CloseAllAsync(
        WebSocketCloseStatus closeStatus = default,
        string reason = "Service maintenance",
        CancellationToken cancellationToken = default)
    {
        if (closeStatus == default) closeStatus = ServiceRestart;
        await Task.WhenAll(_clients.Values.ToArray().Select(client =>
            CloseClientAsync(client, closeStatus, reason, cancellationToken)));
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(BroadcastInterval);
        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken))
            {
                if (restore.MaintenanceRequested || _clients.IsEmpty || !restore.TryBeginApiBackgroundWriter())
                {
                    continue;
                }
                try
                {
                    await BroadcastDashboardAsync(stoppingToken);
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    break;
                }
                catch (Exception exception)
                {
                    logger.LogWarning(exception, "AIOps WebSocket dashboard broadcast failed.");
                }
                finally
                {
                    restore.EndApiBackgroundWriter();
                }
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
    }

    private async Task BroadcastDashboardAsync(CancellationToken cancellationToken)
    {
        var clients = _clients.Values.Where(client => !client.IsClosing && HasBoardAccess(client.User)).ToArray();
        if (clients.Length == 0) return;

        await using var scope = scopes.CreateAsyncScope();
        var dashboard = scope.ServiceProvider.GetRequiredService<AiopsDashboardQueries>();
        foreach (var userClients in clients.GroupBy(client => client.User.Id))
        {
            var user = userClients.First().User;
            var snapshot = await dashboard.GetBoardAsync(user, cancellationToken);
            var payload = JsonSerializer.SerializeToUtf8Bytes(new
            {
                type = "dashboard_update",
                alerts = snapshot.Alerts.Select(AiopsAlertResponse.From).ToArray(),
                events = snapshot.Events.Select(AiopsTimelineEventResponse.From).ToArray(),
                grid = snapshot.Grid.Select(AiopsRegionalOutageResponse.From).ToArray(),
                active_issue_counts = snapshot.ActiveIssueCounts,
                alert_count = snapshot.Alerts.Count,
            }, JsonOptions);
            await BroadcastAsync(payload, client => userClients.Any(item => item.Id == client.Id), cancellationToken);
        }
    }

    private async Task ReceiveAsync(Client client, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested && !client.IsClosing)
        {
            if (restore.MaintenanceRequested)
            {
                await CloseClientAsync(client, ServiceRestart, "Database restore in progress", cancellationToken);
                return;
            }

            string? message;
            try
            {
                message = await ReceiveTextAsync(client.Socket, cancellationToken);
            }
            catch (SocketMessageException exception)
            {
                await CloseClientAsync(client, exception.CloseStatus, exception.Message, cancellationToken);
                return;
            }
            if (message is null)
            {
                await CloseClientAsync(client, WebSocketCloseStatus.NormalClosure,
                    "", cancellationToken);
                return;
            }

            if (!restore.TryBeginApiBackgroundWriter())
            {
                await CloseClientAsync(client, ServiceRestart, "Database restore in progress", cancellationToken);
                return;
            }
            try
            {
                var user = await ResolveUserAsync(client.Token, cancellationToken);
                if (!HasBoardAccess(user))
                {
                    await CloseClientAsync(client, WebSocketCloseStatus.PolicyViolation,
                        "AIOps permission revoked", cancellationToken);
                    return;
                }
                client.User = user!;
                await ProcessCommandAsync(client, message, cancellationToken);
            }
            finally
            {
                restore.EndApiBackgroundWriter();
            }
        }
    }

    private async Task RevalidateAsync(Client client, CancellationToken cancellationToken)
    {
        try
        {
            while (!cancellationToken.IsCancellationRequested && !client.IsClosing)
            {
                await Task.Delay(RevalidationInterval, cancellationToken);
                if (restore.MaintenanceRequested || !restore.TryBeginApiBackgroundWriter())
                {
                    await CloseClientAsync(client, ServiceRestart, "Database restore in progress", cancellationToken);
                    return;
                }
                try
                {
                    var user = await ResolveUserAsync(client.Token, cancellationToken);
                    if (!HasBoardAccess(user))
                    {
                        await CloseClientAsync(client, WebSocketCloseStatus.PolicyViolation,
                            "AIOps permission revoked", cancellationToken);
                        return;
                    }
                    client.User = user!;
                }
                finally
                {
                    restore.EndApiBackgroundWriter();
                }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception exception)
        {
            logger.LogWarning(exception, "AIOps WebSocket session revalidation failed.");
            await CloseClientAsync(client, WebSocketCloseStatus.InternalServerError,
                "Unable to revalidate session.", CancellationToken.None);
        }
    }

    private async Task ProcessCommandAsync(Client client, string message, CancellationToken cancellationToken)
    {
        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(message);
        }
        catch (JsonException)
        {
            return;
        }
        using (document)
        {
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return;
            var messageType = root.TryGetProperty("type", out var typeValue)
                && typeValue.ValueKind == JsonValueKind.String
                    ? typeValue.GetString()
                    : null;
            var requiredAction = RequiredCommandAction(messageType);
            if (requiredAction is null || !HasAction(client.User, requiredAction))
            {
                if (!await SendAsync(client, new
                {
                    type = "error",
                    code = "permission_denied",
                    permission = requiredAction,
                    message = "You do not have permission to send this command.",
                }, cancellationToken))
                {
                    DropClient(client);
                }
                return;
            }
            if (root.EnumerateObject().Select(property => property.Name)
                .Distinct(StringComparer.Ordinal).Take(11).Count() > 10)
            {
                return;
            }

            string? site = null;
            if (messageType == "INVESTIGATING_UPDATE")
            {
                site = root.TryGetProperty("site", out var siteValue) && siteValue.ValueKind != JsonValueKind.Null
                    ? siteValue.ToString()
                    : "";
                if (!await CanAccessSiteAsync(client.User, site, cancellationToken))
                {
                    if (!await SendAsync(client, new
                    {
                        type = "error",
                        code = "site_scope_denied",
                        message = "This site is outside your permitted site types.",
                    }, cancellationToken))
                    {
                        DropClient(client);
                    }
                    return;
                }
            }

            var payload = JsonSerializer.SerializeToUtf8Bytes(root.Clone(), JsonOptions);
            var recipients = _clients.Values.Where(recipient =>
                !recipient.IsClosing && HasBoardAccess(recipient.User)).ToArray();
            if (site is null)
            {
                await BroadcastAsync(payload, recipient => recipients.Any(item => item.Id == recipient.Id), cancellationToken);
                return;
            }

            var permitted = await Task.WhenAll(recipients.Select(async recipient =>
                (Client: recipient, Allowed: await CanAccessSiteAsync(recipient.User, site, cancellationToken))));
            await BroadcastAsync(payload, recipient => permitted.Any(item =>
                item.Client.Id == recipient.Id && item.Allowed), cancellationToken);
        }
    }

    private async Task BroadcastAsync(byte[] payload, Func<Client, bool> include, CancellationToken cancellationToken)
    {
        var sends = _clients.Values.ToArray().Where(include).Select(async client =>
        {
            if (!await SendBytesAsync(client, payload, cancellationToken))
            {
                DropClient(client);
            }
        });
        await Task.WhenAll(sends);
    }

    private async Task<bool> SendAsync(Client client, object payload, CancellationToken cancellationToken) =>
        await SendBytesAsync(client, JsonSerializer.SerializeToUtf8Bytes(payload, JsonOptions), cancellationToken);

    private void DropClient(Client client)
    {
        client.TryBeginClosing();
        client.Socket.Abort();
        _clients.TryRemove(client.Id, out _);
    }

    private static async Task<bool> SendBytesAsync(Client client, byte[] payload, CancellationToken cancellationToken)
    {
        if (client.IsClosing || client.Socket.State != WebSocketState.Open) return false;
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(3));
        try
        {
            await client.SendLock.WaitAsync(timeout.Token);
            try
            {
                if (client.IsClosing || client.Socket.State != WebSocketState.Open) return false;
                await client.Socket.SendAsync(new ArraySegment<byte>(payload), WebSocketMessageType.Text,
                    endOfMessage: true, timeout.Token);
                return true;
            }
            finally
            {
                client.SendLock.Release();
            }
        }
        catch (Exception exception) when (exception is OperationCanceledException or WebSocketException
            or ObjectDisposedException or InvalidOperationException)
        {
            return false;
        }
    }

    private async Task CloseClientAsync(
        Client client,
        WebSocketCloseStatus closeStatus,
        string reason,
        CancellationToken cancellationToken)
    {
        if (!client.TryBeginClosing()) return;
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(3));
        try
        {
            await client.SendLock.WaitAsync(timeout.Token);
            try
            {
                if (client.Socket.State is WebSocketState.Open or WebSocketState.CloseReceived)
                {
                    await client.Socket.CloseOutputAsync(closeStatus, reason, timeout.Token);
                }
            }
            finally
            {
                client.SendLock.Release();
            }
        }
        catch (Exception exception)
        {
            logger.LogDebug(exception, "Unable to send WebSocket close frame.");
            client.Socket.Abort();
        }
        finally
        {
            _clients.TryRemove(client.Id, out _);
        }
    }

    private static async Task CloseUnregisteredAsync(
        WebSocket socket,
        WebSocketCloseStatus closeStatus,
        string reason)
    {
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
            if (socket.State is WebSocketState.Open or WebSocketState.CloseReceived)
            {
                await socket.CloseAsync(closeStatus, reason, timeout.Token);
            }
        }
        catch (Exception)
        {
            socket.Abort();
        }
    }

    private async Task<bool> CanAccessSiteAsync(
        AuthenticatedUser user,
        string site,
        CancellationToken cancellationToken)
    {
        if (user.IsAdministrator) return true;
        await using var scope = scopes.CreateAsyncScope();
        var dashboard = scope.ServiceProvider.GetRequiredService<AiopsDashboardQueries>();
        var sites = await dashboard.GetSitesAsync(user, cancellationToken);
        return sites.Any(location => string.Equals(location.Name, site, StringComparison.Ordinal));
    }

    private async Task<AuthenticatedUser?> ResolveUserAsync(string token, CancellationToken cancellationToken)
    {
        await using var scope = scopes.CreateAsyncScope();
        var sessions = scope.ServiceProvider.GetRequiredService<IUserSessionResolver>();
        return await sessions.ResolveAsync(token, cancellationToken);
    }

    private static bool HasAction(AuthenticatedUser user, string action) =>
        user.IsAdministrator || user.AllowedActions.Contains(action, StringComparer.Ordinal);

    private async Task<string?> ReceiveTextAsync(WebSocket socket, CancellationToken cancellationToken)
    {
        using var message = new MemoryStream();
        var buffer = new byte[4096];
        while (true)
        {
            var result = await socket.ReceiveAsync(new ArraySegment<byte>(buffer), cancellationToken);
            if (result.MessageType == WebSocketMessageType.Close) return null;
            if (result.MessageType != WebSocketMessageType.Text)
            {
                throw new SocketMessageException(WebSocketCloseStatus.InvalidMessageType, "Text messages are required.");
            }
            if (message.Length + result.Count > _maxMessageBytes)
            {
                throw new SocketMessageException(WebSocketCloseStatus.MessageTooBig, "Message too large");
            }
            message.Write(buffer, 0, result.Count);
            if (result.EndOfMessage) break;
        }
        try
        {
            return StrictUtf8.GetString(message.GetBuffer(), 0, checked((int)message.Length));
        }
        catch (DecoderFallbackException exception)
        {
            throw new SocketMessageException(WebSocketCloseStatus.InvalidPayloadData,
                "Message is not valid UTF-8.", exception);
        }
    }

    private static int ReadMaxMessageBytes(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return 65_536;
        if (!int.TryParse(value, out var maximum) || maximum <= 0)
        {
            throw new InvalidOperationException("WEBSOCKET_MAX_MESSAGE_BYTES must be a positive integer.");
        }
        return maximum;
    }

    private sealed class Client(WebSocket socket, string token, AuthenticatedUser user)
    {
        private AuthenticatedUser _user = user;
        private int _closing;

        public Guid Id { get; } = Guid.NewGuid();
        public WebSocket Socket { get; } = socket;
        public string Token { get; } = token;
        public AuthenticatedUser User
        {
            get => Volatile.Read(ref _user);
            set => Volatile.Write(ref _user, value);
        }
        public SemaphoreSlim SendLock { get; } = new(1, 1);
        public bool IsClosing => Volatile.Read(ref _closing) != 0;
        public bool TryBeginClosing() => Interlocked.Exchange(ref _closing, 1) == 0;
    }

    private sealed class SocketMessageException(
        WebSocketCloseStatus closeStatus,
        string message,
        Exception? innerException = null) : Exception(message, innerException)
    {
        public WebSocketCloseStatus CloseStatus { get; } = closeStatus;
    }
}
