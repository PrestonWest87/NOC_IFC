using System.Collections.Concurrent;
using System.Net.WebSockets;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using NocIfc.Api.Services;
using NocIfc.Application.Abstractions.Identity;
using NocIfc.Domain.Identity;
using NocIfc.Infrastructure.BackupRestore;
using NocIfc.Infrastructure.Persistence.Sqlite;
using Xunit;

namespace NocIfc.Api.Tests;

public sealed class AiopsWebSocketHubTests
{
    [Fact]
    public void BoardAccessRequiresPageAndActiveBoardUnlessAdministrator()
    {
        var pageOnly = User(["AIOps RCA"], []);
        var tabOnly = User([], ["Tab: AIOps RCA -> Active Board"]);
        var fullyGranted = User(["AIOps RCA"], ["Tab: AIOps RCA -> Active Board"]);
        var administrator = new AuthenticatedUser(4, "admin", "administrator", [], [], []);

        Assert.False(AiopsWebSocketHub.HasBoardAccess(null));
        Assert.False(AiopsWebSocketHub.HasBoardAccess(pageOnly));
        Assert.False(AiopsWebSocketHub.HasBoardAccess(tabOnly));
        Assert.True(AiopsWebSocketHub.HasBoardAccess(fullyGranted));
        Assert.True(AiopsWebSocketHub.HasBoardAccess(administrator));
        Assert.Equal("Action: Dispatch RCA Tickets",
            AiopsWebSocketHub.RequiredCommandAction("RCA_UPDATE"));
        Assert.Null(AiopsWebSocketHub.RequiredCommandAction("UNSUPPORTED"));
    }

    [Theory]
    [InlineData(false, "permission_denied")]
    [InlineData(true, "RCA_UPDATE")]
    public async Task WebSocketRevalidatesAndAuthorizesCommands(bool mayDispatch, string expectedMessage)
    {
        using var workspace = new TemporaryDirectory("nocifc-ws-");
        var databasePath = Path.Combine(workspace.Path, "database.sqlite");
        using (File.Create(databasePath)) { }
        var control = new SqliteRestoreMaintenanceControl(
            new SqliteConnectionFactory($"sqlite:///{databasePath}"));
        var actions = new List<string>();
        if (mayDispatch) actions.Add("Action: Dispatch RCA Tickets");
        var user = User(["AIOps RCA"], ["Tab: AIOps RCA -> Active Board", .. actions]);
        var resolver = new StubSessionResolver(user);
        var services = new ServiceCollection()
            .AddSingleton<IUserSessionResolver>(resolver)
            .BuildServiceProvider();
        var hub = new AiopsWebSocketHub(
            services.GetRequiredService<IServiceScopeFactory>(),
            control,
            new ConfigurationBuilder().Build(),
            NullLogger<AiopsWebSocketHub>.Instance);
        var socket = new RecordingWebSocket(["{\"type\":\"RCA_UPDATE\"}"]);
        var context = new DefaultHttpContext();
        context.Request.QueryString = new QueryString("?token=live-session");
        context.RequestServices = services;
        context.Features.Set<IHttpWebSocketFeature>(new StubWebSocketFeature(socket));

        await hub.HandleAsync(context);

        var sent = string.Join("\n", socket.SentMessages);
        Assert.Contains(expectedMessage, sent, StringComparison.Ordinal);
        Assert.Equal(2, resolver.ResolveCount);
        Assert.Equal(0, hub.Count);
        services.Dispose();
    }

    [Fact]
    public async Task CloseAllSendsServiceRestartAndDrainsTheConnectedClient()
    {
        using var workspace = new TemporaryDirectory("nocifc-ws-close-");
        var databasePath = Path.Combine(workspace.Path, "database.sqlite");
        using (File.Create(databasePath)) { }
        var control = new SqliteRestoreMaintenanceControl(
            new SqliteConnectionFactory($"sqlite:///{databasePath}"));
        var user = User(["AIOps RCA"], ["Tab: AIOps RCA -> Active Board"]);
        var services = new ServiceCollection()
            .AddSingleton<IUserSessionResolver>(new StubSessionResolver(user))
            .BuildServiceProvider();
        var hub = new AiopsWebSocketHub(
            services.GetRequiredService<IServiceScopeFactory>(),
            control,
            new ConfigurationBuilder().Build(),
            NullLogger<AiopsWebSocketHub>.Instance);
        var socket = new RecordingWebSocket([], waitForClientClose: true);
        var context = new DefaultHttpContext();
        context.Request.QueryString = new QueryString("?token=live-session");
        context.RequestServices = services;
        context.Features.Set<IHttpWebSocketFeature>(new StubWebSocketFeature(socket));
        var connection = hub.HandleAsync(context);

        for (var attempt = 0; attempt < 50 && hub.Count == 0; attempt++)
        {
            await Task.Delay(10);
        }
        Assert.Equal(1, hub.Count);

        await hub.CloseAllAsync(reason: "Database restore in progress");
        await connection;

        Assert.Equal((WebSocketCloseStatus)1012, socket.CloseStatus);
        Assert.Equal(0, hub.Count);
        services.Dispose();
    }

    [Fact]
    public async Task ClosesWhenSessionIsRevokedBeforeACommand()
    {
        using var workspace = new TemporaryDirectory("nocifc-ws-revoked-");
        var databasePath = Path.Combine(workspace.Path, "database.sqlite");
        using (File.Create(databasePath)) { }
        var control = new SqliteRestoreMaintenanceControl(
            new SqliteConnectionFactory($"sqlite:///{databasePath}"));
        var user = User(["AIOps RCA"], ["Tab: AIOps RCA -> Active Board", "Action: Dispatch RCA Tickets"]);
        var resolver = new StubSessionResolver(user, null);
        var services = new ServiceCollection()
            .AddSingleton<IUserSessionResolver>(resolver)
            .BuildServiceProvider();
        var hub = new AiopsWebSocketHub(
            services.GetRequiredService<IServiceScopeFactory>(),
            control,
            new ConfigurationBuilder().Build(),
            NullLogger<AiopsWebSocketHub>.Instance);
        var socket = new RecordingWebSocket(["{\"type\":\"RCA_UPDATE\"}"]);
        var context = new DefaultHttpContext();
        context.Request.QueryString = new QueryString("?token=live-session");
        context.RequestServices = services;
        context.Features.Set<IHttpWebSocketFeature>(new StubWebSocketFeature(socket));

        await hub.HandleAsync(context);

        Assert.Equal(WebSocketCloseStatus.PolicyViolation, socket.CloseStatus);
        Assert.Equal(2, resolver.ResolveCount);
        Assert.Empty(socket.SentMessages);
        services.Dispose();
    }

    private static AuthenticatedUser User(IReadOnlyList<string> pages, IReadOnlyList<string> actions) =>
        new(2, "operator", "analyst", pages, actions, []);

    private sealed class StubSessionResolver(params AuthenticatedUser?[] users) : IUserSessionResolver
    {
        public int ResolveCount { get; private set; }

        public Task<AuthenticatedUser?> ResolveAsync(string token, CancellationToken cancellationToken)
        {
            Assert.Equal("live-session", token);
            var index = Math.Min(ResolveCount++, users.Length - 1);
            return Task.FromResult(users[index]);
        }
    }

    private sealed class StubWebSocketFeature(RecordingWebSocket socket) : IHttpWebSocketFeature
    {
        public bool IsWebSocketRequest => true;
        public Task<WebSocket> AcceptAsync(WebSocketAcceptContext context) => Task.FromResult<WebSocket>(socket);
    }

    private sealed class RecordingWebSocket(IEnumerable<string> messages, bool waitForClientClose = false) : WebSocket
    {
        private readonly Queue<string> _messages = new(messages);
        private WebSocketState _state = WebSocketState.Open;
        private WebSocketCloseStatus? _closeStatus;
        private string? _closeStatusDescription;
        private readonly TaskCompletionSource _closeFrame = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public ConcurrentQueue<string> SentMessages { get; } = new();
        public override WebSocketCloseStatus? CloseStatus => _closeStatus;
        public override string? CloseStatusDescription => _closeStatusDescription;
        public override WebSocketState State => _state;
        public override string? SubProtocol => null;

        public override void Abort() => _state = WebSocketState.Aborted;
        public override void Dispose() => _state = WebSocketState.Closed;

        public override Task CloseAsync(WebSocketCloseStatus closeStatus, string? statusDescription,
            CancellationToken cancellationToken)
        {
            _closeStatus = closeStatus;
            _closeStatusDescription = statusDescription;
            _state = WebSocketState.Closed;
            _closeFrame.TrySetResult();
            return Task.CompletedTask;
        }

        public override Task CloseOutputAsync(WebSocketCloseStatus closeStatus, string? statusDescription,
            CancellationToken cancellationToken)
        {
            _closeStatus = closeStatus;
            _closeStatusDescription = statusDescription;
            _state = WebSocketState.Closed;
            _closeFrame.TrySetResult();
            return Task.CompletedTask;
        }

        public override Task<WebSocketReceiveResult> ReceiveAsync(
            ArraySegment<byte> buffer,
            CancellationToken cancellationToken)
        {
            if (_messages.TryDequeue(out var message))
            {
                var bytes = Encoding.UTF8.GetBytes(message);
                Array.Copy(bytes, 0, buffer.Array!, buffer.Offset, bytes.Length);
                return Task.FromResult(new WebSocketReceiveResult(bytes.Length, WebSocketMessageType.Text, true));
            }
            if (waitForClientClose) return ReceiveClientCloseAsync(cancellationToken);
            _state = WebSocketState.CloseReceived;
            return Task.FromResult(new WebSocketReceiveResult(
                0, WebSocketMessageType.Close, true, WebSocketCloseStatus.NormalClosure, "Client closed."));
        }

        private async Task<WebSocketReceiveResult> ReceiveClientCloseAsync(CancellationToken cancellationToken)
        {
            await _closeFrame.Task.WaitAsync(cancellationToken);
            _state = WebSocketState.CloseReceived;
            return new WebSocketReceiveResult(
                0, WebSocketMessageType.Close, true, WebSocketCloseStatus.NormalClosure, "Client closed.");
        }

        public override Task SendAsync(
            ArraySegment<byte> buffer,
            WebSocketMessageType messageType,
            bool endOfMessage,
            CancellationToken cancellationToken)
        {
            SentMessages.Enqueue(Encoding.UTF8.GetString(buffer.Array!, buffer.Offset, buffer.Count));
            return Task.CompletedTask;
        }
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        public string Path { get; }
        public TemporaryDirectory(string prefix) => Path = Directory.CreateTempSubdirectory(prefix).FullName;
        public void Dispose() => Directory.Delete(Path, true);
    }
}
