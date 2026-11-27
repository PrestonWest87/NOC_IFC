using System.Threading.Channels;
using NocIfc.Application.Abstractions.BackupRestore;

namespace NocIfc.Webhook;

public sealed record SolarWindsWebhookMessage(byte[] Body);

// shortcut: accepted bodies are process-local; use a durable inbox if restart-safe delivery is required.
public sealed class SolarWindsWebhookQueue
{
    private readonly Channel<SolarWindsWebhookMessage> _queue;
    private int _pending;

    public SolarWindsWebhookQueue(WebhookSecurityOptions options)
    {
        var capacity = Math.Clamp(64 * 1024 * 1024 / options.MaxBodyBytes, 1, 64);
        _queue = Channel.CreateBounded<SolarWindsWebhookMessage>(new BoundedChannelOptions(capacity)
        {
            SingleReader = true,
            FullMode = BoundedChannelFullMode.Wait,
        });
    }

    public ChannelReader<SolarWindsWebhookMessage> Reader => _queue.Reader;
    public int Pending => Volatile.Read(ref _pending);

    public bool TryEnqueue(byte[] body, IRestoreMaintenanceControl restore)
    {
        if (restore.MaintenanceRequested) return false;
        Interlocked.Increment(ref _pending);
        if (restore.MaintenanceRequested || !_queue.Writer.TryWrite(new SolarWindsWebhookMessage(body)))
        {
            Interlocked.Decrement(ref _pending);
            return false;
        }
        return true;
    }

    public void CompleteOne()
    {
        while (true)
        {
            var current = Volatile.Read(ref _pending);
            if (current <= 0 || Interlocked.CompareExchange(ref _pending, current - 1, current) == current) return;
        }
    }
}
