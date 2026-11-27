using NocIfc.Domain.AIOps;

namespace NocIfc.Application.Abstractions.AIOps;

public interface ISolarWindsWebhookStore
{
    Task PersistAsync(
        SolarWindsWebhookEvent webhookEvent,
        string rawPayloadJson,
        DateTime receivedAtUtc,
        CancellationToken cancellationToken);
}
