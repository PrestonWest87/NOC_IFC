using NocIfc.Application.Abstractions.Regional;

namespace NocIfc.Application.Features.Regional;

public sealed class TelemetrySyncCommands(ITelemetrySyncProvider telemetry)
{
    public Task<TelemetrySyncResult> ExecuteAsync(CancellationToken cancellationToken) =>
        telemetry.SyncAsync(cancellationToken);
}
