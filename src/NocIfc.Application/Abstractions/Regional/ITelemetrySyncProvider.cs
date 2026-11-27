namespace NocIfc.Application.Abstractions.Regional;

public sealed record TelemetrySyncResult(int PowerRows, int BgpAnomaliesAdded, int IodaRows);

public interface ITelemetrySyncProvider
{
    Task<TelemetrySyncResult> SyncAsync(CancellationToken cancellationToken);
}
