namespace NocIfc.Application.Abstractions.AIOps;

public interface IMaintenanceExpiryStore
{
    Task<IReadOnlyList<string>> ClearExpiredAsync(
        DateOnly centralToday,
        DateTime nowUtc,
        CancellationToken cancellationToken);
}
