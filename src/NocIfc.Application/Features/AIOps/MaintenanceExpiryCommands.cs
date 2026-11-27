using NocIfc.Application.Abstractions.AIOps;

namespace NocIfc.Application.Features.AIOps;

public sealed class MaintenanceExpiryCommands(IMaintenanceExpiryStore maintenance)
{
    private static readonly TimeZoneInfo CentralTimeZone = TimeZoneInfo.FindSystemTimeZoneById("America/Chicago");

    public Task<IReadOnlyList<string>> ExecuteAsync(CancellationToken cancellationToken)
    {
        var nowUtc = DateTime.UtcNow;
        var todayCentral = DateOnly.FromDateTime(TimeZoneInfo.ConvertTimeFromUtc(nowUtc, CentralTimeZone));
        return maintenance.ClearExpiredAsync(todayCentral, nowUtc, cancellationToken);
    }
}
