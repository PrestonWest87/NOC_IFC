using NocIfc.Application.Features.Settings;
using NocIfc.Domain.Settings;

namespace NocIfc.Application.Abstractions.Settings;

public interface IFacilityDirectoryStore
{
    Task<IReadOnlyList<MonitoredLocationEntry>> GetLocationsAsync(CancellationToken cancellationToken);
    Task<IReadOnlyList<MonitoredLocationEntry>> GetAdminLocationsAsync(CancellationToken cancellationToken);
    Task<IReadOnlyList<MonitoredLocationContactEntry>?> GetSiteContactsAsync(
        int locationId,
        CancellationToken cancellationToken);
    Task<IReadOnlyList<MonitoredLocationContactEntry>?> ReplaceSiteContactsAsync(
        int locationId,
        IReadOnlyList<MonitoredLocationContactValue> contacts,
        CancellationToken cancellationToken);
    Task<int> ImportLocationsAsync(
        IReadOnlyList<MonitoredLocationImportRow> locations,
        string mode,
        CancellationToken cancellationToken);
    Task UpdateLocationsAsync(
        IReadOnlyList<MonitoredLocationEditRow> locations,
        CancellationToken cancellationToken);
}
