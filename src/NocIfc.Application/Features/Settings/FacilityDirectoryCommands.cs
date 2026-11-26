using NocIfc.Application.Abstractions.Settings;
using NocIfc.Domain.Identity;
using NocIfc.Domain.Settings;

namespace NocIfc.Application.Features.Settings;

public sealed record MonitoredLocationImportRow(
    string? Name,
    double? Latitude,
    double? Longitude,
    string? Type,
    string? LocationType,
    string? District,
    string? Priority);

public sealed record MonitoredLocationEditRow(
    int? Id,
    string? Name,
    string? LocationType,
    string? Type,
    string? District,
    string? Priority,
    double? Latitude,
    double? Longitude);

public sealed record SiteContactInput(string? Name, string? Phone, string? Email);

public sealed class FacilityDirectoryCommands(IFacilityDirectoryStore facilities)
{
    public async Task<IReadOnlyList<MonitoredLocationEntry>> GetLocationsAsync(
        AuthenticatedUser user,
        CancellationToken cancellationToken)
    {
        var locations = await facilities.GetLocationsAsync(cancellationToken);
        return user.IsAdministrator
            ? locations
            : locations.Where(location => user.AllowedSiteTypes.Contains(location.LocationType, StringComparer.Ordinal)).ToArray();
    }

    public Task<IReadOnlyList<MonitoredLocationEntry>> GetAdminLocationsAsync(CancellationToken cancellationToken) =>
        facilities.GetAdminLocationsAsync(cancellationToken);

    public Task<IReadOnlyList<MonitoredLocationContactEntry>?> GetSiteContactsAsync(
        int locationId,
        CancellationToken cancellationToken) =>
        facilities.GetSiteContactsAsync(locationId, cancellationToken);

    public async Task<IReadOnlyList<MonitoredLocationContactEntry>?> ReplaceSiteContactsAsync(
        int locationId,
        IReadOnlyList<SiteContactInput> contacts,
        CancellationToken cancellationToken)
    {
        if (contacts.Count > 50)
        {
            throw new ArgumentException("A site can have at most 50 contacts.");
        }
        var normalized = contacts.Select(contact => new MonitoredLocationContactValue(
            SiteContactRules.NormalizeOptional("name", contact.Name),
            SiteContactRules.NormalizeOptional("phone", contact.Phone),
            SiteContactRules.NormalizeOptional("email", contact.Email)))
            .Where(contact => contact.Name is not null || contact.Phone is not null || contact.Email is not null)
            .ToArray();
        return await facilities.ReplaceSiteContactsAsync(locationId, normalized, cancellationToken);
    }

    public Task<int> ImportLocationsAsync(
        IReadOnlyList<MonitoredLocationImportRow> locations,
        string mode,
        CancellationToken cancellationToken)
    {
        if (mode is not ("add" or "upsert" or "replace"))
        {
            throw new ArgumentException("mode must be 'add', 'upsert', or 'replace'.");
        }
        return facilities.ImportLocationsAsync(locations, mode, cancellationToken);
    }

    public Task UpdateLocationsAsync(
        IReadOnlyList<MonitoredLocationEditRow> locations,
        CancellationToken cancellationToken) =>
        facilities.UpdateLocationsAsync(locations, cancellationToken);
}
