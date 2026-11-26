using NocIfc.Domain.Regional;

namespace NocIfc.Application.Abstractions.Regional;

public interface IRegionalDataStore
{
    Task<IReadOnlyDictionary<string, string?>> GetGeoJsonLayersAsync(
        IReadOnlyList<string> feedNames,
        CancellationToken cancellationToken);
    Task<IReadOnlyDictionary<string, GeoJsonFeedStatus>> GetGeoJsonFeedStatusesAsync(
        IReadOnlyList<string> feedNames,
        CancellationToken cancellationToken);
    Task<IReadOnlyList<string>> GetActiveNwsEventTypesAsync(
        DateTime nowUtc,
        CancellationToken cancellationToken);
}
