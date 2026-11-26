using NocIfc.Domain.Threat;

namespace NocIfc.Application.Abstractions.Threat;

public interface IThreatStatusStore
{
    Task<IReadOnlyList<CloudOutageEntry>> GetCloudOutagesAsync(
        bool activeOnly,
        DateTime updatedAfterUtc,
        CancellationToken cancellationToken);
    Task<IReadOnlyList<CrimeIncidentEntry>> GetRecentCrimesAsync(
        double maxDistance,
        DateTime occurredAfterUtc,
        CancellationToken cancellationToken);
    Task<Microsoft365StatusSnapshot> GetMicrosoft365StatusAsync(
        DateTime updatedAfterUtc,
        CancellationToken cancellationToken);
}
