using NocIfc.Application.Features.Settings;
using NocIfc.Domain.Threat;

namespace NocIfc.Application.Abstractions.Elastic;

public interface IElasticEventSource
{
    Task<IReadOnlyList<ElasticEventEntry>> SearchHighSeverityAsync(
        ElasticClientSettings settings,
        DateTime sinceUtc,
        CancellationToken cancellationToken);
}
