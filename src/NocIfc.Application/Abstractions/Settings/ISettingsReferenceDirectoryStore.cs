using NocIfc.Domain.Settings;

namespace NocIfc.Application.Abstractions.Settings;

public interface ISettingsReferenceDirectoryStore
{
    Task<IReadOnlyList<FiberEmailContactEntry>> GetFiberAsync(CancellationToken cancellationToken);
    Task<IReadOnlyList<FiberEmailContactEntry>> ReplaceFiberAsync(
        IReadOnlyList<FiberEmailContactValue> contacts,
        int actorUserId,
        CancellationToken cancellationToken);
    Task<IReadOnlyList<OnpageEmailContactEntry>> GetOnpageAsync(CancellationToken cancellationToken);
    Task<IReadOnlyList<OnpageEmailContactEntry>> ReplaceOnpageAsync(
        IReadOnlyList<OnpageEmailContactValue> contacts,
        int actorUserId,
        CancellationToken cancellationToken);
    Task<IReadOnlyList<NetworkOrderCircuitEntry>> GetNetworkOrdersAsync(CancellationToken cancellationToken);
    Task<IReadOnlyList<NetworkOrderCircuitEntry>> ReplaceNetworkOrdersAsync(
        IReadOnlyList<NetworkOrderCircuitValue> records,
        int actorUserId,
        CancellationToken cancellationToken);
}
