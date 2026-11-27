namespace NocIfc.Application.Abstractions.Threat;

public interface IRssFeedClient
{
    Task<byte[]?> FetchAsync(string? url, CancellationToken cancellationToken);
}
