namespace NocIfc.Application.Abstractions.Regional;

public interface IRegionalWildfireProvider
{
    Task<string> GetActiveWildfiresJsonAsync(CancellationToken cancellationToken);
}
