namespace NocIfc.Application.Abstractions.Threat;

public interface IArticleContentFetcher
{
    Task<string?> FetchAndExtractAsync(string url, CancellationToken cancellationToken);
}
