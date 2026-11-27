using NocIfc.Application.Abstractions.Threat;

namespace NocIfc.Application.Features.Threat;

public sealed class ArticleEnrichmentCommands(
    IArticleEnrichmentStore articles,
    IArticleContentFetcher contentFetcher)
{
    public async Task<int> ExecuteAsync(int limit, CancellationToken cancellationToken)
    {
        if (limit is < 1 or > 100) throw new ArgumentOutOfRangeException(nameof(limit));
        var pending = await articles.ClaimPendingAsync(limit, cancellationToken);
        using var parallelism = new SemaphoreSlim(2, 2);
        var completed = await Task.WhenAll(pending.Select(async article =>
        {
            await parallelism.WaitAsync(cancellationToken);
            try
            {
                var content = await contentFetcher.FetchAndExtractAsync(article.Link, cancellationToken);
                if (string.IsNullOrWhiteSpace(content))
                {
                    await articles.SaveFailureAsync(article.Id,
                        "Full-content extraction returned no content.", cancellationToken);
                    return false;
                }
                await articles.SaveEnrichedAsync(article.Id,
                    content[..Math.Min(content.Length, 200_000)], DateTime.UtcNow, cancellationToken);
                return true;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                try
                {
                    await articles.SaveFailureAsync(article.Id, "Article enrichment was interrupted and can be retried.",
                        CancellationToken.None);
                }
                catch (Exception)
                {
                }
                throw;
            }
            catch (Exception exception)
            {
                await articles.SaveFailureAsync(article.Id,
                    exception.Message[..Math.Min(exception.Message.Length, 500)], cancellationToken);
                return false;
            }
            finally
            {
                parallelism.Release();
            }
        }));
        return completed.Count(value => value);
    }
}
