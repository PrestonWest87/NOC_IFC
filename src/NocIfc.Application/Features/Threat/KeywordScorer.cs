using NocIfc.Domain.Threat;

namespace NocIfc.Application.Features.Threat;

public static class KeywordScorer
{
    public static KeywordScore Score(string text, IEnumerable<KeywordWeight> keywordWeights)
    {
        ArgumentNullException.ThrowIfNull(text);
        ArgumentNullException.ThrowIfNull(keywordWeights);

        var normalizedText = text.ToLowerInvariant();
        var reasons = new List<string>();
        double score = 0;

        foreach (var keyword in keywordWeights)
        {
            var normalizedWord = keyword.Word.ToLowerInvariant();
            if (!normalizedText.Contains(normalizedWord, StringComparison.Ordinal))
            {
                continue;
            }

            score += keyword.Weight;
            reasons.Add(normalizedWord);
        }

        return new KeywordScore(Math.Min(score, 100), reasons);
    }
}
