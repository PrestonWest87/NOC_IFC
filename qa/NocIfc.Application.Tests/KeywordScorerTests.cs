using NocIfc.Application.Features.Threat;
using NocIfc.Domain.Threat;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class KeywordScorerTests
{
    [Fact]
    public void ScoreSumsMatchingKeywordWeightsAndCapsAtOneHundred()
    {
        var result = KeywordScorer.Score(
            "NETWORK outage detected",
            [new KeywordWeight("outage", 80), new KeywordWeight("network", 40), new KeywordWeight("unused", 100)]);

        Assert.Equal(100, result.Score);
        Assert.Equal(new[] { "outage", "network" }, result.Reasons);
    }
}
