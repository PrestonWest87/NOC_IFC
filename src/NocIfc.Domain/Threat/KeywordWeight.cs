namespace NocIfc.Domain.Threat;

public sealed record KeywordWeight(string Word, int Weight);

public sealed record KeywordScore(double Score, IReadOnlyList<string> Reasons);
