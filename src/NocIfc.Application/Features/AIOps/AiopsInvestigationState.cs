using System.Collections.Concurrent;

namespace NocIfc.Application.Features.AIOps;

public sealed class AiopsInvestigationState
{
    private readonly ConcurrentDictionary<string, byte> _sites = new(StringComparer.Ordinal);

    public IReadOnlyList<string> GetSites() => _sites.Keys.OrderBy(name => name, StringComparer.Ordinal).ToArray();

    public void Set(string siteName, bool investigating)
    {
        if (investigating)
        {
            _sites[siteName] = 0;
        }
        else
        {
            _sites.TryRemove(siteName, out _);
        }
    }
}
