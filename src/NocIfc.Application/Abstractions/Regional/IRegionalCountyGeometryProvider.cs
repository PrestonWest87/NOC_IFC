using System.Text.Json.Nodes;

namespace NocIfc.Application.Abstractions.Regional;

public sealed record RegionalCountyGeometry(string Fips, string StateFips, JsonNode Geometry);

public interface IRegionalCountyGeometryProvider
{
    IReadOnlyDictionary<string, RegionalCountyGeometry> GetRegionalCounties();
}
