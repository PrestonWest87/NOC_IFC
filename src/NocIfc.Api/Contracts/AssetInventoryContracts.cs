using System.Text.Json.Serialization;

namespace NocIfc.Api.Contracts;

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class AssetCsvImportRequest
{
    [JsonPropertyName("csv_body")]
    public string? CsvBody { get; init; }
}
