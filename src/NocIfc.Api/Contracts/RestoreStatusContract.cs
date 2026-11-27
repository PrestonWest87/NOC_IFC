using System.Globalization;
using System.Text.Json.Serialization;
using NocIfc.Application.Abstractions.BackupRestore;

namespace NocIfc.Api.Contracts;

public sealed record RestoreStatusResponse(
    [property: JsonPropertyName("restore_id")] string RestoreId,
    [property: JsonPropertyName("state")] string State,
    [property: JsonPropertyName("message")] string Message,
    [property: JsonPropertyName("percent"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] int? Percent,
    [property: JsonPropertyName("started_at")] string StartedAt,
    [property: JsonPropertyName("updated_at")] string UpdatedAt,
    [property: JsonPropertyName("result"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] BackupRestoreResultResponse? Result)
{
    public static RestoreStatusResponse From(RestoreProgressState status) => new(
        status.RestoreId,
        status.State,
        status.Message,
        status.Percent,
        FormatUtc(status.StartedAt),
        FormatUtc(status.UpdatedAt),
        status.Result is null ? null : BackupRestoreResultResponse.From(status.Result));

    private static string FormatUtc(DateTimeOffset value) =>
        value.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", CultureInfo.InvariantCulture);
}
