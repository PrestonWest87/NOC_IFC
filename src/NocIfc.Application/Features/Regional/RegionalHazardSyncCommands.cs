using System.Text.Json.Nodes;
using NocIfc.Application.Abstractions.Regional;

namespace NocIfc.Application.Features.Regional;

public sealed record RegionalHazardSyncOutcome(bool Success, JsonObject Body);

public sealed class RegionalHazardSyncCommands(IRegionalHazardSyncProvider syncProvider)
{
    public async Task<RegionalHazardSyncOutcome> ExecuteAsync(CancellationToken cancellationToken)
    {
        var nws = await syncProvider.SyncNwsAlertsAsync(cancellationToken);
        var regional = await syncProvider.SyncRegionalFeedsAsync(cancellationToken);
        var feeds = new JsonObject
        {
            ["nws_alerts"] = nws,
            ["regional_hazards"] = regional,
        };
        var success = nws["status"]?.GetValue<string>() is "ok" or "not_modified" or "throttled" or "backoff"
            && regional["status"]?.GetValue<string>() == "ok";
        if (!success)
        {
            return new RegionalHazardSyncOutcome(false, new JsonObject
            {
                ["detail"] = new JsonObject
                {
                    ["message"] = "One or more hazard sources failed to refresh.",
                    ["feeds"] = feeds,
                },
            });
        }
        return new RegionalHazardSyncOutcome(true, new JsonObject
        {
            ["status"] = "ok",
            ["message"] = "Regional hazards synced.",
            ["feeds"] = feeds,
        });
    }
}
