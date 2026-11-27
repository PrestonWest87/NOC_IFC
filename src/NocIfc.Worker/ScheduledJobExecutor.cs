using Microsoft.Extensions.DependencyInjection;
using NocIfc.Application.Abstractions.BackupRestore;
using NocIfc.Application.Abstractions.Regional;
using NocIfc.Application.Abstractions.Settings;
using NocIfc.Application.Features.AIOps;
using NocIfc.Application.Features.Dashboard;
using NocIfc.Application.Features.Email;
using NocIfc.Application.Features.OperationalEmail;
using NocIfc.Application.Features.Regional;
using NocIfc.Application.Features.Reporting;
using NocIfc.Application.Features.Settings;
using NocIfc.Application.Features.Threat;

namespace NocIfc.Worker;

internal static class ScheduledJobExecutor
{
    private static readonly HashSet<string> SupportedJobs =
    [
        "operational_email_queue", "database_backup", "rss_fetch", "cisa_kev", "nws_alerts",
        "regional_hazards", "telemetry_sync", "cloud_outages", "crime_fetch", "elastic_sync", "database_maintenance",
        "maintenance_expiry", "internal_risk", "rolling_summary", "internal_brief", "unified_brief",
        "global_brief", "daily_fusion_report", "daily_email_brief", "article_enrichment",
        "tiered_alert_escalation",
    ];

    public static bool IsSupported(string key) => SupportedJobs.Contains(key);

    public static async Task ExecuteAsync(string key, IServiceProvider services, CancellationToken cancellationToken)
    {
        switch (key)
        {
            case "operational_email_queue":
            {
                var count = await services.GetRequiredService<OperationalEmailQueueProcessor>()
                    .ProcessDueAsync(DateTimeOffset.UtcNow, 25, cancellationToken);
                if (count > 0) Console.WriteLine($"Processed {count} queued operational emails.");
                return;
            }
            case "database_backup":
                services.GetRequiredService<IBackupManager>().CreateBackup("scheduled");
                return;
            case "rss_fetch":
                await services.GetRequiredService<RssFeedFetchCommands>().ExecuteAsync(cancellationToken);
                return;
            case "article_enrichment":
                await services.GetRequiredService<ArticleEnrichmentCommands>().ExecuteAsync(25, cancellationToken);
                return;
            case "cisa_kev":
                await services.GetRequiredService<CisaKevSyncCommands>().ExecuteAsync(cancellationToken);
                return;
            case "nws_alerts":
                await services.GetRequiredService<IRegionalHazardSyncProvider>().SyncNwsAlertsAsync(cancellationToken);
                return;
            case "regional_hazards":
                await services.GetRequiredService<IRegionalHazardSyncProvider>().SyncRegionalFeedsAsync(cancellationToken);
                return;
            case "telemetry_sync":
            {
                var result = await services.GetRequiredService<TelemetrySyncCommands>().ExecuteAsync(cancellationToken);
                Console.WriteLine($"Telemetry synchronized: {result.PowerRows} power, {result.BgpAnomaliesAdded} BGP, {result.IodaRows} IODA.");
                return;
            }
            case "cloud_outages":
                await services.GetRequiredService<CloudStatusSyncCommands>().ExecuteAsync(cancellationToken);
                return;
            case "crime_fetch":
                await services.GetRequiredService<CrimeDataSyncCommands>().ExecuteAsync(cancellationToken);
                return;
            case "elastic_sync":
                await services.GetRequiredService<ThreatHuntingCommands>().SyncElasticCacheAsync(24, cancellationToken);
                return;
            case "database_maintenance":
                await services.GetRequiredService<DangerZoneCommands>().RunDatabaseMaintenanceAsync(cancellationToken);
                return;
            case "maintenance_expiry":
            {
                var cleared = await services.GetRequiredService<MaintenanceExpiryCommands>().ExecuteAsync(cancellationToken);
                if (cleared.Count > 0) Console.WriteLine($"Auto-cleared expired maintenance for {cleared.Count} site(s).");
                return;
            }
            case "tiered_alert_escalation":
            {
                var result = await services.GetRequiredService<TieredAlertEscalationCommands>().ExecuteAsync(cancellationToken);
                if (result.TicketsSent > 0 || result.PagesSent > 0)
                {
                    Console.WriteLine($"Escalation sent {result.TicketsSent} ticket(s), {result.PagesSent} on-page(s).");
                }
                return;
            }
            case "internal_risk":
                await services.GetRequiredService<InternalRiskScoringCommands>().GenerateAndSaveAsync(cancellationToken);
                return;
            case "rolling_summary":
                await services.GetRequiredService<AiopsSitrepActionCommands>().RefreshBriefingAsync(cancellationToken);
                return;
            case "internal_brief":
                await RequireSuccessAsync("internal asset brief",
                    await services.GetRequiredService<InternalBriefGenerationCommands>().GenerateAsync(_ => { }, cancellationToken));
                return;
            case "unified_brief":
                await RequireSuccessAsync("unified brief",
                    await services.GetRequiredService<UnifiedBriefGenerationCommands>().GenerateAsync(_ => { }, cancellationToken));
                return;
            case "global_brief":
                await RequireSuccessAsync("global brief",
                    await services.GetRequiredService<GlobalBriefGenerationCommands>().GenerateAsync(_ => { }, cancellationToken));
                return;
            case "daily_fusion_report":
            {
                var result = await services.GetRequiredService<DailyFusionCommands>().GenerateAsync(cancellationToken);
                if (!result.Success) throw new InvalidOperationException(result.Message ?? "Daily Fusion report generation failed.");
                return;
            }
            case "daily_email_brief":
            {
                var settings = await services.GetRequiredService<IOperationalIntegrationSettingsStore>().GetAsync(cancellationToken);
                var result = await services.GetRequiredService<BriefBroadcastCommands>()
                    .BroadcastUnifiedAsync(settings.RiskAlertRecipients, cancellationToken);
                if (!result.Success) throw new InvalidOperationException(result.Message);
                return;
            }
            default:
                throw new NotSupportedException($"Scheduled job '{key}' has no C# handler yet.");
        }
    }

    private static Task RequireSuccessAsync(string name, BriefGenerationResult result) =>
        result.Success ? Task.CompletedTask : Task.FromException(
            new InvalidOperationException(result.Message ?? $"Scheduled {name} generation failed."));
}
