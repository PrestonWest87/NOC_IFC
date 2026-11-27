using System.Globalization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using NocIfc.Application.Abstractions.AIOps;
using NocIfc.Application.Abstractions.BackupRestore;
using NocIfc.Application.Abstractions.Dashboard;
using NocIfc.Application.Abstractions.Elastic;
using NocIfc.Application.Abstractions.Email;
using NocIfc.Application.Abstractions.Identity;
using NocIfc.Application.Abstractions.Llm;
using NocIfc.Application.Abstractions.OperationalEmail;
using NocIfc.Application.Abstractions.Regional;
using NocIfc.Application.Abstractions.Reporting;
using NocIfc.Application.Abstractions.Settings;
using NocIfc.Application.Abstractions.Threat;
using NocIfc.Application.Features.AIOps;
using NocIfc.Application.Features.Dashboard;
using NocIfc.Application.Features.Email;
using NocIfc.Application.Features.Identity;
using NocIfc.Application.Features.OperationalEmail;
using NocIfc.Application.Features.Regional;
using NocIfc.Application.Features.Reporting;
using NocIfc.Application.Features.Settings;
using NocIfc.Application.Features.Threat;
using NocIfc.Domain.BackupRestore;
using NocIfc.Infrastructure.BackupRestore;
using NocIfc.Infrastructure.Email;
using NocIfc.Infrastructure.Integrations.Elastic;
using NocIfc.Infrastructure.Integrations.Llm;
using NocIfc.Infrastructure.Integrations.Threat;
using NocIfc.Infrastructure.Integrations.Weather;
using NocIfc.Infrastructure.Persistence.Sqlite;
using NocIfc.Worker;

var builder = Host.CreateApplicationBuilder(args);
var databaseUrl = builder.Configuration["DATABASE_URL"]
    ?? throw new InvalidOperationException("DATABASE_URL is required.");
var integrationEnvironment = new IntegrationEnvironmentSettings(
    builder.Configuration["risk_alert_recipients"] ?? "",
    builder.Configuration["remedyforce_ticket_email"] ?? "",
    builder.Configuration["noc_notify_email"] ?? "",
    builder.Configuration["noc_onpage_email"] ?? "",
    builder.Configuration["itnetwork_onpage_email"] ?? "",
    builder.Configuration["elastic_url"] ?? "",
    builder.Configuration["elastic_api_key"] ?? "",
    ReadBoolean(builder.Configuration["elastic_verify_certs"], true, "ELASTIC_VERIFY_CERTS"),
    builder.Configuration["elastic_ca_certs"],
    ReadDouble(builder.Configuration["elastic_request_timeout"], 15, "ELASTIC_REQUEST_TIMEOUT"),
    ReadInteger(builder.Configuration["elastic_max_results"], 500, "ELASTIC_MAX_RESULTS"),
    builder.Configuration["crime_alert_sms"],
    builder.Configuration["crime_alert_email"]);
var arkansasFireCoverage = ArkansasFireCoverage.LoadBundled();

builder.Services.AddSingleton(new SqliteConnectionFactory(databaseUrl));
builder.Services.AddSingleton<SqliteReadinessProbe>();
builder.Services.AddSingleton<IRestoreMaintenanceControl, SqliteRestoreMaintenanceControl>();
builder.Services.AddSingleton(integrationEnvironment);
builder.Services.AddSingleton(new BackupEncryptionSettings(
    builder.Configuration["BACKUP_ENCRYPTION_KEYS"] ?? "",
    builder.Configuration["BACKUP_ENCRYPTION_ACTIVE_KEY_ID"] ?? "primary",
    builder.Configuration["BACKUP_MAX_BYTES"] ?? "10737418240"));
builder.Services.AddSingleton<IBackupManager, SqliteBackupManager>();

builder.Services.AddScoped<IAiSmtpSettingsStore, SqliteAiSmtpSettingsStore>();
builder.Services.AddScoped<IOperationalDashboardStore, SqliteOperationalDashboardStore>();
builder.Services.AddScoped<IOperationalEmailStore, SqliteOperationalEmailStore>();
builder.Services.AddHttpClient<GmailOAuthTokenProvider>(client => client.Timeout = TimeSpan.FromSeconds(10));
builder.Services.AddScoped<SqliteEmailSender>();
builder.Services.AddScoped<IEmailSender>(services => services.GetRequiredService<SqliteEmailSender>());
builder.Services.AddScoped<IOperationalEmailSender>(services => services.GetRequiredService<SqliteEmailSender>());
builder.Services.AddScoped<OperationalEmailQueueProcessor>();

builder.Services.AddScoped<ISchedulerSettingsStore, SqliteSchedulerSettingsStore>();
builder.Services.AddScoped<IDangerZoneStore, SqliteDangerZoneStore>();
builder.Services.AddScoped<DangerZoneCommands>();
builder.Services.AddScoped<IOperationalIntegrationSettingsStore, SqliteOperationalIntegrationSettingsStore>();
builder.Services.AddScoped<IFacilityDirectoryStore, SqliteFacilityDirectoryStore>();
builder.Services.AddScoped<FacilityDirectoryCommands>();
builder.Services.AddScoped<IMaintenanceExpiryStore, SqliteMaintenanceExpiryStore>();
builder.Services.AddScoped<MaintenanceExpiryCommands>();
builder.Services.AddScoped<IRssIngestionStore, SqliteRssIngestionStore>();
builder.Services.AddScoped<IRssSettingsStore, SqliteRssSettingsStore>();
builder.Services.AddScoped<IArticleEnrichmentStore, SqliteArticleEnrichmentStore>();
builder.Services.AddSingleton<IArticleContentFetcher, PublicArticleContentClient>();
builder.Services.AddScoped<ArticleEnrichmentCommands>();
builder.Services.AddHttpClient<RssFeedClient>(client => client.Timeout = TimeSpan.FromSeconds(15));
builder.Services.AddScoped<IRssFeedClient>(services => services.GetRequiredService<RssFeedClient>());
builder.Services.AddScoped<RssFeedFetchCommands>();

builder.Services.AddScoped<ICisaKevStore, SqliteCisaKevStore>();
builder.Services.AddScoped<CisaKevQueries>();
builder.Services.AddScoped<CisaKevSyncCommands>();
builder.Services.AddHttpClient<CisaKevCatalogClient>(client => client.Timeout = TimeSpan.FromSeconds(30));
builder.Services.AddScoped<ICisaKevCatalogProvider>(services => services.GetRequiredService<CisaKevCatalogClient>());
builder.Services.AddScoped<SqliteCloudStatusSyncStore>();
builder.Services.AddHttpClient<CloudStatusSyncClient>(client => client.Timeout = TimeSpan.FromSeconds(10));
builder.Services.AddScoped<ICloudStatusSyncProvider>(services => services.GetRequiredService<CloudStatusSyncClient>());
builder.Services.AddScoped<CloudStatusSyncCommands>();
builder.Services.AddScoped<SqliteCrimeDataSyncStore>();
builder.Services.AddHttpClient<CrimeDataSyncClient>(client => client.Timeout = TimeSpan.FromSeconds(15));
builder.Services.AddScoped<ICrimeDataSyncProvider>(services => services.GetRequiredService<CrimeDataSyncClient>());
builder.Services.AddScoped<CrimeDataSyncCommands>();

builder.Services.AddSingleton(arkansasFireCoverage);
builder.Services.AddSingleton<IRegionalCountyGeometryProvider>(arkansasFireCoverage);
builder.Services.AddSingleton<WfcaWildfireSnapshotCache>();
builder.Services.AddSingleton(new NwsForecastConfiguration(
    builder.Configuration["nws_api_user_agent"] ?? "NOC-IFC/2.0 (https://test.weasts.net)",
    builder.Configuration["default_admin_email"] ?? ""));
builder.Services.AddHttpClient<WfcaWildfireClient>(client => client.Timeout = TimeSpan.FromSeconds(20))
    .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler { AllowAutoRedirect = false });
builder.Services.AddScoped<IRegionalWildfireProvider>(services => services.GetRequiredService<WfcaWildfireClient>());
builder.Services.AddScoped<SqliteRegionalHazardSyncStore>();
builder.Services.AddHttpClient<RegionalHazardSyncClient>(client => client.Timeout = TimeSpan.FromSeconds(20))
    .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler { AllowAutoRedirect = false });
builder.Services.AddScoped<IRegionalHazardSyncProvider>(services => services.GetRequiredService<RegionalHazardSyncClient>());
builder.Services.AddScoped<RegionalHazardSyncCommands>();
builder.Services.AddHttpClient<TelemetrySyncClient>(client => client.Timeout = TimeSpan.FromSeconds(20))
    .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler { AllowAutoRedirect = false });
builder.Services.AddScoped<ITelemetrySyncProvider>(services => services.GetRequiredService<TelemetrySyncClient>());
builder.Services.AddScoped<TelemetrySyncCommands>();

builder.Services.AddScoped<IElasticEventSource>(_ => new ElasticSearchClient());
builder.Services.AddScoped<IThreatHuntingStore, SqliteThreatHuntingStore>();
builder.Services.AddScoped<ThreatHuntingCommands>();
builder.Services.AddScoped<IThreatArticleStore, SqliteThreatArticleStore>();
builder.Services.AddScoped<IInternalRiskStore, SqliteInternalRiskStore>();
builder.Services.AddScoped<IMaintenanceExpiryStore, SqliteMaintenanceExpiryStore>();
builder.Services.AddScoped<MaintenanceExpiryCommands>();
builder.Services.AddScoped<IAutoEscalationStore, SqliteAutoEscalationStore>();
builder.Services.AddScoped<IAiopsDashboardStore, SqliteAiopsDashboardStore>();
builder.Services.AddScoped<IAiopsRcaAnalysisStore, SqliteAiopsRcaAnalysisStore>();
builder.Services.AddSingleton<AiopsInvestigationState>();
builder.Services.AddScoped<FacilityDirectoryCommands>();
builder.Services.AddScoped<AiopsDashboardQueries>();
builder.Services.AddScoped<AiopsRcaAnalysisEngine>();
builder.Services.AddScoped<TieredAlertEscalationCommands>();
builder.Services.AddScoped<IRiskScoringSettingsStore, SqliteRiskScoringSettingsStore>();
builder.Services.AddScoped<InternalRiskScoringCommands>();
builder.Services.AddScoped<IExecutiveIntelStore, SqliteExecutiveIntelStore>();
builder.Services.AddScoped<ExecutiveIntelQueries>();
builder.Services.AddScoped<IThreatStatusStore, SqliteThreatStatusStore>();
builder.Services.AddScoped<ThreatStatusQueries>();
builder.Services.AddScoped<DashboardQueries>();
builder.Services.AddScoped<InternalRiskQueries>();
builder.Services.AddScoped<IApplicationSettingsStore, SqliteApplicationSettingsStore>();
builder.Services.AddScoped<ISiteTypeDirectory, SqliteSiteTypeDirectory>();
builder.Services.AddScoped<SiteTypeQueries>();
builder.Services.AddScoped<IAiopsSitrepActionStore, SqliteAiopsSitrepActionStore>();
builder.Services.AddScoped<AiopsSitrepActionCommands>();
builder.Services.AddScoped<UnifiedBriefGenerationCommands>();
builder.Services.AddScoped<GlobalBriefGenerationCommands>();
builder.Services.AddScoped<InternalBriefGenerationCommands>();
builder.Services.AddScoped<IDailyBriefingStore, SqliteDailyBriefingStore>();
builder.Services.AddScoped<DailyFusionCommands>();
builder.Services.AddScoped<ReportingBroadcastCommands>();
builder.Services.AddScoped<BriefBroadcastCommands>();

builder.Services.AddSingleton(new LlmEndpointPolicy(
    ReadBoolean(builder.Configuration["allow_private_llm_endpoints"], false, "ALLOW_PRIVATE_LLM_ENDPOINTS")));
builder.Services.AddHttpClient<ProviderAwareLlmClient>(client => client.Timeout = TimeSpan.FromMinutes(5))
    .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler { AllowAutoRedirect = false });
builder.Services.AddScoped<ILlmChatCompletionClient>(services => services.GetRequiredService<ProviderAwareLlmClient>());

builder.Services.AddHostedService<SchedulerWorker>();

await builder.Build().RunAsync();

static bool ReadBoolean(string? value, bool fallback, string name) => value is null
    ? fallback
    : bool.TryParse(value, out var parsed)
        ? parsed
        : throw new InvalidOperationException($"{name} must be true or false.");

static double ReadDouble(string? value, double fallback, string name) => value is null
    ? fallback
    : double.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out var parsed)
        && double.IsFinite(parsed) && parsed is > 0 and <= 120
            ? parsed
            : throw new InvalidOperationException($"{name} must be greater than 0 and at most 120.");

static int ReadInteger(string? value, int fallback, string name) => value is null
    ? fallback
    : int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed)
        && parsed is >= 1 and <= 5000
            ? parsed
            : throw new InvalidOperationException($"{name} must be between 1 and 5000.");
