using System.Globalization;
using NocIfc.Application.Abstractions.Elastic;
using NocIfc.Application.Abstractions.Dashboard;
using NocIfc.Api.Middleware;
using NocIfc.Application.Abstractions.Email;
using NocIfc.Application.Abstractions.Identity;
using NocIfc.Application.Abstractions.Llm;
using NocIfc.Application.Abstractions.Regional;
using NocIfc.Application.Abstractions.Settings;
using NocIfc.Application.Abstractions.Threat;
using NocIfc.Application.Features.Identity;
using NocIfc.Application.Features.Dashboard;
using NocIfc.Application.Features.Settings;
using NocIfc.Application.Features.Threat;
using NocIfc.Application.Features.Regional;
using NocIfc.Infrastructure.Email;
using NocIfc.Infrastructure.Integrations.Elastic;
using NocIfc.Infrastructure.Integrations.Llm;
using NocIfc.Infrastructure.Integrations.Weather;
using NocIfc.Infrastructure.Persistence.Sqlite;
using NocIfc.Infrastructure.Security;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddControllers();
var integrationEnvironment = new IntegrationEnvironmentSettings(
    builder.Configuration["risk_alert_recipients"] ?? "",
    builder.Configuration["remedyforce_ticket_email"] ?? "",
    builder.Configuration["noc_notify_email"] ?? "",
    builder.Configuration["noc_onpage_email"] ?? "",
    builder.Configuration["itnetwork_onpage_email"] ?? "",
    builder.Configuration["elastic_url"] ?? "",
    builder.Configuration["elastic_api_key"] ?? "",
    ReadEnvironmentBoolean(builder.Configuration["elastic_verify_certs"], true, "ELASTIC_VERIFY_CERTS"),
    builder.Configuration["elastic_ca_certs"],
    ReadEnvironmentDouble(builder.Configuration["elastic_request_timeout"], 15, "ELASTIC_REQUEST_TIMEOUT"),
    ReadEnvironmentInteger(builder.Configuration["elastic_max_results"], 500, "ELASTIC_MAX_RESULTS"),
    builder.Configuration["crime_alert_sms"],
    builder.Configuration["crime_alert_email"]);
builder.Services.AddSingleton(integrationEnvironment);
builder.Services.AddSingleton(new LlmEndpointPolicy(
    ReadEnvironmentBoolean(builder.Configuration["allow_private_llm_endpoints"], false, "ALLOW_PRIVATE_LLM_ENDPOINTS")));
var databaseUrl = builder.Configuration["DATABASE_URL"]
    ?? throw new InvalidOperationException("DATABASE_URL is required.");
builder.Services.AddSingleton(new SqliteConnectionFactory(databaseUrl));
builder.Services.AddSingleton<SqliteReadinessProbe>();
builder.Services.AddScoped<IUserSessionResolver, SqliteUserSessionResolver>();
builder.Services.AddScoped<IAuthenticationStore, SqliteAuthenticationStore>();
builder.Services.AddScoped<IPasswordVerifier, BCryptPasswordVerifier>();
builder.Services.AddScoped<IPasswordHasher, BCryptPasswordHasher>();
builder.Services.AddScoped<AuthenticationService>();
builder.Services.AddScoped<IAccountRecoveryStore, SqliteAccountRecoveryStore>();
builder.Services.AddScoped<IRecoveryEmailStore, SqliteRecoveryEmailStore>();
builder.Services.AddScoped<RecoveryReviewerQueries>();
builder.Services.AddScoped<AccountRecoveryCommands>();
builder.Services.AddScoped<RecoveryEmailCommands>();
builder.Services.AddScoped<IApplicationSettingsStore, SqliteApplicationSettingsStore>();
builder.Services.AddScoped<ApplicationSettingsCommands>();
builder.Services.AddScoped<IAssetInventoryStore, SqliteAssetInventoryStore>();
builder.Services.AddScoped<AssetInventoryCommands>();
builder.Services.AddScoped<IAiSmtpSettingsStore, SqliteAiSmtpSettingsStore>();
builder.Services.AddScoped<AiSmtpSettingsCommands>();
builder.Services.AddScoped<LlmConnectionTestCommands>();
builder.Services.AddScoped<IRiskScoringSettingsStore, SqliteRiskScoringSettingsStore>();
builder.Services.AddScoped<RiskScoringCommands>();
builder.Services.AddScoped<IOperationalIntegrationSettingsStore, SqliteOperationalIntegrationSettingsStore>();
builder.Services.AddScoped<OperationalIntegrationSettingsCommands>();
builder.Services.AddScoped<ISchedulerSettingsStore, SqliteSchedulerSettingsStore>();
builder.Services.AddScoped<SchedulerSettingsCommands>();
builder.Services.AddScoped<ISettingsReferenceDirectoryStore, SqliteSettingsReferenceDirectoryStore>();
builder.Services.AddScoped<SettingsReferenceDirectoryCommands>();
builder.Services.AddScoped<IFacilityDirectoryStore, SqliteFacilityDirectoryStore>();
builder.Services.AddScoped<FacilityDirectoryCommands>();
builder.Services.AddScoped<ICisaKevStore, SqliteCisaKevStore>();
builder.Services.AddScoped<CisaKevQueries>();
builder.Services.AddScoped<IRssSettingsStore, SqliteRssSettingsStore>();
builder.Services.AddScoped<RssSettingsCommands>();
builder.Services.AddScoped<IOperationalDashboardStore, SqliteOperationalDashboardStore>();
builder.Services.AddScoped<DashboardQueries>();
builder.Services.AddScoped<IExecutiveIntelStore, SqliteExecutiveIntelStore>();
builder.Services.AddScoped<ExecutiveIntelQueries>();
builder.Services.AddScoped<IInternalRiskStore, SqliteInternalRiskStore>();
builder.Services.AddScoped<InternalRiskQueries>();
builder.Services.AddScoped<IThreatArticleStore, SqliteThreatArticleStore>();
builder.Services.AddScoped<ThreatArticleQueries>();
builder.Services.AddScoped<IThreatStatusStore, SqliteThreatStatusStore>();
builder.Services.AddScoped<ThreatStatusQueries>();
builder.Services.AddScoped<IThreatHuntingStore, SqliteThreatHuntingStore>();
builder.Services.AddScoped<ThreatHuntingQueries>();
builder.Services.AddScoped<ThreatHuntingCommands>();
builder.Services.AddScoped<IRegionalPreferenceStore, SqliteRegionalPreferenceStore>();
builder.Services.AddScoped<RegionalWeatherPreferenceCommands>();
builder.Services.AddScoped<IRegionalDataStore, SqliteRegionalDataStore>();
builder.Services.AddScoped<RegionalDataQueries>();
builder.Services.AddScoped<RegionalMapQueries>();
builder.Services.AddSingleton(new NwsForecastConfiguration(
    builder.Configuration["nws_api_user_agent"] ?? "NOC-IFC/2.0 (https://test.weasts.net)",
    builder.Configuration["default_admin_email"] ?? ""));
builder.Services.AddHttpClient<NwsForecastClient>(client => client.Timeout = TimeSpan.FromSeconds(10))
    .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler { AllowAutoRedirect = false });
builder.Services.AddScoped<INwsForecastProvider>(services => services.GetRequiredService<NwsForecastClient>());
builder.Services.AddScoped<RegionalForecastQueries>();
var arkansasFireCoverage = ArkansasFireCoverage.LoadBundled();
builder.Services.AddSingleton(arkansasFireCoverage);
builder.Services.AddSingleton<IRegionalCountyGeometryProvider>(arkansasFireCoverage);
builder.Services.AddSingleton<WfcaWildfireSnapshotCache>();
builder.Services.AddHttpClient<WfcaWildfireClient>(client => client.Timeout = TimeSpan.FromSeconds(20))
    .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler { AllowAutoRedirect = false });
builder.Services.AddScoped<IRegionalWildfireProvider>(services => services.GetRequiredService<WfcaWildfireClient>());
builder.Services.AddScoped<RegionalWildfireQueries>();
builder.Services.AddScoped<IElasticEventSource>(_ => new ElasticSearchClient());
builder.Services.AddScoped<IFailedLoginAlertStore, SqliteFailedLoginAlertStore>();
builder.Services.AddHttpClient<GmailOAuthTokenProvider>(client => client.Timeout = TimeSpan.FromSeconds(10));
builder.Services.AddScoped<IEmailSender, SqliteEmailSender>();
builder.Services.AddHttpClient<ProviderAwareLlmClient>(client => client.Timeout = TimeSpan.FromMinutes(5))
    .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler { AllowAutoRedirect = false });
builder.Services.AddScoped<ILlmConnectionTester>(services =>
    services.GetRequiredService<ProviderAwareLlmClient>());
builder.Services.AddScoped<ILlmChatCompletionClient>(services =>
    services.GetRequiredService<ProviderAwareLlmClient>());
builder.Services.AddScoped<IRoleDirectory, SqliteRoleDirectory>();
builder.Services.AddScoped<IRoleWriter, SqliteRoleDirectory>();
builder.Services.AddScoped<RoleQueries>();
builder.Services.AddScoped<RoleCommands>();
builder.Services.AddScoped<IUserDirectory, SqliteUserDirectory>();
builder.Services.AddScoped<UserDirectoryQueries>();
builder.Services.AddScoped<IUserAdminStore, SqliteUserAdminStore>();
builder.Services.AddScoped<UserAdminCommands>();
builder.Services.AddScoped<ISiteTypeDirectory, SqliteSiteTypeDirectory>();
builder.Services.AddScoped<SiteTypeQueries>();

var app = builder.Build();
app.UseMiddleware<SessionAuthenticationMiddleware>();
app.MapControllers();

app.Run();

static bool ReadEnvironmentBoolean(string? value, bool fallback, string name)
{
    if (value is null)
    {
        return fallback;
    }
    return bool.TryParse(value, out var parsed)
        ? parsed
        : throw new InvalidOperationException($"{name} must be true or false.");
}

static double ReadEnvironmentDouble(string? value, double fallback, string name)
{
    if (value is null)
    {
        return fallback;
    }
    if (!double.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out var parsed)
        || !double.IsFinite(parsed)
        || parsed <= 0
        || parsed > 120)
    {
        throw new InvalidOperationException($"{name} must be greater than 0 and at most 120.");
    }
    return parsed;
}

static int ReadEnvironmentInteger(string? value, int fallback, string name)
{
    if (value is null)
    {
        return fallback;
    }
    return int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed)
        && parsed is >= 1 and <= 5000
        ? parsed
        : throw new InvalidOperationException($"{name} must be an integer between 1 and 5000.");
}

public partial class Program { }
