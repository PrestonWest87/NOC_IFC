using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using NocIfc.Application.Abstractions.Dashboard;
using NocIfc.Application.Abstractions.Email;
using NocIfc.Application.Abstractions.OperationalEmail;
using NocIfc.Application.Abstractions.Settings;
using NocIfc.Application.Features.OperationalEmail;
using NocIfc.Infrastructure.Email;
using NocIfc.Infrastructure.Persistence.Sqlite;
using NocIfc.Worker;

var builder = Host.CreateApplicationBuilder(args);
var databaseUrl = builder.Configuration["DATABASE_URL"]
    ?? throw new InvalidOperationException("DATABASE_URL is required.");

builder.Services.AddSingleton(new SqliteConnectionFactory(databaseUrl));
builder.Services.AddSingleton<SqliteReadinessProbe>();
builder.Services.AddScoped<IOperationalEmailStore, SqliteOperationalEmailStore>();
builder.Services.AddScoped<IAiSmtpSettingsStore, SqliteAiSmtpSettingsStore>();
builder.Services.AddScoped<IOperationalDashboardStore, SqliteOperationalDashboardStore>();
builder.Services.AddHttpClient<GmailOAuthTokenProvider>(client => client.Timeout = TimeSpan.FromSeconds(10));
builder.Services.AddScoped<SqliteEmailSender>();
builder.Services.AddScoped<IOperationalEmailSender>(services => services.GetRequiredService<SqliteEmailSender>());
builder.Services.AddScoped<OperationalEmailQueueProcessor>();
builder.Services.AddHostedService<OperationalEmailQueueWorker>();

await builder.Build().RunAsync();
