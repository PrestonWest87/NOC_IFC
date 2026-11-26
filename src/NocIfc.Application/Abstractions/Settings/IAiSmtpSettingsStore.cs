using NocIfc.Application.Features.Settings;

namespace NocIfc.Application.Abstractions.Settings;

public interface IAiSmtpSettingsStore
{
    Task<AiSmtpSettings?> GetAsync(CancellationToken cancellationToken);
    Task<string> GetSavedLlmApiKeyForProviderAsync(string provider, CancellationToken cancellationToken);
    Task SaveAsync(AiSmtpSettingsUpdate update, CancellationToken cancellationToken);
}
