using NocIfc.Application.Features.Settings;

namespace NocIfc.Application.Abstractions.Settings;

public interface IApplicationSettingsStore
{
    Task<GlobalApplicationSettings?> GetAsync(CancellationToken cancellationToken);
    Task<bool> ActiveEmailProfileIsReadyAsync(CancellationToken cancellationToken);
    Task SaveAsync(GlobalApplicationSettingsUpdate settings, CancellationToken cancellationToken);
}
