using NocIfc.Application.Abstractions.Regional;

namespace NocIfc.Application.Features.Regional;

public sealed class RegionalWeatherPreferenceCommands(IRegionalPreferenceStore preferences)
{
    public Task<IReadOnlyList<string?>> GetAsync(string username, CancellationToken cancellationToken) =>
        preferences.GetWeatherPreferencesAsync(username, cancellationToken);

    public Task ReplaceAsync(
        string username,
        IReadOnlyList<string> alertTypes,
        CancellationToken cancellationToken) =>
        preferences.ReplaceWeatherPreferencesAsync(username, alertTypes, cancellationToken);
}
