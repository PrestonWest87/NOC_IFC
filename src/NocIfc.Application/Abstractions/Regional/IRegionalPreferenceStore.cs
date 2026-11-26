namespace NocIfc.Application.Abstractions.Regional;

public interface IRegionalPreferenceStore
{
    Task<IReadOnlyList<string?>> GetWeatherPreferencesAsync(string username, CancellationToken cancellationToken);
    Task ReplaceWeatherPreferencesAsync(
        string username,
        IReadOnlyList<string> alertTypes,
        CancellationToken cancellationToken);
}
