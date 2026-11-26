namespace NocIfc.Application.Abstractions.Regional;

public interface INwsForecastProvider
{
    Task<string?> GetForecastPeriodsJsonAsync(
        double latitude,
        double longitude,
        CancellationToken cancellationToken);
}
