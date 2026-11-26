using NocIfc.Application.Features.Settings;

namespace NocIfc.Application.Abstractions.Settings;

public interface IAssetInventoryStore
{
    Task ReplaceSoftwareAssetsAsync(IReadOnlyList<string> names, CancellationToken cancellationToken);
    Task ReplaceHardwareAssetsAsync(IReadOnlyList<HardwareAssetImportRow> assets, CancellationToken cancellationToken);
}
