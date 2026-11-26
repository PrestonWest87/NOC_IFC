namespace NocIfc.Domain.Settings;

public sealed record FiberEmailContactEntry(
    int Id,
    string Name,
    string Company,
    string Email,
    string? Phone,
    int SortOrder);

public sealed record FiberEmailContactValue(string Name, string Company, string Email, string? Phone);

public sealed record OnpageEmailContactEntry(
    int Id,
    string Department,
    string Email,
    int SortOrder);

public sealed record OnpageEmailContactValue(string Department, string Email);

public sealed record NetworkOrderCircuitEntry(
    int Id,
    string ALocation,
    string ZLocation,
    string CircuitNetworkOrderId,
    string Company,
    IReadOnlyList<string> AssociatedCircuitNetworkOrderIds,
    int SortOrder);

public sealed record NetworkOrderCircuitValue(
    string ALocation,
    string ZLocation,
    string CircuitNetworkOrderId,
    string Company,
    IReadOnlyList<string> AssociatedCircuitNetworkOrderIds);
