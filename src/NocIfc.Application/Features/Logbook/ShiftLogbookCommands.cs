using System.Globalization;
using NocIfc.Application.Abstractions.Logbook;
using NocIfc.Domain.Identity;
using NocIfc.Domain.Logbook;

namespace NocIfc.Application.Features.Logbook;

public sealed record ShiftLogbookUpdateResult(
    string Status,
    string? Message,
    int? Id,
    bool? IsDeleted,
    bool Forbidden = false);

public sealed class ShiftLogbookCommands(IShiftLogbookStore logs)
{
    private const string HistoryGrant = "Tab: Shift Log -> History";
    private const string ManageGrant = "Action: Manage Shift Logs";
    private static readonly TimeZoneInfo CentralTimeZone = TimeZoneInfo.FindSystemTimeZoneById("America/Chicago");

    public async Task<IReadOnlyList<ShiftLogEntry>> GetEntriesAsync(
        AuthenticatedUser user,
        string roleFilter,
        string? startDate,
        string? endDate,
        CancellationToken cancellationToken)
    {
        var role = user.IsAdministrator ? roleFilter : user.Role;
        var startUtc = ParseCentralDate(startDate);
        var endUtc = ParseCentralDate(endDate);
        var endExclusiveUtc = endUtc?.AddDays(1);
        if (!user.IsAdministrator && !user.AllowedActions.Contains(HistoryGrant, StringComparer.Ordinal))
        {
            var localToday = TimeZoneInfo.ConvertTime(DateTimeOffset.UtcNow, CentralTimeZone).Date;
            var localMidnight = DateTime.SpecifyKind(localToday, DateTimeKind.Unspecified);
            startUtc = TimeZoneInfo.ConvertTimeToUtc(localMidnight, CentralTimeZone);
            endExclusiveUtc = startUtc.Value.AddDays(1);
        }
        return await logs.GetEntriesAsync(
            string.Equals(role, "All", StringComparison.Ordinal) ? null : role,
            startUtc,
            endExclusiveUtc,
            cancellationToken);
    }

    public Task<IReadOnlyList<string>> GetRoleNamesAsync(CancellationToken cancellationToken) =>
        logs.GetRoleNamesAsync(cancellationToken);

    public async Task CreateAsync(
        AuthenticatedUser user,
        string role,
        string shiftPeriod,
        string content,
        string? customDate,
        CancellationToken cancellationToken)
    {
        if (shiftPeriod is not ("Morning" or "Afternoon" or "Evening" or "No Shift"))
        {
            throw new ArgumentException("Invalid shift period.");
        }
        if (string.IsNullOrWhiteSpace(content) || content.Length > 20_000)
        {
            throw new ArgumentException("Shift log content is required and must be 20,000 characters or fewer.");
        }

        var authorRole = user.IsAdministrator ? role : user.Role;
        var analyst = await logs.GetUserFullNameAsync(user.Id, cancellationToken);
        if (string.IsNullOrWhiteSpace(analyst)) analyst = user.Username;
        var createdAtUtc = DateTime.UtcNow;
        if (!string.IsNullOrWhiteSpace(customDate))
        {
            if (!DateTime.TryParse(customDate, CultureInfo.InvariantCulture, DateTimeStyles.None, out var selectedDate))
            {
                throw new ArgumentException("custom_date must be an ISO date.");
            }
            var localNow = TimeZoneInfo.ConvertTime(DateTimeOffset.UtcNow, CentralTimeZone);
            var localTimestamp = DateTime.SpecifyKind(selectedDate.Date.Add(localNow.TimeOfDay), DateTimeKind.Unspecified);
            createdAtUtc = TimeZoneInfo.ConvertTimeToUtc(localTimestamp, CentralTimeZone);
        }
        await logs.CreateAsync(analyst, authorRole, shiftPeriod, content, createdAtUtc, createdAtUtc, cancellationToken);
    }

    public async Task<ShiftLogbookUpdateResult> UpdateDeletedAsync(
        AuthenticatedUser user,
        int entryId,
        bool? isDeleted,
        CancellationToken cancellationToken)
    {
        var entry = await logs.GetByIdAsync(entryId, cancellationToken);
        if (entry is null)
        {
            return new ShiftLogbookUpdateResult("error", "Entry not found", null, null);
        }
        var fullName = await logs.GetUserFullNameAsync(user.Id, cancellationToken);
        var ownsEntry = string.Equals(entry.Analyst, user.Username, StringComparison.Ordinal)
            || !string.IsNullOrEmpty(fullName) && string.Equals(entry.Analyst, fullName, StringComparison.Ordinal);
        var canManage = user.AllowedActions.Contains(ManageGrant, StringComparer.Ordinal);
        if (!user.IsAdministrator && !ownsEntry && !canManage)
        {
            return new ShiftLogbookUpdateResult("forbidden", "Missing action permission.", entryId, entry.IsDeleted, true);
        }
        var updated = isDeleted is { } requested
            ? await logs.SetDeletedAsync(entryId, requested, cancellationToken)
            : true;
        var current = updated ? await logs.GetByIdAsync(entryId, cancellationToken) : null;
        return current is null
            ? new ShiftLogbookUpdateResult("error", "Entry not found", null, null)
            : new ShiftLogbookUpdateResult("ok", null, entryId, current.IsDeleted);
    }

    private static DateTime? ParseCentralDate(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        var timeMarker = value.IndexOf('T');
        var hasOffset = value.EndsWith("Z", StringComparison.OrdinalIgnoreCase)
            || timeMarker >= 0 && (value.LastIndexOf('+') > timeMarker || value.LastIndexOf('-') > timeMarker);
        if (hasOffset && DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var offsetDate))
        {
            return offsetDate.UtcDateTime;
        }
        if (!DateTime.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.None, out var local))
        {
            throw new ArgumentException("Date filters must be ISO dates or timestamps.");
        }
        return TimeZoneInfo.ConvertTimeToUtc(DateTime.SpecifyKind(local, DateTimeKind.Unspecified), CentralTimeZone);
    }
}
