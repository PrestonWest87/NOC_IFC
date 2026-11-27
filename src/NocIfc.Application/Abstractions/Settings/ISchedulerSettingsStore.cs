using NocIfc.Application.Features.Settings;

namespace NocIfc.Application.Abstractions.Settings;

public interface ISchedulerSettingsStore
{
    Task<SchedulerSettingsState> GetAsync(CancellationToken cancellationToken);
    Task<int> SaveAsync(
        string jobKey,
        SchedulerSchedule schedule,
        string updatedBy,
        int actorUserId,
        CancellationToken cancellationToken);
    Task MarkAppliedAsync(int revision, CancellationToken cancellationToken);
}
