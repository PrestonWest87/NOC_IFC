using NocIfc.Domain.Identity;

namespace NocIfc.Application.Abstractions.Identity;

public interface IFailedLoginAlertStore
{
    Task<FailedLoginAlert?> RecordAsync(string? username, string? sourceIp, CancellationToken cancellationToken);
}
