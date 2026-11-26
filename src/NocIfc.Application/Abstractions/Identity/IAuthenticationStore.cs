using NocIfc.Domain.Identity;

namespace NocIfc.Application.Abstractions.Identity;

public interface IAuthenticationStore
{
    Task<LoginCredential?> FindCredentialsAsync(string username, CancellationToken cancellationToken);
    Task<LoginUser?> CreateSessionAsync(
        LoginCredential credential,
        string token,
        DateTime now,
        CancellationToken cancellationToken);
    Task<LoginUser?> GetCurrentUserAsync(int userId, CancellationToken cancellationToken);
    Task RevokeSessionAsync(int userId, string token, CancellationToken cancellationToken);
    Task<bool> UpdateThemeAsync(int userId, string theme, CancellationToken cancellationToken);
    Task<string?> GetPasswordHashAsync(int userId, CancellationToken cancellationToken);
    Task<bool> UpdateProfileAsync(
        int userId,
        string fullName,
        string jobTitle,
        string contactInfo,
        string defaultShift,
        string? expectedPasswordHash,
        string? newPasswordHash,
        CancellationToken cancellationToken);
    Task<RegistrationInviteInfo?> GetRegistrationInviteAsync(
        string tokenHash,
        DateTime now,
        CancellationToken cancellationToken);
    Task<LoginUser?> CompleteRegistrationAsync(
        string tokenHash,
        string passwordHash,
        string fullName,
        string jobTitle,
        string contactInfo,
        string defaultShift,
        string theme,
        string sessionToken,
        DateTime now,
        CancellationToken cancellationToken);
}
