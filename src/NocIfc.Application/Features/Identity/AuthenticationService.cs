using NocIfc.Application.Abstractions.Identity;
using NocIfc.Domain.Identity;

namespace NocIfc.Application.Features.Identity;

public sealed record LoginResult(LoginUser User, string Token);
public sealed record RegistrationInput(
    string? Token,
    string? Password,
    string? FullName,
    string? JobTitle,
    string? ContactInfo,
    string? DefaultShift,
    string? Theme);

public sealed class RegistrationException(string message) : Exception(message);

public sealed class AuthenticationService(
    IAuthenticationStore authentication,
    IPasswordVerifier passwords,
    IPasswordHasher passwordHasher,
    SiteTypeQueries siteTypes)
{
    private static readonly HashSet<string> ValidThemes = new(StringComparer.Ordinal)
    {
        "standard", "noc-terminal", "high-contrast", "cyberpunk", "solarized-dark", "midnight-ocean",
        "arctic-command", "ember-watch", "forest-ops", "amethyst-grid", "slate-steel", "paper-light",
        "nordic-frost", "dracula-console", "synthwave", "desert-signal", "olive-command", "mono-ops",
        "rose-pine", "oceanic-teal", "copper-wire",
    };

    public async Task<LoginResult?> AuthenticateAsync(
        string username,
        string password,
        CancellationToken cancellationToken)
    {
        var credential = await authentication.FindCredentialsAsync(username, cancellationToken);
        if (credential is null || !credential.IsActive || string.IsNullOrEmpty(credential.PasswordHash))
        {
            return null;
        }

        if (!passwords.Verify(password, credential.PasswordHash))
        {
            return null;
        }

        var token = Guid.NewGuid().ToString();
        var user = await authentication.CreateSessionAsync(
            credential,
            token,
            DateTime.UtcNow,
            cancellationToken);
        if (user is null)
        {
            return null;
        }

        return new LoginResult(await ApplyAdministratorGrantsAsync(user, cancellationToken), token);
    }

    public async Task<LoginUser?> GetCurrentUserAsync(int userId, CancellationToken cancellationToken)
    {
        var user = await authentication.GetCurrentUserAsync(userId, cancellationToken);
        return user is null ? null : await ApplyAdministratorGrantsAsync(user, cancellationToken);
    }

    public Task RevokeSessionAsync(int userId, string token, CancellationToken cancellationToken) =>
        authentication.RevokeSessionAsync(userId, token, cancellationToken);

    public async Task UpdateThemeAsync(int userId, string theme, CancellationToken cancellationToken)
    {
        if (!ValidThemes.Contains(theme))
        {
            throw new ArgumentException("Invalid theme.");
        }
        if (!await authentication.UpdateThemeAsync(userId, theme, cancellationToken))
        {
            throw new ArgumentException("User not found.");
        }
    }

    public async Task UpdateProfileAsync(
        int userId,
        string? fullName,
        string? jobTitle,
        string? contactInfo,
        string? defaultShift,
        string? oldPassword,
        string? newPassword,
        CancellationToken cancellationToken)
    {
        var expectedPasswordHash = default(string?);
        var newPasswordHash = default(string?);
        if (!string.IsNullOrEmpty(newPassword))
        {
            if (newPassword.EnumerateRunes().Count() < 12)
            {
                throw new ArgumentException("Password must be at least 12 characters.");
            }

            expectedPasswordHash = await authentication.GetPasswordHashAsync(userId, cancellationToken);
            if (string.IsNullOrEmpty(expectedPasswordHash))
            {
                throw new ArgumentException("User not found.");
            }
            if (!passwords.Verify(oldPassword ?? "", expectedPasswordHash))
            {
                throw new ArgumentException("Incorrect current password.");
            }
            newPasswordHash = passwordHasher.Hash(newPassword);
        }

        var updated = await authentication.UpdateProfileAsync(
            userId,
            (fullName ?? "").Trim(),
            (jobTitle ?? "").Trim(),
            (contactInfo ?? "").Trim(),
            (defaultShift ?? "").Trim(),
            expectedPasswordHash,
            newPasswordHash,
            cancellationToken);
        if (!updated)
        {
            throw new ArgumentException(newPasswordHash is null ? "User not found." : "Incorrect current password.");
        }
    }

    public Task<RegistrationInviteInfo?> GetRegistrationInviteAsync(
        string? token,
        CancellationToken cancellationToken) =>
        string.IsNullOrEmpty(token)
            ? Task.FromResult<RegistrationInviteInfo?>(null)
            : authentication.GetRegistrationInviteAsync(CapabilityTokenHash.Sha256(token), DateTime.UtcNow, cancellationToken);

    public async Task<LoginResult> CompleteRegistrationAsync(
        RegistrationInput input,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(input);
        if (string.IsNullOrEmpty(input.Token) || (input.Password?.EnumerateRunes().Count() ?? 0) < 12)
        {
            throw new RegistrationException("Password must be at least 12 characters.");
        }
        var theme = input.Theme ?? "standard";
        if (!ValidThemes.Contains(theme))
        {
            throw new RegistrationException("Invalid theme.");
        }

        var tokenHash = CapabilityTokenHash.Sha256(input.Token);
        if (await authentication.GetRegistrationInviteAsync(tokenHash, DateTime.UtcNow, cancellationToken) is null)
        {
            throw new RegistrationException("This registration link is invalid, expired, or already used.");
        }

        var token = Guid.NewGuid().ToString();
        var now = DateTime.UtcNow;
        var user = await authentication.CompleteRegistrationAsync(
            tokenHash,
            passwordHasher.Hash(input.Password!),
            (input.FullName ?? "").Trim(),
            (input.JobTitle ?? "").Trim(),
            (input.ContactInfo ?? "").Trim(),
            string.IsNullOrEmpty(input.DefaultShift) ? "No Shift" : input.DefaultShift.Trim(),
            theme,
            token,
            now,
            cancellationToken);
        if (user is null)
        {
            throw new RegistrationException("This registration link is invalid, expired, or already used.");
        }

        return new LoginResult(await ApplyAdministratorGrantsAsync(user, cancellationToken), token);
    }

    private async Task<LoginUser> ApplyAdministratorGrantsAsync(LoginUser user, CancellationToken cancellationToken) =>
        RoleAccessPolicy.IsAdministratorRole(user.Role)
            ? user with
            {
                AllowedPages = PermissionCatalog.PageKeys,
                AllowedActions = PermissionCatalog.AdministratorActionKeys,
                AllowedSiteTypes = await siteTypes.ExecuteAsync(cancellationToken),
            }
            : user;

}

public static class FailedLoginAlertText
{
    public static (string Subject, string Body) Format(FailedLoginAlert alert)
    {
        var lines = new List<string>
        {
            "NOC Fusion Center security alert",
            $"{alert.Attempts.Count} failed login attempts occurred within the previous {alert.WindowMinutes} minute(s).",
            $"Alert threshold: {alert.Threshold} attempts.",
            $"Detected at: {IsoUtc(alert.TriggeredAt)}",
            "",
            "Attempted usernames (as submitted):",
        };

        foreach (var attempt in alert.Attempts)
        {
            var sourceIp = string.IsNullOrEmpty(attempt.SourceIp) ? "" : $" from {attempt.SourceIp}";
            lines.Add($"- {IsoUtc(attempt.AttemptedAt)} — {System.Text.Json.JsonSerializer.Serialize(attempt.Username)}{sourceIp}");
        }
        lines.AddRange(["", "Passwords are not collected or included in this alert."]);
        return ("Multiple failed login attempts detected", string.Join("\n", lines));
    }

    private static string IsoUtc(DateTime value) =>
        value.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", System.Globalization.CultureInfo.InvariantCulture);
}
