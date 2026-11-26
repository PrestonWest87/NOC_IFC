using NocIfc.Application.Abstractions.Identity;
using NocIfc.Domain.Identity;

namespace NocIfc.Application.Features.Identity;

public sealed class RecoveryReviewerQueries(IUserDirectory users, IRoleDirectory roles)
{
    public async Task<IReadOnlyList<string>> GetEmailAddressesAsync(
        string requiredAction,
        int? excludeUserId,
        CancellationToken cancellationToken)
    {
        var roleDefinitions = await roles.GetAllAsync(cancellationToken);
        var userRows = await users.GetAllAsync(cancellationToken);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var reviewers = new List<string>();
        foreach (var reviewer in userRows)
        {
            if (reviewer.Id == excludeUserId
                || !reviewer.IsActive
                || !reviewer.EmailVerified
                || string.IsNullOrEmpty(reviewer.Email))
            {
                continue;
            }

            var isAdmin = RoleAccessPolicy.IsAdministratorRole(reviewer.Role);
            var role = roleDefinitions.FirstOrDefault(item =>
                string.Equals(item.Name, reviewer.Role, StringComparison.OrdinalIgnoreCase));
            var authorized = isAdmin || role is not null
                && role.AllowedActions.Contains(requiredAction, StringComparer.Ordinal)
                && role.AllowedActions.Contains("Tab: Settings -> Users & Roles", StringComparer.Ordinal)
                && role.AllowedPages.Contains("Settings & Admin", StringComparer.Ordinal);
            if (authorized && seen.Add(reviewer.Email))
            {
                reviewers.Add(reviewer.Email);
            }
        }

        return reviewers;
    }
}
