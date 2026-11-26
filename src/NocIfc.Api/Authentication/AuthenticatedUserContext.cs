using NocIfc.Domain.Identity;

namespace NocIfc.Api.Authentication;

public static class AuthenticatedUserContext
{
    private static readonly object ItemKey = new();
    private static readonly object TokenItemKey = new();

    public static AuthenticatedUser? GetUser(HttpContext context) =>
        context.Items.TryGetValue(ItemKey, out var value) ? value as AuthenticatedUser : null;

    public static string? GetToken(HttpContext context) =>
        context.Items.TryGetValue(TokenItemKey, out var value) ? value as string : null;

    internal static void Set(HttpContext context, AuthenticatedUser user, string token)
    {
        context.Items[ItemKey] = user;
        context.Items[TokenItemKey] = token;
    }
}
