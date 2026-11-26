using System.Text.RegularExpressions;

namespace NocIfc.Application.Features.Identity;

public static class EmailAddressRules
{
    private static readonly Regex Pattern = new(
        "^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\\.)+[A-Za-z]{2,63}$",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);

    public static bool IsValid(string value) => value.Length <= 254 && Pattern.IsMatch(value);

    public static string NormalizeRecipients(string? value)
    {
        var recipients = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var candidate in (value ?? "").Split([',', ';', '\n'], StringSplitOptions.RemoveEmptyEntries))
        {
            var address = candidate.Trim();
            if (address.Length == 0)
            {
                continue;
            }
            if (!IsValid(address))
            {
                throw new ArgumentException($"Invalid failed login alert email address: {address[..Math.Min(address.Length, 80)]}");
            }
            if (seen.Add(address))
            {
                recipients.Add(address);
            }
        }
        return string.Join(", ", recipients);
    }

    public static (string Email, string Normalized) NormalizeUserEmail(string? value)
    {
        var email = (value ?? "").Trim();
        if (email.Length == 0 || !IsValid(email))
        {
            throw new ArgumentException("Enter a valid email address.");
        }
        return (email, email.ToLowerInvariant());
    }
}
