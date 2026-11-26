using System.Text.RegularExpressions;

namespace NocIfc.Application.Features.Settings;

internal static class SiteContactRules
{
    private static readonly IReadOnlyDictionary<string, int> Limits = new Dictionary<string, int>(StringComparer.Ordinal)
    {
        ["name"] = 128,
        ["phone"] = 64,
        ["email"] = 254,
    };

    private static readonly Regex EmailPattern = new(
        "^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\\.)+[A-Za-z]{2,63}$",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex PhoneExtensionPattern = new(@" *(?:ext\.?|x|#) *[0-9]{1,10}$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex PhoneCorePattern = new(@"^\+?(?:[0-9]|\([0-9]{1,5}\))[0-9(). -]*$", RegexOptions.CultureInvariant | RegexOptions.Compiled);

    public static string? NormalizeOptional(string field, string? value)
    {
        if (!Limits.TryGetValue(field, out var maximum))
        {
            throw new ArgumentException($"Unsupported site contact field: {field}.");
        }
        if (value is null)
        {
            return null;
        }
        if (value.Any(character => character < ' ' || character == 127))
        {
            throw new ArgumentException($"Contact {field} cannot contain control characters.");
        }
        var normalized = value.Trim();
        if (normalized.Length == 0)
        {
            return null;
        }
        if (normalized.Length > maximum)
        {
            throw new ArgumentException($"Contact {field} must be at most {maximum} characters.");
        }
        if (field == "email" && !EmailPattern.IsMatch(normalized))
        {
            throw new ArgumentException("Contact email must be a valid single email address.");
        }
        if (field == "phone")
        {
            ValidatePhone(normalized);
        }
        return normalized;
    }

    private static void ValidatePhone(string value)
    {
        var extension = PhoneExtensionPattern.Match(value);
        var number = extension.Success ? value[..extension.Index].TrimEnd() : value;
        if (!PhoneCorePattern.IsMatch(number))
        {
            throw new ArgumentException("Contact phone must use digits, an optional leading +, common phone separators, and an optional extension.");
        }
        if (number.Count(character => character == '(') != number.Count(character => character == ')')
            || number.Count(character => character == '(') > 1)
        {
            throw new ArgumentException("Contact phone must use balanced parentheses.");
        }
        if (number.Contains('('))
        {
            var opening = number.IndexOf('(');
            var closing = number.IndexOf(')', opening + 1);
            if (closing < 0 || number.IndexOf(')', closing + 1) >= 0
                || number[(opening + 1)..closing].Length == 0
                || number[(opening + 1)..closing].Any(character => character is < '0' or > '9'))
            {
                throw new ArgumentException("Contact phone must use balanced parentheses.");
            }
        }
        var digitCount = number.Count(char.IsDigit);
        if (digitCount is < 7 or > 15)
        {
            throw new ArgumentException("Contact phone must contain 7 to 15 digits, excluding an optional extension.");
        }
    }
}
