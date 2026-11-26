using System.Security.Cryptography;
using System.Text;

namespace NocIfc.Application.Features.Identity;

public static class CapabilityTokenHash
{
    public static string CreateToken() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
        .TrimEnd('=')
        .Replace('+', '-')
        .Replace('/', '_');

    public static string Sha256(string token) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token))).ToLowerInvariant();
}
