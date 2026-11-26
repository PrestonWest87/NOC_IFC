using NocIfc.Application.Abstractions.Identity;

namespace NocIfc.Infrastructure.Security;

public sealed class BCryptPasswordVerifier : IPasswordVerifier
{
    public bool Verify(string password, string passwordHash)
    {
        try
        {
            return BCrypt.Net.BCrypt.Verify(password, passwordHash);
        }
        catch (ArgumentException)
        {
            return false;
        }
        catch (BCrypt.Net.SaltParseException)
        {
            return false;
        }
    }
}

public sealed class BCryptPasswordHasher : IPasswordHasher
{
    public string Hash(string password) => BCrypt.Net.BCrypt.HashPassword(password, workFactor: 12);
}
