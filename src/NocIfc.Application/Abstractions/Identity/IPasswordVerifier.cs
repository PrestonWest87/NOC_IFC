namespace NocIfc.Application.Abstractions.Identity;

public interface IPasswordVerifier
{
    bool Verify(string password, string passwordHash);
}
