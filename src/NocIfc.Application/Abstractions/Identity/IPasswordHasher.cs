namespace NocIfc.Application.Abstractions.Identity;

public interface IPasswordHasher
{
    string Hash(string password);
}
