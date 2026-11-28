using NocIfc.Infrastructure.Security;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class BCryptPasswordVerifierTests
{
    [Fact]
    public void HashesWithIndependentSaltsAndTheCurrentWorkFactor()
    {
        const string password = "NocIfc password salt test 2026";
        var hasher = new BCryptPasswordHasher();
        var verifier = new BCryptPasswordVerifier();
        var first = hasher.Hash(password);
        var second = hasher.Hash(password);

        Assert.NotEqual(first, second);
        Assert.Contains("$13$", first);
        Assert.True(verifier.Verify(password, first));
        Assert.True(verifier.Verify(password, second));
    }

    [Fact]
    public void VerifiesExistingPythonBcryptHashes()
    {
        var verifier = new BCryptPasswordVerifier();
        const string hash = "$2b$04$0nVrv8HTA99lGMsDPALhUeDuvupAJyGHc/ctBUpsRUFszYNf2IwK6";

        Assert.True(verifier.Verify("NocIfc login compatibility test", hash));
        Assert.False(verifier.Verify("wrong", hash));
        Assert.False(verifier.Verify("password", "invalid-hash"));
    }
}
