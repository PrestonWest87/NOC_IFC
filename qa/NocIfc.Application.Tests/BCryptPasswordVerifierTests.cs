using NocIfc.Infrastructure.Security;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class BCryptPasswordVerifierTests
{
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
