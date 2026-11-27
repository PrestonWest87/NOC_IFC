using System.Net;
using NocIfc.Infrastructure.Integrations.Threat;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class PublicArticleContentClientTests
{
    [Theory]
    [InlineData("https://example.com/article", true)]
    [InlineData("http://8.8.8.8/article", true)]
    [InlineData("http://127.0.0.1/article", false)]
    [InlineData("http://169.254.169.254/latest/meta-data", false)]
    [InlineData("http://192.168.1.10/article", false)]
    [InlineData("https://localhost/article", false)]
    [InlineData("http://example.com:8080/article", false)]
    [InlineData("https://user:secret@example.com/article", false)]
    [InlineData("file:///etc/passwd", false)]
    public void AllowsOnlyHttpUrlsThatCannotDirectlyTargetPrivateAddresses(string url, bool expected) =>
        Assert.Equal(expected, PublicArticleContentClient.IsAllowedUri(url));

    [Fact]
    public void RejectsPrivateAndSpecialPurposeIpAddresses()
    {
        Assert.True(PublicArticleContentClient.IsPublicAddress(IPAddress.Parse("1.1.1.1")));
        Assert.False(PublicArticleContentClient.IsPublicAddress(IPAddress.Parse("10.0.0.5")));
        Assert.False(PublicArticleContentClient.IsPublicAddress(IPAddress.Loopback));
        Assert.False(PublicArticleContentClient.IsPublicAddress(IPAddress.Parse("169.254.0.1")));
        Assert.False(PublicArticleContentClient.IsPublicAddress(IPAddress.Parse("fd00::1")));
    }
}
