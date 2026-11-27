using NocIfc.Application.Features.Threat;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class ArticleCategorizerTests
{
    [Fact]
    public void ReturnsHighestMatchingSourceCategoryOrGeneral()
    {
        Assert.Equal("Cyber: Exploits & Vulns", ArticleCategorizer.CategorizeText("CVE-2026-1234 vulnerability patch available"));
        Assert.Equal("ICS/OT & SCADA", ArticleCategorizer.CategorizeText("Modbus RTU industrial control network"));
        Assert.Equal("General", ArticleCategorizer.CategorizeText("Routine public meeting scheduled for next week."));
    }
}
