using System.Reflection;
using System.Text.Json;
using NocIfc.Api.Authorization;
using NocIfc.Api.Controllers;
using NocIfc.Api.Contracts;
using NocIfc.Application.Abstractions.Threat;
using Xunit;

namespace NocIfc.Api.Tests;

public sealed class KeywordAnalysisControllerTests
{
    [Fact]
    public void ControllerAndRecategorizeActionDeclareTheirPermissionBoundaries()
    {
        var controllerPage = typeof(KeywordAnalysisController)
            .GetCustomAttributes(typeof(RequirePageAttribute), inherit: true)
            .SingleOrDefault();
        var recategorizeAction = typeof(KeywordAnalysisController)
            .GetMethod(nameof(KeywordAnalysisController.Recategorize))!
            .GetCustomAttributes(typeof(RequireActionAttribute), inherit: true)
            .SingleOrDefault();

        Assert.NotNull(controllerPage);
        Assert.NotNull(recategorizeAction);
    }

    [Fact]
    public void OverviewResponseKeepsTheFrontendSnakeCaseFields()
    {
        var response = KeywordAnalysisOverviewResponse.From(new KeywordAnalysisOverview(
            10, 20, 30, 50, 10, 8, 2, 12, 8));
        using var json = JsonDocument.Parse(JsonSerializer.Serialize(response,
            new JsonSerializerOptions(JsonSerializerDefaults.Web)));
        var root = json.RootElement;

        Assert.Equal(10, root.GetProperty("total_keywords").GetInt32());
        Assert.Equal(30, root.GetProperty("avg_weight").GetDouble());
        Assert.Equal(12, root.GetProperty("articles_with_keywords").GetInt32());
    }
}
