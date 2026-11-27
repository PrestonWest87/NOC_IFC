using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging.Abstractions;
using NocIfc.Api.Controllers;
using NocIfc.Api.Contracts;
using NocIfc.Api.Validation;
using Xunit;

namespace NocIfc.Api.Tests;

public sealed class FastApiValidationResponseTests
{
    [Fact]
    public void MapsInvalidQueryBindingToFastApiStyle422Details()
    {
        var descriptor = new ControllerActionDescriptor
        {
            Parameters =
            [
                new ControllerParameterDescriptor
                {
                    Name = "days",
                    BindingInfo = new BindingInfo { BindingSource = BindingSource.Query },
                },
            ],
        };
        var context = new ActionContext(new DefaultHttpContext(), new RouteData(), descriptor, new ModelStateDictionary());
        context.ModelState.AddModelError("days", "The value 'bad' is not valid.");

        var response = Assert.IsType<UnprocessableEntityObjectResult>(FastApiValidationResponseFactory.Create(context));
        using var body = JsonDocument.Parse(JsonSerializer.Serialize(response.Value,
            new JsonSerializerOptions(JsonSerializerDefaults.Web)));

        Assert.Equal(422, response.StatusCode);
        Assert.Equal("query", body.RootElement.GetProperty("detail")[0].GetProperty("loc")[0].GetString());
        Assert.Equal("days", body.RootElement.GetProperty("detail")[0].GetProperty("loc")[1].GetString());
    }

    [Fact]
    public async Task MissingLoginFieldsReturn422FieldErrors()
    {
        var controller = new AuthenticationController(null!, null!, null!, null!,
            NullLogger<AuthenticationController>.Instance);

        var response = Assert.IsType<UnprocessableEntityObjectResult>(
            await controller.Login(new LoginRequest(), CancellationToken.None));
        using var body = JsonDocument.Parse(JsonSerializer.Serialize(response.Value,
            new JsonSerializerOptions(JsonSerializerDefaults.Web)));
        var errors = body.RootElement.GetProperty("detail");

        Assert.Equal(422, response.StatusCode);
        Assert.Equal(2, errors.GetArrayLength());
        Assert.Equal("username", errors[0].GetProperty("loc")[1].GetString());
        Assert.Equal("password", errors[1].GetProperty("loc")[1].GetString());
    }
}
