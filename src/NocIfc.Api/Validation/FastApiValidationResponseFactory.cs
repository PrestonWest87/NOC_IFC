using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using System.Text.Json;

namespace NocIfc.Api.Validation;

public static class FastApiValidationResponseFactory
{
    public static IActionResult Create(ActionContext context)
    {
        var parameters = context.ActionDescriptor.Parameters.OfType<ControllerParameterDescriptor>().ToArray();
        var details = context.ModelState
            .Where(entry => entry.Value?.Errors.Count > 0)
            .SelectMany(entry => entry.Value!.Errors.Select(error =>
            {
                var parameter = parameters.FirstOrDefault(candidate =>
                    string.Equals(entry.Key, candidate.Name, StringComparison.OrdinalIgnoreCase)
                    || entry.Key.StartsWith(candidate.Name + ".", StringComparison.OrdinalIgnoreCase));
                var source = parameter?.BindingInfo?.BindingSource;
                var location = source == BindingSource.Query ? "query"
                    : source == BindingSource.Path ? "path"
                    : source == BindingSource.Header ? "header"
                    : "body";
                var field = parameter is not null && entry.Key.Length > parameter.Name.Length
                    ? entry.Key[(parameter.Name.Length + 1)..]
                    : location == "body" ? entry.Key : parameter?.Name ?? entry.Key;
                var locationFields = field.Split('.', StringSplitOptions.RemoveEmptyEntries)
                    .Select(JsonNamingPolicy.SnakeCaseLower.ConvertName);
                var message = error.Exception is JsonException
                    ? "JSON decode error"
                    : string.IsNullOrWhiteSpace(error.ErrorMessage)
                        ? "Input should be a valid value"
                        : error.ErrorMessage;
                return new
                {
                    type = error.Exception is JsonException ? "json_invalid" : "value_error",
                    loc = new object[] { location }.Concat(locationFields.Cast<object>()).ToArray(),
                    msg = message,
                    input = entry.Value.AttemptedValue,
                };
            }))
            .ToArray();
        return new UnprocessableEntityObjectResult(new { detail = details });
    }
}
