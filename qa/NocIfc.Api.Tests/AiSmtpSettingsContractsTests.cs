using System.Text.Json;
using NocIfc.Api.Contracts;
using Xunit;

namespace NocIfc.Api.Tests;

public sealed class AiSmtpSettingsContractsTests
{
    private static readonly JsonSerializerOptions WebJson = new(JsonSerializerDefaults.Web);

    [Fact]
    public void ConfigPatchTracksExplicitClearAndLeavesOmittedSecretsUntouched()
    {
        var request = JsonSerializer.Deserialize<AiSmtpSettingsUpdateRequest>(
            """{"llm_provider":"ollama_native","smtp_server":"smtp.example","smtp_password":null}""",
            WebJson)!;

        var update = request.ToUpdate();

        Assert.Contains("llm_provider", update.ProvidedFields);
        Assert.Contains("smtp_password", update.ProvidedFields);
        Assert.DoesNotContain("llm_api_key", update.ProvidedFields);
        Assert.Null(update.SmtpPassword);
    }

    [Fact]
    public void ConfigPatchRejectsUnknownFieldsAndInvalidSettingTypes()
    {
        var unknown = JsonSerializer.Deserialize<AiSmtpSettingsUpdateRequest>(
            """{"smtp_password":"secret","allowed_actions":["Action: Manage Users"]}""",
            WebJson)!;
        Assert.Throws<ArgumentException>(() => unknown.ToUpdate());

        var wrongType = JsonSerializer.Deserialize<AiSmtpSettingsUpdateRequest>(
            """{"smtp_enabled":"yes"}""",
            WebJson)!;
        Assert.Throws<ArgumentException>(() => wrongType.ToUpdate());
    }
}
