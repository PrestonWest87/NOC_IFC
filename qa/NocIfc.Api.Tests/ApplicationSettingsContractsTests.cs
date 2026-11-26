using System.Text.Json;
using NocIfc.Api.Contracts;
using Xunit;

namespace NocIfc.Api.Tests;

public sealed class ApplicationSettingsContractsTests
{
    private static readonly JsonSerializerOptions WebJson = new(JsonSerializerDefaults.Web);

    [Fact]
    public void IntegrationPatchDistinguishesAnExplicitNullResetFromOmittedFields()
    {
        var request = JsonSerializer.Deserialize<IntegrationSettingsUpdateRequest>(
            """{"elastic_api_key":null,"elastic_url":"https://elastic.example.com"}""",
            WebJson)!;

        var update = request.ToUpdate();

        Assert.Contains("elastic_api_key", update.ProvidedFields);
        Assert.Contains("elastic_url", update.ProvidedFields);
        Assert.DoesNotContain("risk_alert_recipients", update.ProvidedFields);
        Assert.Null(update.ElasticApiKey);
        Assert.Equal("https://elastic.example.com", update.ElasticUrl);
    }

    [Fact]
    public void IntegrationPatchRejectsUnknownSettingsAndWrongJsonTypes()
    {
        var unknown = JsonSerializer.Deserialize<IntegrationSettingsUpdateRequest>(
            """{"smtp_password":"must-not-be-accepted"}""",
            WebJson)!;
        Assert.Throws<ArgumentException>(() => unknown.ToUpdate());

        var wrongType = JsonSerializer.Deserialize<IntegrationSettingsUpdateRequest>(
            """{"elastic_verify_certs":"yes"}""",
            WebJson)!;
        Assert.Throws<ArgumentException>(() => wrongType.ToUpdate());
    }

    [Fact]
    public void SchedulerPatchRequiresTypedFieldsAndRejectsUnknownOrNullValues()
    {
        var valid = JsonSerializer.Deserialize<SchedulerUpdateRequest>(
            """{"schedule":{"every_value":10,"enabled":true}}""",
            WebJson)!;
        var update = valid.ToUpdate();
        Assert.Equal(10, update.EveryValue);
        Assert.True(update.Enabled);

        var unknown = JsonSerializer.Deserialize<SchedulerUpdateRequest>(
            """{"schedule":{"interval":10}}""",
            WebJson)!;
        Assert.Throws<ArgumentException>(() => unknown.ToUpdate());

        var nullValue = JsonSerializer.Deserialize<SchedulerUpdateRequest>(
            """{"schedule":{"every_value":null}}""",
            WebJson)!;
        Assert.Throws<ArgumentException>(() => nullValue.ToUpdate());
    }
}
