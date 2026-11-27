using NocIfc.Application.Features.OperationalEmail;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class OperationalEmailTemplateCatalogTests
{
    [Fact]
    public void ContainsTheComposeTemplatesAndSpecialRoutingCapabilities()
    {
        Assert.Equal(11, OperationalEmailTemplateCatalog.All.Count);
        var templates = OperationalEmailTemplateCatalog.All.ToDictionary(template => template.Key, StringComparer.Ordinal);
        Assert.True(templates["after_hours_onpage"].RecipientsMode == "to_only");
        Assert.False(templates["after_hours_onpage"].AllowsCc);
        Assert.True(templates["morning_report"].AllowsAttachments);
        Assert.Equal("global_shift_analysis", templates["morning_report"].LiveSource);
        Assert.True(templates["fiber_maintenance_notice"].NetworkOrderAutofill);
        Assert.True(templates["fiber_outage_onpage"].OnpageTo);
        Assert.Contains(templates["fiber_outage_onpage"].Fields, field => field.Key == "closest_hand_hole");
        Assert.Equal(new[] { "maintenance_notice", "fiber_maintenance_notice" },
            templates["maintenance_complete"].SourceTemplateKeys);
    }
}
