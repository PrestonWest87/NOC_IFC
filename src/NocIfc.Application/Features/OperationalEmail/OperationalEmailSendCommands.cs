using System.Globalization;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using NocIfc.Application.Abstractions.Dashboard;
using NocIfc.Application.Abstractions.Email;
using NocIfc.Application.Abstractions.OperationalEmail;
using NocIfc.Application.Abstractions.Settings;
using NocIfc.Application.Features.Identity;
using NocIfc.Application.Features.Settings;
using NocIfc.Domain.OperationalEmail;
using NocIfc.Domain.Settings;

namespace NocIfc.Application.Features.OperationalEmail;

public sealed record OperationalEmailAttachmentInput(string? FileName, string? ContentType, string? ContentBase64);

public sealed record OperationalEmailSendInput(
    string? TemplateKey,
    string? To,
    string? Cc,
    string? Bcc,
    string? Subject,
    string? Body,
    IReadOnlyDictionary<string, string>? Fields,
    IReadOnlyList<OperationalEmailAttachmentInput> Attachments,
    int? MaintenanceNoticeId,
    int? SourceEmailId,
    int? SignatureId,
    bool? UseDefaultSignature,
    IReadOnlySet<string> ProvidedFields);

public sealed record OperationalEmailScheduleResult(
    OperationalEmailScheduledEntry Primary,
    bool Grouped,
    string? GroupId,
    string? Message,
    int? CompanyCount,
    IReadOnlyList<int>? EmailIds,
    DateTime? NextRunAt,
    IReadOnlyList<OperationalEmailScheduledEntry>? Emails);

public sealed record OperationalEmailSendDelivery(
    int EmailId,
    int DeliveryId,
    string Status,
    string Message,
    DateTime? SentAtUtc,
    string? Company,
    bool BccCopyOnly);

public sealed record OperationalEmailSendResult(
    string Status,
    string Message,
    int EmailId,
    int? DeliveryId,
    DateTime? SentAtUtc,
    bool Grouped,
    string? GroupId,
    int? CompanyCount,
    IReadOnlyList<int>? EmailIds,
    IReadOnlyList<int?>? DeliveryIds,
    IReadOnlyList<OperationalEmailSendDelivery>? Deliveries,
    IReadOnlyList<OperationalEmailSendDelivery>? BccCopyDeliveries);

public sealed class OperationalEmailSendCommands(
    IOperationalEmailStore emailStore,
    ISettingsReferenceDirectoryStore directories,
    IAiSmtpSettingsStore smtpSettings,
    IOperationalDashboardStore dashboard,
    IOperationalEmailSender emailSender)
{
    private const string EmailTimezone = "America/Chicago";
    private const int MaxAttachments = 5;
    private const int MaxAttachmentBytes = 5 * 1024 * 1024;
    private const int MaxTotalAttachmentBytes = 20 * 1024 * 1024;
    private static readonly TimeZoneInfo CentralTimeZone = TimeZoneInfo.FindSystemTimeZoneById(EmailTimezone);
    private static readonly Regex TokenPattern = new(@"\{\{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\}\}",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex ContentTypePattern = new("^[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+$",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly string[] CircuitDetailFields =
    ["network_orders", "circuit", "circuit_ids", "network_order_ids", "excluded_network_order_ids", "a_location", "z_location", "fiber_details"];
    private static readonly HashSet<string> FiberFollowupKeys =
        ["fiber_outage_update", "fiber_outage_resolution"];
    private static readonly IReadOnlyDictionary<string, HashSet<string>> LinkedEditableFields =
        new Dictionary<string, HashSet<string>>(StringComparer.Ordinal)
        {
            [OperationalEmailTemplateCatalog.MaintenanceStartKey] = new([], StringComparer.Ordinal),
            ["maintenance_complete"] = new(["completion_time", "work_performed", "service_status", "follow_up"], StringComparer.Ordinal),
            ["fiber_outage_update"] = new(["update_time", "update_details", "restoration_estimate", "next_update"], StringComparer.Ordinal),
            ["fiber_outage_resolution"] = new(["resolution_time", "resolution_details", "follow_up"], StringComparer.Ordinal),
        };

    public async Task<OperationalEmailSendResult> SendAsync(
        OperationalEmailSendInput input,
        int actorUserId,
        CancellationToken cancellationToken)
    {
        var composition = await ComposeAsync(input, forSchedule: false, cancellationToken);
        var context = composition.Context;
        var prepared = composition.Messages;
        var templateKey = context.Definition.Key;

        var persisted = new List<PersistedMessage>(prepared.Count);
        foreach (var message in prepared)
        {
            var emailId = await emailStore.CreateEmailAsync(message.ToSnapshot(actorUserId, null), cancellationToken);
            persisted.Add(new PersistedMessage(emailId, message));
        }

        var outcomes = new List<OperationalEmailSendDelivery>(persisted.Count);
        foreach (var record in persisted)
        {
            var attemptedAt = DateTime.UtcNow;
            var deliveryId = await emailStore.CreateDeliverySnapshotAsync(
                record.EmailId, context.Provider, context.SenderAddress, attemptedAt, cancellationToken);
            EmailSendResult delivery;
            if (!IsConfiguredSender(context.SenderAddress))
            {
                delivery = new EmailSendResult(false,
                    "Configure one valid global SMTP sender address in Settings > AI & SMTP.");
            }
            else
            {
                try
                {
                    delivery = await emailSender.SendOperationalEmailAsync(
                        new OperationalEmailEnvelope(
                            record.Message.ToRecipients,
                            record.Message.CcRecipients,
                            record.Message.BccRecipients,
                            record.Message.Subject,
                            record.Message.Body,
                            RenderHtmlAlternative(record.Message.Body, record.Message.Fields),
                            record.Message.Attachments.Select(attachment => new EmailAttachment(
                                attachment.FileName, attachment.ContentType, attachment.Content)).ToArray()),
                        cancellationToken);
                }
                catch (Exception)
                {
                    delivery = new EmailSendResult(false, "SMTP delivery failed.");
                }
            }

            var completedAt = DateTime.UtcNow;
            await emailStore.CompleteImmediateDeliveryAsync(
                record.EmailId, deliveryId, delivery.Success, delivery.Message, completedAt, CancellationToken.None);
            outcomes.Add(new OperationalEmailSendDelivery(
                record.EmailId,
                deliveryId,
                delivery.Success ? "sent" : "failed",
                delivery.Message,
                delivery.Success ? completedAt : null,
                record.Message.Company,
                record.Message.BccCopyOnly));
        }

        return AggregateResults(templateKey, prepared, outcomes);
    }

    public async Task<OperationalEmailScheduleResult> ScheduleAsync(
        OperationalEmailSendInput input,
        OperationalEmailScheduleInput scheduleInput,
        int actorUserId,
        CancellationToken cancellationToken)
    {
        var schedule = OperationalEmailScheduleRules.Validate(scheduleInput, DateTimeOffset.UtcNow);
        var composition = await ComposeAsync(input, forSchedule: true, cancellationToken);
        var persistedIds = new List<int>(composition.Messages.Count);
        foreach (var message in composition.Messages)
        {
            persistedIds.Add(await emailStore.CreateEmailAsync(
                message.ToSnapshot(actorUserId, schedule), cancellationToken));
        }
        var scheduled = await emailStore.GetScheduledEmailsByIdsAsync(persistedIds, cancellationToken);
        var byId = scheduled.ToDictionary(email => email.Id);
        var ordered = persistedIds.Select(id => byId.TryGetValue(id, out var item)
            ? item
            : throw new InvalidOperationException("Scheduled email snapshot could not be loaded.")).ToArray();
        var primaryMessages = composition.Messages.Select((message, index) => (message, index))
            .Where(item => !item.message.BccCopyOnly).ToArray();
        var primary = primaryMessages.Select(item => byId[persistedIds[item.index]]).ToArray();
        var copies = composition.Messages.Count(message => message.BccCopyOnly);
        var hasCompanyGroups = primaryMessages.Any(item => item.message.GroupCompany is not null);
        if (composition.Messages.Count == 1 && composition.Messages[0].GroupId is null)
        {
            return new OperationalEmailScheduleResult(primary[0], false, null, null, null, null,
                primary[0].NextRunAt, null);
        }
        if (!hasCompanyGroups)
        {
            var message = copies == 0
                ? null
                : $"Scheduled email with {copies} circuit-filtered BCC cop{(copies == 1 ? "y" : "ies")}.";
            return new OperationalEmailScheduleResult(
                primary[0], false, null, message, null,
                composition.Messages.Count > 1 || composition.Messages[0].GroupId is not null
                    ? ordered.Select(email => email.Id).ToArray()
                    : null,
                primary[0].NextRunAt,
                null);
        }

        var templateKey = composition.Context.Definition.Key;
        var label = templateKey == OperationalEmailTemplateCatalog.FiberMaintenanceKey
            ? "Fiber Maintenance"
            : composition.Context.Definition.Label;
        var groupMessage = $"Scheduled {label} notices for {primary.Length} compan{(primary.Length == 1 ? "y" : "ies")}.";
        if (copies > 0) groupMessage += $" Circuit-filtered BCC copies: {copies}.";
        return new OperationalEmailScheduleResult(
            primary[0],
            true,
            composition.Messages[0].GroupId,
            groupMessage,
            primary.Length,
            ordered.Select(email => email.Id).ToArray(),
            primary[0].NextRunAt,
            ordered);
    }

    private async Task<PreparedComposition> ComposeAsync(
        OperationalEmailSendInput input,
        bool forSchedule,
        CancellationToken cancellationToken)
    {
        ValidateRequestBounds(input);
        var templateKey = input.TemplateKey?.Trim() ?? "";
        var definition = OperationalEmailTemplateCatalog.Find(templateKey)
            ?? throw new ArgumentException("Unknown operational email template.");
        var defaults = OperationalEmailTemplateCatalog.All.Select(template => new OperationalEmailTemplateDefault(
            template.Key, template.Label, template.Description, template.DefaultSubject, template.DefaultBody,
            "", "", "", null)).ToArray();
        await emailStore.EnsureTemplateDefaultsAsync(defaults, cancellationToken);
        var savedTemplates = (await emailStore.GetTemplateDefaultsAsync(cancellationToken))
            .ToDictionary(template => template.TemplateKey, StringComparer.Ordinal);
        if (!savedTemplates.TryGetValue(templateKey, out var template))
        {
            throw new ArgumentException("Operational email template is not initialized.");
        }

        var settings = await smtpSettings.GetAsync(cancellationToken);
        var provider = string.IsNullOrWhiteSpace(settings?.ActiveSmtpProvider) ? "smtp" : settings.ActiveSmtpProvider;
        var senderAddress = provider switch
        {
            "gmail" => OperationalEmailRules.ParseAddress(
                string.IsNullOrWhiteSpace(settings?.GmailSmtpSender)
                    ? settings?.GmailSmtpUsername
                    : settings.GmailSmtpSender),
            "smtp" => OperationalEmailRules.ParseAddress(settings?.SmtpSender),
            _ => "",
        };
        var needsFiberDirectories = definition.NetworkOrderAutofill
            || OperationalEmailTemplateCatalog.FiberCircuitBccKeys.Contains(templateKey);
        var context = new SendContext(
            definition,
            template,
            provider,
            senderAddress,
            OperationalEmailRules.GlobalSenderRecipient(settings),
            TimezoneAbbreviation(),
            needsFiberDirectories ? await directories.GetFiberAsync(cancellationToken) : Array.Empty<FiberEmailContactEntry>(),
            definition.OnpageTo ? await directories.GetOnpageAsync(cancellationToken) : Array.Empty<OnpageEmailContactEntry>(),
            needsFiberDirectories ? await directories.GetNetworkOrdersAsync(cancellationToken) : Array.Empty<NetworkOrderCircuitEntry>(),
            await emailStore.GetSignaturesAsync(false, cancellationToken),
            definition.LiveSource == "global_shift_analysis"
                ? (await dashboard.GetBriefsAsync(cancellationToken))?.RollingSummary ?? ""
                : "");

        var signature = SelectSignature(input, context.Signatures);
        var attachments = NormalizeAttachments(definition, input.Attachments);
        var sourceMessages = await ResolveSourceMessagesAsync(input, context, cancellationToken);
        var prepared = PrepareMessages(input, context, sourceMessages, signature, attachments, forSchedule);
        prepared = CollapseCircuitlessBccCopies(prepared, context);
        if (prepared.Count == 0) throw new ArgumentException("No email recipients were prepared for delivery.");
        return new PreparedComposition(context, prepared);
    }

    private async Task<IReadOnlyList<OperationalEmailSourceMessage>> ResolveSourceMessagesAsync(
        OperationalEmailSendInput input,
        SendContext context,
        CancellationToken cancellationToken)
    {
        var templateKey = context.Definition.Key;
        if (input.MaintenanceNoticeId is not null && templateKey != "maintenance_complete")
        {
            throw new ArgumentException("A maintenance notice can only be linked to a Maintenance Complete email.");
        }
        if (templateKey == "maintenance_complete"
            && input.SourceEmailId is not null
            && input.MaintenanceNoticeId is not null
            && input.SourceEmailId != input.MaintenanceNoticeId)
        {
            throw new ArgumentException("Choose one source maintenance notification.");
        }
        var sourceId = templateKey == "maintenance_complete"
            ? input.SourceEmailId ?? input.MaintenanceNoticeId
            : input.SourceEmailId;
        if (context.Definition.SourceTemplateKeys.Count == 0)
        {
            if (sourceId is not null)
            {
                throw new ArgumentException("This email template does not support a linked source email.");
            }
            return [];
        }
        if (sourceId is null or <= 0)
        {
            throw new ArgumentException("Select a previously sent source email.");
        }
        var messages = await emailStore.GetSuccessfulSourceMessagesAsync(
            sourceId.Value,
            context.Definition.SourceTemplateKeys,
            OperationalEmailTemplateCatalog.FiberCircuitBccKeys.Contains(templateKey),
            cancellationToken);
        if (!messages.Any(message => message.Id == sourceId.Value && !message.BccCopyOnly))
        {
            throw new ArgumentException("The selected source email has not been sent successfully.");
        }
        return messages;
    }

    private List<PreparedEmail> PrepareMessages(
        OperationalEmailSendInput input,
        SendContext context,
        IReadOnlyList<OperationalEmailSourceMessage> sourceMessages,
        OperationalEmailSignatureEntry? signature,
        IReadOnlyList<OperationalEmailAttachmentSnapshot> attachments,
        bool forSchedule)
    {
        var templateKey = context.Definition.Key;
        if (templateKey == OperationalEmailTemplateCatalog.FiberMaintenanceKey)
        {
            return PrepareFiberMaintenance(input, context, signature, attachments, forSchedule);
        }
        if (templateKey == "fiber_outage")
        {
            var preview = PrepareFields(input.Fields, context.Definition, null, context, deferRequired: true);
            var records = SelectNetworkOrderRecords(preview, context.NetworkOrders);
            if (records.Count > 0)
            {
                return PrepareFiberOutageGroups(input, context, preview, records, signature, attachments, forSchedule);
            }
        }
        if (sourceMessages.Count > 0)
        {
            var parentId = templateKey == "maintenance_complete"
                ? input.SourceEmailId ?? input.MaintenanceNoticeId
                : input.SourceEmailId;
            var parent = sourceMessages.Single(message => message.Id == parentId && !message.BccCopyOnly);
            if (parent.GroupId is not null && LinkedEditableFields.ContainsKey(templateKey))
            {
                return PrepareLinkedGroup(input, context, sourceMessages, signature, attachments, forSchedule);
            }
            var prepared = PrepareOne(input, context, parent, signature, attachments, false, forSchedule);
            return ScopeSelectedCircuitBcc(prepared, context);
        }

        var message = PrepareOne(input, context, null, signature, attachments, false, forSchedule);
        return ScopeSelectedCircuitBcc(message, context);
    }

    private List<PreparedEmail> PrepareFiberMaintenance(
        OperationalEmailSendInput input,
        SendContext context,
        OperationalEmailSignatureEntry? signature,
        IReadOnlyList<OperationalEmailAttachmentSnapshot> attachments,
        bool forSchedule)
    {
        var fields = PrepareFields(input.Fields, context.Definition, null, context, deferRequired: true);
        var records = SelectNetworkOrderRecords(fields, context.NetworkOrders);
        if (records.Count == 0)
        {
            throw new ArgumentException("Select at least one configured Network Order/Circuit for Fiber Maintenance.");
        }
        AutofillNetworkOrderFields(context.Definition, fields, records);
        fields = PrepareFields(fields, context.Definition, null, context);
        EnsureDefaultRendered(input, context, fields);
        EnsureGlobalSender(context, "Cc");
        var groups = GroupByCompany(records);
        var contacts = ContactsByCompany(context.FiberContacts);
        var missing = groups.Keys.Where(company => !contacts.ContainsKey(company)).Select(company => groups[company].Name).ToArray();
        if (missing.Length > 0)
        {
            throw new ArgumentException($"No Fiber email contacts are configured for: {string.Join(", ", missing)}.");
        }

        var groupId = Guid.NewGuid().ToString("N");
        var prepared = new List<PreparedEmail>();
        foreach (var (companyKey, group) in groups)
        {
            var companyFields = new Dictionary<string, string>(fields, StringComparer.Ordinal)
            {
                ["network_order_ids"] = "",
                ["excluded_network_order_ids"] = "",
                ["network_orders"] = FormatNetworkOrderDetails(group.Records),
                ["a_location"] = JoinUnique(group.Records.Select(record => record.ALocation), "; "),
                ["z_location"] = JoinUnique(group.Records.Select(record => record.ZLocation), "; "),
            };
            var companyContacts = contacts[companyKey];
            var companyInput = input with
            {
                To = JoinUnique(companyContacts.Select(contact => contact.Email)),
                Subject = context.Template.DefaultSubject,
                Body = context.Template.DefaultBody,
                Fields = companyFields,
                ProvidedFields = WithFields(input.ProvidedFields, "to", "subject", "body"),
            };
            var message = PrepareOne(companyInput, context, null, signature, attachments, false, forSchedule);
            message.GroupId = groupId;
            message.GroupCompany = group.Name;
            message.Company = group.Name;
            prepared.Add(message);
        }
        return prepared;
    }

    private List<PreparedEmail> PrepareFiberOutageGroups(
        OperationalEmailSendInput input,
        SendContext context,
        Dictionary<string, string> fields,
        IReadOnlyList<NetworkOrderCircuitEntry> records,
        OperationalEmailSignatureEntry? signature,
        IReadOnlyList<OperationalEmailAttachmentSnapshot> attachments,
        bool forSchedule)
    {
        AutofillNetworkOrderFields(context.Definition, fields, records);
        fields = PrepareFields(fields, context.Definition, null, context);
        EnsureDefaultRendered(input, context, fields);
        EnsureGlobalSender(context, "Cc");
        var groups = GroupByCompany(records);
        var contacts = ContactsByCompany(context.FiberContacts);
        var missing = groups.Keys.Where(company => !contacts.ContainsKey(company)).Select(company => groups[company].Name).ToArray();
        if (missing.Length > 0)
        {
            throw new ArgumentException($"No Fiber email contacts are configured for: {string.Join(", ", missing)}.");
        }
        var groupId = Guid.NewGuid().ToString("N");
        var prepared = new List<PreparedEmail>();
        foreach (var (companyKey, group) in groups)
        {
            var companyFields = new Dictionary<string, string>(fields, StringComparer.Ordinal)
            {
                ["network_order_ids"] = "",
                ["excluded_network_order_ids"] = "",
                ["network_orders"] = JoinUnique(group.Records.Select(record => record.CircuitNetworkOrderId), "\n"),
            };
            var companyInput = input with
            {
                To = JoinUnique(contacts[companyKey].Select(contact => contact.Email)),
                Subject = context.Template.DefaultSubject,
                Body = context.Template.DefaultBody,
                Fields = companyFields,
                ProvidedFields = WithFields(input.ProvidedFields, "to", "subject", "body"),
            };
            var message = PrepareOne(companyInput, context, null, signature, attachments,
                companyRouted: true, forSchedule: forSchedule);
            message.GroupId = groupId;
            message.GroupCompany = group.Name;
            message.Company = group.Name;
            prepared.AddRange(ScopeCompanyBcc(message, context, group.Name));
        }
        return prepared;
    }

    private List<PreparedEmail> PrepareLinkedGroup(
        OperationalEmailSendInput input,
        SendContext context,
        IReadOnlyList<OperationalEmailSourceMessage> sourceMessages,
        OperationalEmailSignatureEntry? signature,
        IReadOnlyList<OperationalEmailAttachmentSnapshot> attachments,
        bool forSchedule)
    {
        var templateKey = context.Definition.Key;
        var members = sourceMessages.Where(message => !message.BccCopyOnly).ToArray();
        var inheritedBccCopies = OperationalEmailRules.NormalizeRecipients(OperationalEmailRules.JoinUnique(
            sourceMessages.Where(message => message.BccCopyOnly).SelectMany(message => message.BccRecipients)));
        var rawFields = input.Fields ?? new Dictionary<string, string>();
        var editableFields = LinkedEditableFields[templateKey];
        var batchId = Guid.NewGuid().ToString("N");
        var prepared = new List<PreparedEmail>();
        foreach (var member in members)
        {
            var memberFields = rawFields
                .Where(pair => editableFields.Contains(pair.Key))
                .ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal);
            var memberInput = input with
            {
                SourceEmailId = member.Id,
                MaintenanceNoticeId = null,
                Subject = "",
                Body = "",
                Fields = memberFields,
                ProvidedFields = WithFields(input.ProvidedFields, "source_email_id", "subject", "body"),
            };
            if (OperationalEmailTemplateCatalog.FiberCircuitBccKeys.Contains(templateKey)
                && inheritedBccCopies.Length > 0)
            {
                memberInput = memberInput with
                {
                    Bcc = OperationalEmailRules.JoinUnique([
                        .. OperationalEmailRules.NormalizeRecipients(memberInput.Bcc),
                        .. inheritedBccCopies,
                    ]),
                    ProvidedFields = WithFields(memberInput.ProvidedFields, "bcc"),
                };
            }

            var message = PrepareOne(memberInput, context, member, signature, attachments, false, forSchedule);
            message.GroupId = batchId;
            message.GroupCompany = member.GroupCompany;
            var label = member.GroupCompany
                ?? OperationalEmailRules.JoinUnique(member.ToRecipients)
                ?? $"Source email {member.Id}";
            message.Company = label;
            if (OperationalEmailTemplateCatalog.FiberCircuitBccKeys.Contains(templateKey))
            {
                prepared.AddRange(member.GroupCompany is not null
                    ? ScopeCompanyBcc(message, context, member.GroupCompany)
                    : ScopeSelectedCircuitBcc(message, context));
            }
            else
            {
                prepared.Add(message);
            }
        }
        return prepared;
    }

    private PreparedEmail PrepareOne(
        OperationalEmailSendInput input,
        SendContext context,
        OperationalEmailSourceMessage? parent,
        OperationalEmailSignatureEntry? signature,
        IReadOnlyList<OperationalEmailAttachmentSnapshot> attachments,
        bool companyRouted,
        bool forSchedule)
    {
        var definition = context.Definition;
        var template = context.Template;
        var parentFields = GetParentFields(definition.Key, parent);
        var rawFields = input.Fields ?? new Dictionary<string, string>();
        if (definition.Key == "maintenance_complete" && parent?.TemplateKey == OperationalEmailTemplateCatalog.FiberMaintenanceKey)
        {
            rawFields = rawFields.Where(pair => pair.Key != "fiber_details").ToDictionary(
                pair => pair.Key,
                pair => pair.Value,
                StringComparer.Ordinal);
            if (string.IsNullOrWhiteSpace(rawFields.GetValueOrDefault("site")))
            {
                rawFields = rawFields.Where(pair => pair.Key != "site").ToDictionary(
                    pair => pair.Key,
                    pair => pair.Value,
                    StringComparer.Ordinal);
            }
        }

        var fields = PrepareFields(rawFields, definition, parentFields, context,
            deferRequired: definition.NetworkOrderAutofill);
        var networkRecords = SelectNetworkOrderRecords(fields, context.NetworkOrders);
        AutofillNetworkOrderFields(definition, fields, networkRecords);
        fields = PrepareFields(fields, definition, parentFields, context);

        var subjectInput = string.IsNullOrEmpty(input.Subject) ? template.DefaultSubject : input.Subject;
        var bodyInput = string.IsNullOrEmpty(input.Body) ? template.DefaultBody : input.Body;
        var supported = definition.Fields.Select(field => field.Key).ToHashSet(StringComparer.Ordinal);
        ValidateTokens(subjectInput!, supported, "subject");
        if (definition.LiveSource == "global_shift_analysis" && TokenPattern.IsMatch(subjectInput!))
        {
            subjectInput = "Morning Operations Report";
        }
        var subject = NormalizeSubject(Render(subjectInput!, fields));

        string body;
        if (definition.LiveSource == "global_shift_analysis")
        {
            fields["shift_analysis"] = context.LatestShiftAnalysis;
            if (string.IsNullOrWhiteSpace(context.LatestShiftAnalysis) && !forSchedule)
            {
                throw new ArgumentException("No shift analysis is available in Global Dashboards yet.");
            }
            body = context.LatestShiftAnalysis;
            bodyInput = "{{shift_analysis}}";
        }
        else
        {
            ValidateTokens(bodyInput!, supported, "body");
            body = Render(bodyInput!, fields);
        }
        if (signature is not null && body.Length > 0)
        {
            body = AppendSignature(body, signature.Content);
        }
        body = NormalizeLines(body);
        if (body.Length > 200_000 || (!forSchedule && string.IsNullOrWhiteSpace(body)))
        {
            throw new ArgumentException("Email body must contain no more than 200,000 characters and cannot be blank.");
        }

        var (to, cc, bcc) = ResolveRecipients(input, context, parent, companyRouted);
        if (definition.OnpageTo)
        {
            var allowedOnpage = context.OnpageContacts.Select(contact => contact.Email)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            if (to.Length == 0 || to.Any(recipient => !allowedOnpage.Contains(recipient)))
            {
                throw new ArgumentException("Fiber Outage ONPAGE To recipients must be selected from the ONPAGE directory.");
            }
        }
        if (definition.NetworkOrderBcc)
        {
            var companies = networkRecords.Select(record => record.Company);
            var automatic = context.FiberContacts
                .Where(contact => companies.Contains(contact.Company, StringComparer.OrdinalIgnoreCase))
                .Select(contact => contact.Email);
            bcc = UniqueRecipients([.. bcc, .. NormalizeRecipients(JoinUnique(automatic))]);
        }
        if (to.Length == 0)
        {
            throw new ArgumentException("At least one To recipient is required.");
        }
        if (bcc.Length > 0 && !definition.AllowsBcc)
        {
            throw new ArgumentException("BCC recipients are not supported by this email template.");
        }
        if (cc.Length > 0 && !definition.AllowsCc && definition.RecipientsMode != "to_only")
        {
            throw new ArgumentException("Cc recipients are not supported by this email template.");
        }
        if (to.Concat(cc).Intersect(bcc, StringComparer.OrdinalIgnoreCase).Any())
        {
            throw new ArgumentException("A recipient cannot appear in both a visible field and BCC.");
        }

        return new PreparedEmail
        {
            TemplateKey = definition.Key,
            SignatureId = signature?.Id,
            SignatureName = signature?.Name,
            SignatureContent = signature?.Content,
            ParentEmailId = parent?.Id,
            Subject = subject,
            Body = body,
            SubjectTemplate = subjectInput!,
            BodyTemplate = bodyInput!,
            Fields = fields,
            ToRecipients = to,
            CcRecipients = cc,
            BccRecipients = bcc,
            Attachments = attachments,
        };
    }

    private (string[] To, string[] Cc, string[] Bcc) ResolveRecipients(
        OperationalEmailSendInput input,
        SendContext context,
        OperationalEmailSourceMessage? parent,
        bool companyRouted)
    {
        var definition = context.Definition;
        var template = context.Template;
        var toInput = input.To;
        var ccInput = input.Cc;
        var bccInput = input.Bcc;
        string to;
        string cc;
        string bcc;
        if (definition.RecipientsMode == "to_only")
        {
            if (NormalizeRecipients(ccInput).Length > 0 || NormalizeRecipients(bccInput).Length > 0)
            {
                throw new ArgumentException("After-Hours ONPAGE supports To recipients only.");
            }
            to = FirstNonempty(toInput, template.DefaultTo);
            cc = "";
            bcc = "";
        }
        else if (definition.Key == "fiber_outage" && companyRouted)
        {
            var extraCc = input.ProvidedFields.Contains("cc") ? ccInput : template.DefaultCc;
            to = toInput ?? template.DefaultTo;
            cc = OperationalEmailRules.JoinUnique([context.GlobalSender, .. NormalizeRecipients(extraCc)]);
            bcc = FirstNonempty(bccInput, template.DefaultBcc);
        }
        else if (definition.Key == OperationalEmailTemplateCatalog.FiberMaintenanceKey)
        {
            var extraCc = input.ProvidedFields.Contains("cc") ? ccInput : template.DefaultCc;
            to = toInput ?? template.DefaultTo;
            cc = OperationalEmailRules.JoinUnique([context.GlobalSender, .. NormalizeRecipients(extraCc)]);
            bcc = bccInput ?? template.DefaultBcc;
        }
        else if (definition.Key == OperationalEmailTemplateCatalog.FiberOnpageKey)
        {
            to = FirstNonempty(toInput, template.DefaultTo);
            cc = context.GlobalSender;
            bcc = FirstNonempty(bccInput, template.DefaultBcc);
        }
        else if (FiberFollowupKeys.Contains(definition.Key))
        {
            if (parent?.GroupId is not null)
            {
                to = string.Join(", ", parent.ToRecipients);
                cc = OperationalEmailRules.JoinUnique([
                    .. parent.CcRecipients,
                    .. NormalizeRecipients(FirstNonempty(ccInput, template.DefaultCc)),
                ]);
            }
            else
            {
                to = context.GlobalSender;
                cc = FirstNonempty(ccInput, template.DefaultCc);
            }
            bcc = OperationalEmailRules.JoinUnique([
                .. (parent?.BccRecipients ?? []),
                .. NormalizeRecipients(FirstNonempty(bccInput, template.DefaultBcc)),
            ]);
        }
        else if (OperationalEmailTemplateCatalog.FiberSenderToKeys.Contains(definition.Key))
        {
            to = context.GlobalSender;
            if (parent is not null)
            {
                cc = FirstNonempty(ccInput, string.Join(", ", parent.CcRecipients));
                bcc = FirstNonempty(bccInput, string.Join(", ", parent.BccRecipients));
            }
            else
            {
                cc = FirstNonempty(ccInput, template.DefaultCc);
                bcc = FirstNonempty(bccInput, template.DefaultBcc);
            }
        }
        else if (parent is not null
            && (definition.Key is "maintenance_complete" or OperationalEmailTemplateCatalog.MaintenanceStartKey))
        {
            if (parent.GroupId is not null)
            {
                to = string.Join(", ", parent.ToRecipients);
                var extraCc = input.ProvidedFields.Contains("cc") ? ccInput : template.DefaultCc;
                cc = OperationalEmailRules.JoinUnique([.. parent.CcRecipients, .. NormalizeRecipients(extraCc)]);
            }
            else
            {
                to = FirstNonempty(toInput, string.Join(", ", parent.ToRecipients));
                cc = ccInput ?? OperationalEmailRules.JoinUnique([
                    .. parent.CcRecipients,
                    .. NormalizeRecipients(template.DefaultCc),
                ]);
            }
            var requestedBcc = NormalizeRecipients(FirstNonempty(bccInput, template.DefaultBcc));
            bcc = OperationalEmailRules.JoinUnique([.. parent.BccRecipients, .. requestedBcc]);
            to = FirstNonempty(to, template.DefaultTo);
            if (!input.ProvidedFields.Contains("cc")) cc = FirstNonempty(cc, template.DefaultCc);
        }
        else if (parent is not null)
        {
            to = FirstNonempty(toInput, string.Join(", ", parent.ToRecipients));
            cc = FirstNonempty(ccInput, string.Join(", ", parent.CcRecipients));
            bcc = OperationalEmailRules.JoinUnique([
                .. parent.BccRecipients,
                .. NormalizeRecipients(FirstNonempty(bccInput, template.DefaultBcc)),
            ]);
            to = FirstNonempty(to, template.DefaultTo);
            cc = FirstNonempty(cc, template.DefaultCc);
        }
        else
        {
            to = FirstNonempty(toInput, template.DefaultTo);
            cc = FirstNonempty(ccInput, template.DefaultCc);
            bcc = FirstNonempty(bccInput, template.DefaultBcc);
        }

        var toRecipients = NormalizeRecipients(to);
        var ccRecipients = NormalizeRecipients(cc);
        var bccRecipients = NormalizeRecipients(bcc);
        return (toRecipients, ccRecipients, bccRecipients);
    }

    private List<PreparedEmail> ScopeSelectedCircuitBcc(PreparedEmail prepared, SendContext context)
    {
        if (!OperationalEmailTemplateCatalog.FiberCircuitBccKeys.Contains(prepared.TemplateKey)
            || !HasCircuitDetails(prepared.Fields)
            || prepared.BccRecipients.Length == 0)
        {
            return [prepared];
        }
        var records = NetworkOrderRecordsForMessage(prepared.Fields, context.NetworkOrders);
        var contactCompanies = FiberContactCompanyMap(context.FiberContacts);
        var byRecordSet = new Dictionary<string, (IReadOnlyList<NetworkOrderCircuitEntry> Records, List<string> Recipients)>(StringComparer.Ordinal);
        foreach (var recipient in prepared.BccRecipients)
        {
            var companies = contactCompanies.GetValueOrDefault(recipient, new HashSet<string>(StringComparer.OrdinalIgnoreCase));
            var matches = records.Where(record => companies.Contains(record.Company)).ToArray();
            var key = string.Join(",", matches.Select(record => record.Id));
            if (!byRecordSet.TryGetValue(key, out var group))
            {
                group = (matches, []);
                byRecordSet[key] = group;
            }
            group.Recipients.Add(recipient);
        }
        var groupId = prepared.GroupId ?? Guid.NewGuid().ToString("N");
        prepared.GroupId = groupId;
        prepared.BccRecipients = [];
        var result = new List<PreparedEmail> { prepared };
        foreach (var group in byRecordSet.Values)
        {
            var fields = group.Records.Count == 0
                ? CircuitlessFields(prepared.Fields)
                : FieldsForNetworkOrders(prepared.Fields, group.Records);
            result.Add(BccOnlyCopy(prepared, fields, group.Recipients, context));
        }
        return result;
    }

    private List<PreparedEmail> ScopeCompanyBcc(
        PreparedEmail prepared,
        SendContext context,
        string? company)
    {
        if (!OperationalEmailTemplateCatalog.FiberCircuitBccKeys.Contains(prepared.TemplateKey)
            || !HasCircuitDetails(prepared.Fields)
            || prepared.BccRecipients.Length == 0
            || string.IsNullOrWhiteSpace(company))
        {
            return [prepared];
        }
        var contactCompanies = FiberContactCompanyMap(context.FiberContacts);
        var companyKey = company.Trim();
        var matching = prepared.BccRecipients.Where(recipient =>
            contactCompanies.GetValueOrDefault(recipient, new HashSet<string>(StringComparer.OrdinalIgnoreCase))
                .Contains(companyKey)).ToArray();
        var circuitFree = prepared.BccRecipients.Except(matching, StringComparer.OrdinalIgnoreCase).ToArray();
        prepared.BccRecipients = matching;
        if (circuitFree.Length == 0) return [prepared];
        return [prepared, BccOnlyCopy(prepared, CircuitlessFields(prepared.Fields), circuitFree, context)];
    }

    private PreparedEmail BccOnlyCopy(
        PreparedEmail source,
        Dictionary<string, string> fields,
        IReadOnlyList<string> recipients,
        SendContext context)
    {
        EnsureGlobalSender(context, "circuit-filtered BCC copies");
        var allowed = NetworkOrderIdentifiers(fields).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var excluded = NetworkOrderIdentifiers(source.Fields).Where(identifier => !allowed.Contains(identifier)).ToArray();
        var subject = NormalizeSubject(RemoveCircuitIdentifiers(Render(source.SubjectTemplate, fields), excluded));
        var body = Render(source.BodyTemplate, fields);
        body = AppendSignature(RemoveCircuitIdentifiers(body, excluded), source.SignatureContent);
        return new PreparedEmail
        {
            TemplateKey = source.TemplateKey,
            SignatureId = source.SignatureId,
            SignatureName = source.SignatureName,
            SignatureContent = source.SignatureContent,
            ParentEmailId = source.ParentEmailId,
            GroupId = source.GroupId,
            GroupCompany = source.GroupCompany,
            BccCopyOnly = true,
            Subject = subject,
            Body = NormalizeLines(body),
            SubjectTemplate = source.SubjectTemplate,
            BodyTemplate = source.BodyTemplate,
            Fields = fields,
            ToRecipients = [context.GlobalSender],
            CcRecipients = [],
            BccRecipients = UniqueRecipients(recipients),
            Attachments = source.Attachments,
            Company = source.Company,
        };
    }

    private List<PreparedEmail> CollapseCircuitlessBccCopies(
        List<PreparedEmail> prepared,
        SendContext context)
    {
        var selectedCompanies = prepared
            .Where(message => !message.BccCopyOnly && !string.IsNullOrWhiteSpace(message.GroupCompany))
            .Select(message => message.GroupCompany!.Trim())
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (selectedCompanies.Count == 0) return prepared;
        var contacts = FiberContactCompanyMap(context.FiberContacts);
        var result = new List<PreparedEmail>();
        var copiesByBatch = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var message in prepared)
        {
            if (!message.BccCopyOnly || NetworkOrderIdentifiers(message.Fields).Count > 0)
            {
                result.Add(message);
                continue;
            }
            var recipients = message.BccRecipients.Where(recipient =>
                !contacts.GetValueOrDefault(recipient, new HashSet<string>(StringComparer.OrdinalIgnoreCase))
                    .Overlaps(selectedCompanies)).ToArray();
            if (recipients.Length == 0) continue;
            var batchId = message.GroupId ?? Guid.NewGuid().ToString("N");
            if (copiesByBatch.TryGetValue(batchId, out var index))
            {
                result[index].BccRecipients = UniqueRecipients([.. result[index].BccRecipients, .. recipients]);
                continue;
            }
            message.BccRecipients = UniqueRecipients(recipients);
            message.GroupCompany = null;
            message.Company = null;
            copiesByBatch[batchId] = result.Count;
            result.Add(message);
        }
        return result;
    }

    private Dictionary<string, string> PrepareFields(
        IReadOnlyDictionary<string, string>? input,
        OperationalEmailTemplateDefinition definition,
        IReadOnlyDictionary<string, string>? inherited,
        SendContext context,
        bool deferRequired = false)
    {
        input ??= new Dictionary<string, string>();
        if (input.Count > 40) throw new ArgumentException("No more than 40 template fields may be supplied.");
        var fieldSpecs = definition.Fields.ToDictionary(field => field.Key, StringComparer.Ordinal);
        var unknown = input.Keys.Where(key => !fieldSpecs.ContainsKey(key)).Order(StringComparer.Ordinal).ToArray();
        if (unknown.Length > 0)
        {
            throw new ArgumentException($"Unsupported field(s) for this template: {string.Join(", ", unknown)}.");
        }
        var raw = input.ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal);
        if (definition.Key == OperationalEmailTemplateCatalog.FiberMaintenanceKey)
        {
            if (string.IsNullOrEmpty(raw.GetValueOrDefault("expected_impact"))
                && raw.TryGetValue("departmental_impact", out var departmental)) raw["expected_impact"] = departmental;
            if (string.IsNullOrEmpty(raw.GetValueOrDefault("departmental_impact"))
                && raw.TryGetValue("expected_impact", out var expected)) raw["departmental_impact"] = expected;
        }

        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var field in definition.Fields)
        {
            var value = raw.TryGetValue(field.Key, out var supplied)
                ? supplied
                : inherited?.GetValueOrDefault(field.Key);
            if (value is null)
            {
                if (raw.ContainsKey(field.Key))
                {
                    throw new ArgumentException($"{field.Label} must be text.");
                }
                value = "";
            }
            value = NormalizeLines(value);
            value = Regex.Replace(value, @"(\d{4}-\d{2}-\d{2})T(?=\d{2}:\d{2})", "$1 ", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            value = field.Multiline == true
                ? string.IsNullOrWhiteSpace(value) ? "" : value
                : value.Trim();
            if (field.Key == "timezone") value = context.TimezoneAbbreviation;
            if (value.Length > field.MaxLength)
            {
                throw new ArgumentException($"{field.Label} must be no more than {field.MaxLength} characters.");
            }
            if (field.Required && string.IsNullOrWhiteSpace(value) && !deferRequired)
            {
                throw new ArgumentException($"{field.Label} is required.");
            }
            if (value.Length > 0 && (field.InputType == "datetime-local" || field.PickerType == "datetime-local"))
            {
                value = FormatLocalDateTime(value, field.Label);
            }
            if (field.Options is { Count: > 0 } && value.Length > 0 && !field.Options.Contains(value, StringComparer.Ordinal))
            {
                throw new ArgumentException($"Select a valid {field.Label.ToLowerInvariant()}.");
            }
            result[field.Key] = value;
        }

        if (definition.Key is "maintenance_notice" or OperationalEmailTemplateCatalog.MaintenanceStartKey or "maintenance_complete")
        {
            if (result["expected_impact"].Length == 0 && !input.ContainsKey("expected_impact"))
            {
                result["expected_impact"] = string.Join("\n", new[] { result["operational_impact"], result["departmental_impact"] }
                    .Where(value => value.Length > 0));
            }
            if (result["expected_impact"].Length > 0)
            {
                if (result["operational_impact"].Length == 0) result["operational_impact"] = result["expected_impact"];
                if (result["departmental_impact"].Length == 0) result["departmental_impact"] = result["expected_impact"];
            }
        }
        return result;
    }

    private static List<NetworkOrderCircuitEntry> SelectNetworkOrderRecords(
        Dictionary<string, string> fields,
        IReadOnlyList<NetworkOrderCircuitEntry> allRecords)
    {
        var selectedIds = ParseRecordIds(fields.GetValueOrDefault("network_order_ids"), "Selected Network Orders", 50);
        var excludedIds = ParseRecordIds(fields.GetValueOrDefault("excluded_network_order_ids"), "Excluded Network Orders", 250)
            .Where(id => !selectedIds.Contains(id)).ToArray();
        if (selectedIds.Count == 0 && excludedIds.Length == 0) return [];
        var byId = allRecords.ToDictionary(record => record.Id);
        var missing = selectedIds.Concat(excludedIds).Where(id => !byId.ContainsKey(id)).ToArray();
        if (missing.Length > 0)
        {
            throw new ArgumentException("One or more selected or excluded Network Order records no longer exist.");
        }
        var byCircuit = allRecords.GroupBy(record => record.CircuitNetworkOrderId.Trim(), StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.ToArray(), StringComparer.OrdinalIgnoreCase);
        var excluded = excludedIds.ToHashSet();
        var relevantExclusions = new HashSet<int>();
        var selected = selectedIds.Select(id => byId[id]).ToList();
        var selectedRecordIds = selectedIds.ToHashSet();
        foreach (var original in selected.ToArray())
        {
            foreach (var associatedId in original.AssociatedCircuitNetworkOrderIds)
            {
                if (!byCircuit.TryGetValue(associatedId.Trim(), out var matches) || matches.Length == 0)
                {
                    throw new ArgumentException($"Associated circuit '{associatedId}' no longer exists in the reference table.");
                }
                if (matches.Length > 1)
                {
                    throw new ArgumentException($"Associated circuit ID '{associatedId}' is ambiguous in the reference table.");
                }
                var target = matches[0];
                if (excluded.Contains(target.Id))
                {
                    relevantExclusions.Add(target.Id);
                }
                else if (selectedRecordIds.Add(target.Id))
                {
                    selected.Add(target);
                    if (selected.Count > 50)
                    {
                        throw new ArgumentException("No more than 50 network-order records can be selected, including immediate associations.");
                    }
                }
            }
        }
        if (fields.ContainsKey("network_order_ids"))
        {
            fields["network_order_ids"] = string.Join(", ", selected.Select(record => record.Id));
            fields["excluded_network_order_ids"] = string.Join(", ", excludedIds.Where(relevantExclusions.Contains));
        }
        return selected;
    }

    private static List<int> ParseRecordIds(string? value, string label, int maximum)
    {
        var result = new List<int>();
        foreach (var item in (value ?? "").Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (!int.TryParse(item, NumberStyles.None, CultureInfo.InvariantCulture, out var id) || id <= 0)
            {
                throw new ArgumentException($"{label} contain an invalid reference ID.");
            }
            if (!result.Contains(id)) result.Add(id);
        }
        if (result.Count > maximum)
        {
            throw new ArgumentException($"No more than {maximum} {label.ToLowerInvariant()} can be used.");
        }
        return result;
    }

    private static void AutofillNetworkOrderFields(
        OperationalEmailTemplateDefinition definition,
        Dictionary<string, string> fields,
        IReadOnlyList<NetworkOrderCircuitEntry> records)
    {
        if (!definition.NetworkOrderAutofill) return;
        var networkOrders = definition.Key == OperationalEmailTemplateCatalog.FiberMaintenanceKey
            ? FormatNetworkOrderDetails(records)
            : JoinUnique(records.Select(record => record.CircuitNetworkOrderId), "\n");
        if (fields.ContainsKey("network_orders") && string.IsNullOrWhiteSpace(fields["network_orders"]))
        {
            fields["network_orders"] = networkOrders;
        }
        if (fields.ContainsKey("a_location") && string.IsNullOrWhiteSpace(fields["a_location"]))
        {
            fields["a_location"] = JoinUnique(records.Select(record => record.ALocation), "; ");
        }
        if (fields.ContainsKey("z_location") && string.IsNullOrWhiteSpace(fields["z_location"]))
        {
            fields["z_location"] = JoinUnique(records.Select(record => record.ZLocation), "; ");
        }
        if (definition.Key == OperationalEmailTemplateCatalog.FiberMaintenanceKey)
        {
            foreach (var key in new[] { "network_orders", "a_location", "z_location" })
            {
                if (fields.ContainsKey(key) && string.IsNullOrWhiteSpace(fields[key]))
                {
                    throw new ArgumentException($"{FieldLabel(definition, key)} is required.");
                }
            }
        }
    }

    private static IReadOnlyList<NetworkOrderCircuitEntry> NetworkOrderRecordsForMessage(
        IReadOnlyDictionary<string, string> fields,
        IReadOnlyList<NetworkOrderCircuitEntry> allRecords)
    {
        var rowIds = ParseRecordIds(fields.GetValueOrDefault("network_order_ids"), "Selected Network Orders", 250);
        if (rowIds.Count > 0)
        {
            var byId = allRecords.ToDictionary(record => record.Id);
            return rowIds.Where(byId.ContainsKey).Select(id => byId[id]).ToArray();
        }
        var identifiers = NetworkOrderIdentifiers(fields);
        var byCircuit = allRecords.GroupBy(record => record.CircuitNetworkOrderId.Trim(), StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.ToArray(), StringComparer.OrdinalIgnoreCase);
        return identifiers.Select(identifier => byCircuit.GetValueOrDefault(identifier, []))
            .Where(matches => matches.Length == 1)
            .Select(matches => matches[0])
            .ToArray();
    }

    private static Dictionary<string, string> FieldsForNetworkOrders(
        IReadOnlyDictionary<string, string> fields,
        IReadOnlyList<NetworkOrderCircuitEntry> records)
    {
        var result = new Dictionary<string, string>(fields, StringComparer.Ordinal);
        var circuitIds = JoinUnique(records.Select(record => record.CircuitNetworkOrderId), "\n");
        foreach (var key in new[] { "network_orders", "circuit", "circuit_ids" })
        {
            if (result.ContainsKey(key)) result[key] = circuitIds;
        }
        if (result.ContainsKey("network_order_ids"))
        {
            result["network_order_ids"] = string.Join(", ", records.Select(record => record.Id));
        }
        if (result.ContainsKey("excluded_network_order_ids")) result["excluded_network_order_ids"] = "";
        if (result.ContainsKey("a_location")) result["a_location"] = JoinUnique(records.Select(record => record.ALocation), "; ");
        if (result.ContainsKey("z_location")) result["z_location"] = JoinUnique(records.Select(record => record.ZLocation), "; ");
        return result;
    }

    private static Dictionary<string, string> CircuitlessFields(IReadOnlyDictionary<string, string> fields)
    {
        var result = new Dictionary<string, string>(fields, StringComparer.Ordinal);
        var mopType = (result.GetValueOrDefault("fiber_details") ?? "").Split('\n')
            .Select(line => line.Trim())
            .FirstOrDefault(line => line.StartsWith("MOP Type:", StringComparison.OrdinalIgnoreCase)) ?? "";
        foreach (var key in CircuitDetailFields)
        {
            if (result.ContainsKey(key)) result[key] = "";
        }
        if (mopType.Length > 0) result["fiber_details"] = $"\nFIBER MAINTENANCE DETAILS\n{mopType}\n";
        return result;
    }

    private static bool HasCircuitDetails(IReadOnlyDictionary<string, string> fields) =>
        CircuitDetailFields.Any(key => !string.IsNullOrWhiteSpace(fields.GetValueOrDefault(key)));

    private static List<string> NetworkOrderIdentifiers(IReadOnlyDictionary<string, string> fields)
    {
        var identifiers = new List<string>();
        var label = new Regex(@"^(?:Network Orders(?:/Circuit IDs(?: and A/Z locations)?)?|Circuit IDs?)\s*:\s*",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        foreach (var key in new[] { "network_orders", "circuit", "circuit_ids" })
        {
            foreach (var rawLine in (fields.GetValueOrDefault(key) ?? "").Split('\n'))
            {
                var line = rawLine.Trim();
                if (line.Length == 0 || Regex.IsMatch(line, @"^(?:A|Z) locations?\s*:", RegexOptions.IgnoreCase)
                    || line == "FIBER MAINTENANCE DETAILS") continue;
                line = label.Replace(line, "");
                var aMarker = line.IndexOf(" — A: ", StringComparison.Ordinal);
                if (aMarker >= 0) line = line[..aMarker].Trim();
                identifiers.AddRange(line.Split([';', ','], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
            }
        }
        foreach (var rawLine in (fields.GetValueOrDefault("fiber_details") ?? "").Split('\n'))
        {
            var line = rawLine.Trim();
            var match = label.Match(line);
            if (match.Success) line = line[match.Length..];
            else if (!line.Contains(" — A: ", StringComparison.Ordinal)) continue;
            var aMarker = line.IndexOf(" — A: ", StringComparison.Ordinal);
            if (aMarker >= 0) line = line[..aMarker].Trim();
            identifiers.AddRange(line.Split([';', ','], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
        }
        return UniqueStrings(identifiers);
    }

    private static string RenderHtmlAlternative(string body, IReadOnlyDictionary<string, string> fields)
    {
        var identifiers = NetworkOrderIdentifiers(fields).OrderByDescending(value => value.Length).ToArray();
        var encoded = WebUtility.HtmlEncode(body);
        if (identifiers.Length > 0)
        {
            var expression = new Regex($"(?<!\\w)(?:{string.Join("|", identifiers.Select(Regex.Escape))})(?!\\w)",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            var matches = expression.Matches(body);
            if (matches.Count > 0)
            {
                var result = new StringBuilder();
                var position = 0;
                foreach (Match match in matches)
                {
                    result.Append(WebUtility.HtmlEncode(body[position..match.Index]));
                    result.Append("<strong>").Append(WebUtility.HtmlEncode(match.Value)).Append("</strong>");
                    position = match.Index + match.Length;
                }
                result.Append(WebUtility.HtmlEncode(body[position..]));
                encoded = result.ToString();
            }
        }
        return $"<pre style=\"white-space:pre-wrap;overflow-wrap:anywhere;margin:0\">{encoded}</pre>";
    }

    private static OperationalEmailSendResult AggregateResults(
        string templateKey,
        IReadOnlyList<PreparedEmail> prepared,
        IReadOnlyList<OperationalEmailSendDelivery> outcomes)
    {
        var primary = outcomes.Where(outcome => !outcome.BccCopyOnly).ToArray();
        var copies = outcomes.Where(outcome => outcome.BccCopyOnly).ToArray();
        var successful = outcomes.Count(outcome => outcome.Status == "sent");
        var status = successful == outcomes.Count ? "sent" : successful > 0 ? "partial" : "failed";
        var hasCompanyGroups = prepared.Where(message => !message.BccCopyOnly)
            .Any(message => message.GroupCompany is not null);
        var first = primary[0];
        if (!hasCompanyGroups)
        {
            var message = first.Message;
            if (copies.Length > 0)
            {
                var copiesSent = copies.Count(item => item.Status == "sent");
                message = first.Status == "sent"
                    ? $"Email sent; {copiesSent} of {copies.Length} circuit-filtered BCC copies sent."
                    : $"Email delivery failed: {message} {copiesSent} circuit-filtered BCC copies sent.";
            }
            return new OperationalEmailSendResult(
                status, message, first.EmailId, first.DeliveryId, first.SentAtUtc, false, null, null,
                copies.Length > 0 ? outcomes.Select(item => item.EmailId).ToArray() : null,
                copies.Length > 0 ? outcomes.Select(item => (int?)item.DeliveryId).ToArray() : null,
                null,
                copies.Length > 0 ? copies : null);
        }

        var groupName = templateKey == OperationalEmailTemplateCatalog.FiberMaintenanceKey
            ? "Fiber Maintenance"
            : OperationalEmailTemplateCatalog.Find(templateKey)?.Label ?? templateKey;
        var sentPrimary = primary.Count(item => item.Status == "sent");
        var groupMessage = sentPrimary == primary.Length
            ? $"Sent {groupName} notices to {primary.Length} compan{(primary.Length == 1 ? "y" : "ies")}."
            : sentPrimary > 0
                ? $"Sent {sentPrimary} of {primary.Length} {groupName} notices; failed: {string.Join(", ", primary.Where(item => item.Status != "sent").Select(item => $"{item.Company}: {item.Message}"))}."
                : $"{groupName} notices failed for all {primary.Length} companies: {string.Join(", ", primary.Select(item => $"{item.Company}: {item.Message}"))}.";
        if (copies.Length > 0)
        {
            groupMessage += $" Circuit-filtered BCC copies sent: {copies.Count(item => item.Status == "sent")}/{copies.Length}.";
        }
        return new OperationalEmailSendResult(
            status,
            groupMessage,
            first.EmailId,
            first.DeliveryId,
            primary.LastOrDefault(item => item.SentAtUtc is not null)?.SentAtUtc,
            true,
            prepared.First(message => !message.BccCopyOnly).GroupId,
            primary.Length,
            outcomes.Select(item => item.EmailId).ToArray(),
            outcomes.Select(item => (int?)item.DeliveryId).ToArray(),
            primary,
            copies);
    }

    private static List<OperationalEmailAttachmentSnapshot> NormalizeAttachments(
        OperationalEmailTemplateDefinition definition,
        IReadOnlyList<OperationalEmailAttachmentInput>? attachments)
    {
        attachments ??= [];
        if (attachments.Count > MaxAttachments)
        {
            throw new ArgumentException($"No more than {MaxAttachments} attachments may be included.");
        }
        if (attachments.Count > 0 && !definition.AllowsAttachments)
        {
            throw new ArgumentException("Attachments are only supported by the Morning Report template.");
        }
        var result = new List<OperationalEmailAttachmentSnapshot>();
        var totalBytes = 0;
        foreach (var item in attachments)
        {
            var original = (item.FileName ?? "attachment").Replace('\\', '/');
            var fileName = original[(original.LastIndexOf('/') + 1)..].Trim();
            fileName = new string(fileName.Where(character => character >= ' ' && character != '\x7f').Take(120).ToArray());
            if (fileName.Length == 0) throw new ArgumentException("Attachment filename is required.");
            var contentType = string.IsNullOrWhiteSpace(item.ContentType)
                ? "application/octet-stream"
                : item.ContentType.Trim();
            if (contentType.Length > 100 || !ContentTypePattern.IsMatch(contentType))
            {
                throw new ArgumentException($"Attachment content type is invalid: {fileName}.");
            }
            var encoded = item.ContentBase64;
            if (string.IsNullOrEmpty(encoded) || encoded.Length > 7_000_000 || encoded.Any(char.IsWhiteSpace))
            {
                throw new ArgumentException($"Attachment content is invalid or too large: {fileName}.");
            }
            byte[] content;
            try
            {
                content = Convert.FromBase64String(encoded);
            }
            catch (FormatException exception)
            {
                throw new ArgumentException($"Attachment content is invalid: {fileName}.", exception);
            }
            if (!Convert.ToBase64String(content).Equals(encoded, StringComparison.Ordinal))
            {
                throw new ArgumentException($"Attachment content is invalid: {fileName}.");
            }
            if (content.Length > MaxAttachmentBytes)
            {
                throw new ArgumentException($"Attachment exceeds the 5 MiB limit: {fileName}.");
            }
            totalBytes += content.Length;
            if (totalBytes > MaxTotalAttachmentBytes)
            {
                throw new ArgumentException("Combined attachments may not exceed 20 MiB.");
            }
            result.Add(new OperationalEmailAttachmentSnapshot(fileName, contentType, content));
        }
        return result;
    }

    private static OperationalEmailSignatureEntry? SelectSignature(
        OperationalEmailSendInput input,
        IReadOnlyList<OperationalEmailSignatureEntry> signatures)
    {
        if (input.UseDefaultSignature is null)
        {
            throw new ArgumentException("Use-default-signature must be a boolean value.");
        }
        if (input.SignatureId is { } signatureId)
        {
            return signatures.FirstOrDefault(signature => signature.Id == signatureId)
                ?? throw new ArgumentException("The selected email signature is unavailable.");
        }
        return input.UseDefaultSignature.Value
            ? signatures.Where(signature => signature.IsDefault).OrderBy(signature => signature.Id).FirstOrDefault()
            : null;
    }

    private static void ValidateRequestBounds(OperationalEmailSendInput input)
    {
        if (string.IsNullOrWhiteSpace(input.TemplateKey) || input.TemplateKey.Length > 64)
        {
            throw new ArgumentException("Template key is required and must be no more than 64 characters.");
        }
        if (input.To?.Length > 5000 || input.Cc?.Length > 5000 || input.Bcc?.Length > 5000)
        {
            throw new ArgumentException("Recipient fields must be no more than 5,000 characters.");
        }
        if (input.Subject?.Length > 500 || input.Body?.Length > 200_000)
        {
            throw new ArgumentException("Email subject or body exceeds the allowed length.");
        }
        if (input.MaintenanceNoticeId is <= 0 || input.SourceEmailId is <= 0 || input.SignatureId is <= 0)
        {
            throw new ArgumentException("Linked message and signature IDs must be positive.");
        }
    }

    private static void EnsureDefaultRendered(
        OperationalEmailSendInput input,
        SendContext context,
        IReadOnlyDictionary<string, string> fields)
    {
        var previewSubject = Render(context.Template.DefaultSubject, fields);
        var previewBody = Render(context.Template.DefaultBody, fields);
        if ((!string.IsNullOrEmpty(input.Body) && input.Body != previewBody)
            || (!string.IsNullOrEmpty(input.Subject) && input.Subject != previewSubject))
        {
            var label = context.Definition.Key == "fiber_outage" ? "Fiber Outage" : "Fiber Maintenance";
            throw new ArgumentException($"{label} subject and message are rendered per company; edit shared template defaults instead.");
        }
    }

    private static void EnsureGlobalSender(SendContext context, string purpose)
    {
        if (!IsConfiguredSender(context.GlobalSender))
        {
            throw new ArgumentException($"Configure one valid active Global From address for Fiber {purpose}.");
        }
    }

    private static bool IsConfiguredSender(string? address) =>
        !string.IsNullOrWhiteSpace(address) && EmailAddressRules.IsValid(address);

    private static Dictionary<string, string> GetParentFields(
        string templateKey,
        OperationalEmailSourceMessage? parent)
    {
        if (parent is null) return new Dictionary<string, string>(StringComparer.Ordinal);
        var fields = new Dictionary<string, string>(parent.Fields, StringComparer.Ordinal);
        if (OperationalEmailTemplateCatalog.FiberOutageSourceKeys.Contains(parent.TemplateKey, StringComparer.Ordinal))
        {
            fields.TryAdd("network_orders", fields.GetValueOrDefault("circuit", ""));
            fields.TryAdd("company", fields.GetValueOrDefault("provider", ""));
        }
        if ((templateKey is "maintenance_complete" or OperationalEmailTemplateCatalog.MaintenanceStartKey)
            && parent.TemplateKey == OperationalEmailTemplateCatalog.FiberMaintenanceKey)
        {
            fields["network_orders"] = LegacyFiberNetworkOrderDetails(fields);
            var route = string.Join(" to ", new[] { fields.GetValueOrDefault("a_location"), fields.GetValueOrDefault("z_location") }
                .Where(value => !string.IsNullOrWhiteSpace(value)));
            if (route.Length > 0 && route.Length <= FieldMaximum(templateKey, "site")) fields.TryAdd("site", route);
            if (templateKey == "maintenance_complete") fields["fiber_details"] = FiberMaintenanceCompletionDetails(fields);
        }
        return fields;
    }

    private static string LegacyFiberNetworkOrderDetails(IReadOnlyDictionary<string, string> fields)
    {
        var networkOrders = fields.GetValueOrDefault("network_orders", "").Trim();
        if (networkOrders.Contains(" — A: ", StringComparison.Ordinal)) return networkOrders;
        var circuitIds = SplitLegacy(networkOrders);
        var aLocations = SplitLegacy(fields.GetValueOrDefault("a_location"));
        var zLocations = SplitLegacy(fields.GetValueOrDefault("z_location"));
        if (circuitIds.Length > 0 && circuitIds.Length == aLocations.Length && circuitIds.Length == zLocations.Length)
        {
            return string.Join("\n", circuitIds.Zip(aLocations, (id, a) => (id, a))
                .Zip(zLocations, (first, z) => $"{first.id} — A: {first.a} → Z: {z}"));
        }
        return string.Join("\n", new[]
        {
            networkOrders.Length > 0 ? $"Network Orders/Circuit IDs: {networkOrders}" : "",
            fields.GetValueOrDefault("a_location") is { Length: > 0 } a ? $"A locations: {a}" : "",
            fields.GetValueOrDefault("z_location") is { Length: > 0 } z ? $"Z locations: {z}" : "",
        }.Where(value => value.Length > 0));
    }

    private static string FiberMaintenanceCompletionDetails(IReadOnlyDictionary<string, string> fields)
    {
        var details = new List<string>();
        var orders = LegacyFiberNetworkOrderDetails(fields).Trim();
        if (orders.Length > 0) details.Add($"Network Orders/Circuit IDs and A/Z locations: {orders}");
        if (fields.GetValueOrDefault("mop_type") is { Length: > 0 } mopType)
        {
            details.Add($"MOP Type: {mopType}");
        }
        return details.Count == 0 ? "" : $"\nFIBER MAINTENANCE DETAILS\n{string.Join("\n", details)}\n";
    }

    private static string[] SplitLegacy(string? value) =>
        Regex.Split(value ?? "", @"[;\r\n]+").Select(item => item.Trim()).Where(item => item.Length > 0).ToArray();

    private static Dictionary<string, (string Name, List<NetworkOrderCircuitEntry> Records)> GroupByCompany(
        IReadOnlyList<NetworkOrderCircuitEntry> records)
    {
        var result = new Dictionary<string, (string Name, List<NetworkOrderCircuitEntry> Records)>(StringComparer.OrdinalIgnoreCase);
        foreach (var record in records)
        {
            var company = record.Company.Trim();
            if (company.Length == 0)
            {
                throw new ArgumentException("Every selected Network Order/Circuit must have a company assigned.");
            }
            if (!result.TryGetValue(company, out var group))
            {
                group = (company, []);
                result[company] = group;
            }
            group.Records.Add(record);
        }
        return result;
    }

    private static Dictionary<string, List<FiberEmailContactEntry>> ContactsByCompany(
        IReadOnlyList<FiberEmailContactEntry> contacts)
    {
        var result = new Dictionary<string, List<FiberEmailContactEntry>>(StringComparer.OrdinalIgnoreCase);
        foreach (var contact in contacts)
        {
            var company = contact.Company.Trim();
            if (company.Length == 0 || string.IsNullOrWhiteSpace(contact.Email)) continue;
            if (!result.TryGetValue(company, out var companyContacts))
            {
                companyContacts = [];
                result[company] = companyContacts;
            }
            companyContacts.Add(contact);
        }
        return result;
    }

    private static Dictionary<string, HashSet<string>> FiberContactCompanyMap(
        IReadOnlyList<FiberEmailContactEntry> contacts)
    {
        var result = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var contact in contacts)
        {
            if (string.IsNullOrWhiteSpace(contact.Email) || string.IsNullOrWhiteSpace(contact.Company)) continue;
            if (!result.TryGetValue(contact.Email.Trim(), out var companies))
            {
                companies = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                result[contact.Email.Trim()] = companies;
            }
            companies.Add(contact.Company.Trim());
        }
        return result;
    }

    private static string[] NormalizeRecipients(string? value) => OperationalEmailRules.NormalizeRecipients(value);

    private static string[] UniqueRecipients(IEnumerable<string> values) =>
        OperationalEmailRules.JoinUnique(values).Split(", ", StringSplitOptions.RemoveEmptyEntries);

    private static string JoinUnique(IEnumerable<string> values, string separator = ", ") =>
        string.Join(separator, values.Select(value => value?.Trim() ?? "")
            .Where(value => value.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase));

    private static List<string> UniqueStrings(IEnumerable<string> values) =>
        values.Select(value => value.Trim()).Where(value => value.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase).ToList();

    private static string FormatNetworkOrderDetails(IReadOnlyList<NetworkOrderCircuitEntry> records) =>
        string.Join("\n", records.Select(record =>
            $"{record.CircuitNetworkOrderId} — A: {record.ALocation} → Z: {record.ZLocation}"));

    private static string FirstNonempty(string? first, string? fallback) =>
        !string.IsNullOrWhiteSpace(first) ? first : fallback ?? "";

    private static IReadOnlySet<string> WithFields(IReadOnlySet<string> fields, params string[] additional) =>
        fields.Concat(additional).ToHashSet(StringComparer.Ordinal);

    private static string FieldLabel(OperationalEmailTemplateDefinition definition, string key) =>
        definition.Fields.FirstOrDefault(field => field.Key == key)?.Label ?? key;

    private static int FieldMaximum(string templateKey, string key) =>
        OperationalEmailTemplateCatalog.Find(templateKey)?.Fields.FirstOrDefault(field => field.Key == key)?.MaxLength ?? 0;

    private static string TimezoneAbbreviation()
    {
        var local = TimeZoneInfo.ConvertTime(DateTimeOffset.UtcNow, CentralTimeZone);
        return CentralTimeZone.IsDaylightSavingTime(local) ? "CDT" : "CST";
    }

    private static string FormatLocalDateTime(string value, string label)
    {
        var formats = new[]
        {
            "MM/dd/yy hh:mm tt", "MM/dd/yy h:mm tt", "yyyy-MM-dd'T'HH:mm",
            "yyyy-MM-dd'T'HH:mm:ss", "yyyy-MM-dd'T'HH:mm:ss.FFFFFF",
            "yyyy-MM-dd HH:mm", "yyyy-MM-dd HH:mm:ss", "yyyy-MM-dd HH:mm:ss.FFFFFF",
        };
        if (!DateTime.TryParseExact(value, formats, CultureInfo.InvariantCulture,
                DateTimeStyles.None, out var parsed))
        {
            throw new ArgumentException($"{label} must include a valid date and time.");
        }
        return parsed.ToString("MM/dd/yy hh:mm tt", CultureInfo.InvariantCulture);
    }

    private static string Render(string value, IReadOnlyDictionary<string, string> fields) =>
        TokenPattern.Replace(value, match => fields.GetValueOrDefault(match.Groups[1].Value, ""));

    private static void ValidateTokens(string value, HashSet<string> supported, string label)
    {
        var unknown = TokenPattern.Matches(value).Select(match => match.Groups[1].Value)
            .Where(token => !supported.Contains(token)).Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal).ToArray();
        if (unknown.Length > 0)
        {
            throw new ArgumentException($"Unsupported {label} placeholder(s): {string.Join(", ", unknown)}.");
        }
    }

    private static string NormalizeSubject(string value)
    {
        value = value.Trim();
        if (value.Length == 0 || value.Length > 500 || value.Contains('\r') || value.Contains('\n'))
        {
            throw new ArgumentException("Subject must be 1–500 characters with no line breaks.");
        }
        return value;
    }

    private static string NormalizeLines(string value) => value.Replace("\r\n", "\n").Replace('\r', '\n');

    private static string AppendSignature(string body, string? signature)
    {
        if (string.IsNullOrEmpty(signature) || body.Length == 0) return body;
        var separator = body.EndsWith('\n') || body.EndsWith('\r') ? "" : "\n\n";
        return $"{body}{separator}--\n{signature}";
    }

    private static string RemoveCircuitIdentifiers(string value, IReadOnlyList<string> identifiers)
    {
        if (identifiers.Count == 0) return value;
        var pattern = new Regex($"(?<!\\w)(?:{string.Join("|", identifiers.OrderByDescending(item => item.Length).Select(Regex.Escape))})(?!\\w)",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        return pattern.Replace(value, "");
    }

    private sealed record PreparedComposition(SendContext Context, List<PreparedEmail> Messages);

    private sealed record SendContext(
        OperationalEmailTemplateDefinition Definition,
        OperationalEmailTemplateDefault Template,
        string Provider,
        string SenderAddress,
        string GlobalSender,
        string TimezoneAbbreviation,
        IReadOnlyList<FiberEmailContactEntry> FiberContacts,
        IReadOnlyList<OnpageEmailContactEntry> OnpageContacts,
        IReadOnlyList<NetworkOrderCircuitEntry> NetworkOrders,
        IReadOnlyList<OperationalEmailSignatureEntry> Signatures,
        string LatestShiftAnalysis);

    private sealed record PersistedMessage(int EmailId, PreparedEmail Message);

    private sealed class PreparedEmail
    {
        public string TemplateKey { get; init; } = "";
        public int? SignatureId { get; init; }
        public string? SignatureName { get; init; }
        public string? SignatureContent { get; init; }
        public int? ParentEmailId { get; init; }
        public string? GroupId { get; set; }
        public string? GroupCompany { get; set; }
        public bool BccCopyOnly { get; init; }
        public string Subject { get; init; } = "";
        public string Body { get; init; } = "";
        public string SubjectTemplate { get; init; } = "";
        public string BodyTemplate { get; init; } = "";
        public IReadOnlyDictionary<string, string> Fields { get; init; } = new Dictionary<string, string>();
        public string[] ToRecipients { get; init; } = [];
        public string[] CcRecipients { get; init; } = [];
        public string[] BccRecipients { get; set; } = [];
        public IReadOnlyList<OperationalEmailAttachmentSnapshot> Attachments { get; init; } = [];
        public string? Company { get; set; }

        public OperationalEmailMessageSnapshot ToSnapshot(
            int actorUserId,
            OperationalEmailScheduleDefinition? schedule) => new(
            TemplateKey,
            actorUserId,
            SignatureId,
            SignatureName,
            SignatureContent,
            ParentEmailId,
            GroupId,
            GroupCompany,
            BccCopyOnly,
            Subject,
            Body,
            Fields,
            ToRecipients,
            CcRecipients,
            BccRecipients,
            schedule?.ScheduleType ?? "immediate",
            schedule?.Timezone ?? EmailTimezone,
            schedule?.ScheduledAt,
            schedule?.RecurrenceTime,
            schedule?.RecurrenceWeekday,
            schedule?.NextRunAt,
            Attachments);
    }
}
