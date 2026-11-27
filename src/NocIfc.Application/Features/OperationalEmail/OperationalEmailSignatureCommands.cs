using NocIfc.Application.Abstractions.OperationalEmail;
using NocIfc.Domain.OperationalEmail;

namespace NocIfc.Application.Features.OperationalEmail;

public sealed record OperationalEmailSignaturePatch(
    string? Name,
    string? Content,
    bool? IsActive,
    bool? IsDefault,
    IReadOnlySet<string> ProvidedFields);

public sealed class OperationalEmailSignatureCommands(IOperationalEmailStore emailStore)
{
    private static readonly HashSet<string> AllowedFields =
        new(["name", "content", "is_active", "is_default"], StringComparer.Ordinal);

    public async Task<OperationalEmailSignatureEntry> CreateAsync(
        string? name,
        string? content,
        bool isActive,
        bool isDefault,
        int actorUserId,
        CancellationToken cancellationToken)
    {
        var validated = OperationalEmailRules.ValidateSignature(name, content);
        if (isDefault && !isActive)
        {
            throw new ArgumentException("An inactive signature cannot be the default.");
        }
        var result = await emailStore.CreateSignatureAsync(
            new OperationalEmailSignatureValues(validated.Name, validated.Content, isActive, isDefault),
            actorUserId,
            cancellationToken);
        if (result.NameConflict) throw new ArgumentException("A signature with this name already exists.");
        return result.Signature ?? throw new InvalidOperationException("The signature could not be created.");
    }

    public async Task<OperationalEmailSignatureEntry> UpdateAsync(
        int signatureId,
        OperationalEmailSignaturePatch patch,
        int actorUserId,
        CancellationToken cancellationToken)
    {
        var unknown = patch.ProvidedFields.Where(field => !AllowedFields.Contains(field))
            .OrderBy(field => field, StringComparer.Ordinal).ToArray();
        if (unknown.Length > 0)
        {
            throw new ArgumentException($"Unsupported signature field(s): {string.Join(", ", unknown)}.");
        }
        if (patch.ProvidedFields.Count == 0)
        {
            throw new ArgumentException("Provide at least one signature field to update.");
        }
        var existing = await emailStore.GetSignatureAsync(signatureId, cancellationToken)
            ?? throw new KeyNotFoundException("Operational email signature was not found.");
        var validated = OperationalEmailRules.ValidateSignature(
            patch.ProvidedFields.Contains("name") ? patch.Name : existing.Name,
            patch.ProvidedFields.Contains("content") ? patch.Content : existing.Content);
        var active = patch.ProvidedFields.Contains("is_active")
            ? patch.IsActive ?? throw new ArgumentException("Signature active setting must be a boolean value.")
            : existing.IsActive;
        var isDefault = patch.ProvidedFields.Contains("is_default")
            ? patch.IsDefault ?? throw new ArgumentException("Signature default setting must be a boolean value.")
            : existing.IsDefault;
        if (!active) isDefault = false;
        var result = await emailStore.UpdateSignatureAsync(
            signatureId,
            new OperationalEmailSignatureValues(validated.Name, validated.Content, active, isDefault),
            patch.ProvidedFields.Order(StringComparer.Ordinal).ToArray(),
            actorUserId,
            cancellationToken);
        if (!result.Found) throw new KeyNotFoundException("Operational email signature was not found.");
        if (result.NameConflict) throw new ArgumentException("A signature with this name already exists.");
        return result.Signature ?? throw new InvalidOperationException("The signature could not be updated.");
    }

    public Task<OperationalEmailSignatureEntry> DeactivateAsync(
        int signatureId,
        int actorUserId,
        CancellationToken cancellationToken) =>
        UpdateAsync(signatureId,
            new OperationalEmailSignaturePatch(null, null, false, false,
                new HashSet<string>(["is_active", "is_default"], StringComparer.Ordinal)),
            actorUserId,
            cancellationToken);
}
