using NocIfc.Domain.OperationalEmail;

namespace NocIfc.Application.Abstractions.OperationalEmail;

public interface IOperationalEmailStore
{
    Task EnsureTemplateDefaultsAsync(IReadOnlyList<OperationalEmailTemplateDefault> defaults, CancellationToken cancellationToken);
    Task<IReadOnlyList<OperationalEmailTemplateDefault>> GetTemplateDefaultsAsync(CancellationToken cancellationToken);
    Task<bool> UpdateTemplateDefaultsAsync(
        string templateKey,
        IReadOnlyDictionary<string, string> values,
        int actorUserId,
        CancellationToken cancellationToken);
    Task<IReadOnlyList<OperationalEmailSignatureEntry>> GetSignaturesAsync(bool includeInactive, CancellationToken cancellationToken);
    Task<OperationalEmailSignatureEntry?> GetSignatureAsync(int signatureId, CancellationToken cancellationToken);
    Task<OperationalEmailSignatureMutation> CreateSignatureAsync(
        OperationalEmailSignatureValues signature,
        int actorUserId,
        CancellationToken cancellationToken);
    Task<OperationalEmailSignatureMutation> UpdateSignatureAsync(
        int signatureId,
        OperationalEmailSignatureValues signature,
        IReadOnlyList<string> changedFields,
        int actorUserId,
        CancellationToken cancellationToken);
}
