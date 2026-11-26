namespace NocIfc.Domain.Identity;

public sealed record LoginCredential(int Id, string Username, string? PasswordHash, bool IsActive);
