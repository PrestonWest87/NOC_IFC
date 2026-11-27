using MailKit;
using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.Data.Sqlite;
using MimeKit;
using NocIfc.Application.Abstractions.Email;
using NocIfc.Infrastructure.Persistence.Sqlite;

namespace NocIfc.Infrastructure.Email;

public sealed class SqliteEmailSender(
    SqliteConnectionFactory connections,
    GmailOAuthTokenProvider gmailTokens) : IEmailSender
{
    public Task<EmailSendResult> SendPlainTextAsync(
        string recipientOverride,
        string subject,
        string body,
        CancellationToken cancellationToken) =>
        SendAsync(recipientOverride, subject, body, false, cancellationToken);

    public Task<EmailSendResult> SendHtmlAsync(
        string recipientOverride,
        string subject,
        string body,
        CancellationToken cancellationToken) =>
        SendAsync(recipientOverride, subject, body, true, cancellationToken);

    private async Task<EmailSendResult> SendAsync(
        string recipientOverride,
        string subject,
        string body,
        bool isHtml,
        CancellationToken cancellationToken)
    {
        var profile = await ReadProfileAsync(cancellationToken);
        var recipient = string.IsNullOrWhiteSpace(recipientOverride) ? profile.Recipient : recipientOverride;
        var providerName = profile.Provider == "gmail" ? "Gmail SMTP" : "SMTP";
        if (!profile.Enabled)
        {
            return new EmailSendResult(false, $"{providerName} is disabled in Settings.");
        }
        if (string.IsNullOrWhiteSpace(profile.Server)
            || string.IsNullOrWhiteSpace(profile.Sender)
            || string.IsNullOrWhiteSpace(recipient))
        {
            return new EmailSendResult(false, $"{providerName} configuration is incomplete.");
        }
        if (profile.Provider == "gmail"
            && (string.IsNullOrWhiteSpace(profile.Username)
                || string.IsNullOrWhiteSpace(profile.ClientId)
                || string.IsNullOrWhiteSpace(profile.ClientSecret)
                || string.IsNullOrWhiteSpace(profile.RefreshToken)))
        {
            return new EmailSendResult(false, "Gmail SMTP requires a complete OAuth 2.0 profile.");
        }
        if (profile.Provider is not ("smtp" or "gmail"))
        {
            return new EmailSendResult(false, "The active email provider is unsupported.");
        }

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(10));
        try
        {
            var message = new MimeMessage();
            message.From.AddRange(InternetAddressList.Parse(profile.Sender));
            message.To.AddRange(InternetAddressList.Parse(recipient));
            message.Subject = $"[NOC FUSION] {subject}";
            message.Body = new TextPart(isHtml ? "html" : "plain") { Text = body };

            using var client = new SmtpClient { Timeout = 10_000 };
            await client.ConnectAsync(profile.Server, profile.Port, SecureSocketOptions.StartTls, timeout.Token);
            if (profile.Provider == "gmail")
            {
                var accessToken = await gmailTokens.RefreshAsync(
                    profile.ClientId,
                    profile.ClientSecret,
                    profile.RefreshToken,
                    timeout.Token);
                await client.AuthenticateAsync(
                    new SaslMechanismOAuth2(profile.Username!, accessToken),
                    timeout.Token);
            }
            else if (!string.IsNullOrEmpty(profile.Username) && !string.IsNullOrEmpty(profile.Password))
            {
                await client.AuthenticateAsync(profile.Username, profile.Password, timeout.Token);
            }

            await client.SendAsync(message, timeout.Token);
            await client.DisconnectAsync(true, timeout.Token);
            return new EmailSendResult(true, "Email sent successfully.");
        }
        catch (GmailOAuthException exception)
        {
            return new EmailSendResult(false, exception.Message);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new EmailSendResult(false, "SMTP request timed out.");
        }
        catch (MailKit.Security.AuthenticationException)
        {
            return new EmailSendResult(false, profile.Provider == "gmail"
                ? "Gmail OAuth2 SMTP authentication failed. Check the account, refresh token, and Gmail scope."
                : "SMTP authentication failed.");
        }
        catch (Exception)
        {
            return new EmailSendResult(false, "SMTP delivery failed.");
        }
    }

    private async Task<EmailProfile> ReadProfileAsync(CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT active_smtp_provider, smtp_server, smtp_port, smtp_username, smtp_password,
                   smtp_sender, smtp_recipient, smtp_enabled, gmail_smtp_username,
                   gmail_smtp_client_id, gmail_smtp_client_secret, gmail_smtp_refresh_token,
                   gmail_smtp_sender, gmail_smtp_enabled
            FROM system_config
            ORDER BY id
            LIMIT 1
            """;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return EmailProfile.Disabled;
        }

        var provider = ReadString(reader, 0);
        if (string.IsNullOrEmpty(provider))
        {
            provider = "smtp";
        }
        var recipient = ReadString(reader, 6) ?? "";
        return provider switch
        {
            "gmail" => new EmailProfile(
                provider,
                !reader.IsDBNull(13) && reader.GetBoolean(13),
                "smtp.gmail.com",
                587,
                ReadString(reader, 8) ?? "",
                "",
                string.IsNullOrEmpty(ReadString(reader, 12)) ? ReadString(reader, 8) ?? "" : ReadString(reader, 12)!,
                recipient,
                ReadString(reader, 9) ?? "",
                ReadString(reader, 10) ?? "",
                ReadString(reader, 11) ?? ""),
            "smtp" => new EmailProfile(
                provider,
                !reader.IsDBNull(7) && reader.GetBoolean(7),
                ReadString(reader, 1) ?? "",
                reader.IsDBNull(2) || reader.GetInt32(2) == 0 ? 587 : reader.GetInt32(2),
                ReadString(reader, 3) ?? "",
                ReadString(reader, 4) ?? "",
                ReadString(reader, 5) ?? "",
                recipient,
                "",
                "",
                ""),
            _ => new EmailProfile(provider, false, "", 587, "", "", "", recipient, "", "", ""),
        };
    }

    private static string? ReadString(SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);

    private sealed record EmailProfile(
        string Provider,
        bool Enabled,
        string Server,
        int Port,
        string Username,
        string Password,
        string Sender,
        string Recipient,
        string ClientId,
        string ClientSecret,
        string RefreshToken)
    {
        public static EmailProfile Disabled { get; } = new("smtp", false, "", 587, "", "", "", "", "", "", "");
    }
}
