using System.Text.Json;

namespace NocIfc.Infrastructure.Email;

public sealed class GmailOAuthException(string message) : Exception(message);

public sealed class GmailOAuthTokenProvider(HttpClient httpClient)
{
    public async Task<string> RefreshAsync(
        string clientId,
        string clientSecret,
        string refreshToken,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(clientId)
            || string.IsNullOrWhiteSpace(clientSecret)
            || string.IsNullOrWhiteSpace(refreshToken))
        {
            throw new GmailOAuthException("Gmail OAuth is incomplete; configure the client and refresh token.");
        }

        using var request = new HttpRequestMessage(HttpMethod.Post, "https://oauth2.googleapis.com/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["client_id"] = clientId,
                ["client_secret"] = clientSecret,
                ["refresh_token"] = refreshToken,
                ["grant_type"] = "refresh_token",
            }),
        };

        try
        {
            using var response = await httpClient.SendAsync(request, cancellationToken);
            using var content = await JsonDocument.ParseAsync(
                await response.Content.ReadAsStreamAsync(cancellationToken),
                cancellationToken: cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                var errorCode = content.RootElement.TryGetProperty("error", out var error)
                    ? error.GetString()
                    : null;
                throw new GmailOAuthException(ErrorMessage(errorCode, (int)response.StatusCode));
            }

            if (!content.RootElement.TryGetProperty("access_token", out var accessToken)
                || string.IsNullOrEmpty(accessToken.GetString()))
            {
                throw new GmailOAuthException("Google OAuth did not return an access token; reconnect the Gmail account.");
            }
            return accessToken.GetString()!;
        }
        catch (GmailOAuthException)
        {
            throw;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new GmailOAuthException("Google OAuth token refresh timed out.");
        }
        catch (Exception exception) when (exception is HttpRequestException or JsonException)
        {
            throw new GmailOAuthException("Google OAuth token refresh failed; verify the OAuth client and refresh-token grant.");
        }
    }

    private static string ErrorMessage(string? error, int statusCode) => error switch
    {
        "invalid_client" => "Google rejected the OAuth client. Verify the client ID and secret.",
        "invalid_grant" => "Google rejected the refresh token. Reauthorize the account.",
        "unauthorized_client" => "Google does not allow this OAuth client to use the refresh-token grant.",
        "invalid_scope" => "The Google OAuth grant does not include the Gmail SMTP scope.",
        "admin_policy_enforced" => "Workspace policy blocks this OAuth client or Gmail scope.",
        _ => $"Google OAuth token refresh failed (HTTP {statusCode}).",
    };
}
