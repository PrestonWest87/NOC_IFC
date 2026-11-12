"""Refresh short-lived Google OAuth access tokens for Gmail SMTP XOAUTH2."""

from __future__ import annotations

import requests


GOOGLE_OAUTH_TOKEN_URL = "https://oauth2.googleapis.com/token"


class GmailOAuthError(RuntimeError):
    """Credential-safe failure while refreshing a Google access token."""


def refresh_gmail_access_token(profile: dict) -> str:
    """Exchange a stored OAuth refresh token for a short-lived access token.

    The returned token is used only for one SMTP authentication attempt. Neither
    request credentials nor Google's response body are included in raised errors.
    """
    required = ("client_id", "client_secret", "refresh_token")
    if any(not profile.get(key) for key in required):
        raise GmailOAuthError("Gmail OAuth is incomplete; configure the OAuth client and refresh token.")

    try:
        response = requests.post(
            GOOGLE_OAUTH_TOKEN_URL,
            data={
                "client_id": profile["client_id"],
                "client_secret": profile["client_secret"],
                "refresh_token": profile["refresh_token"],
                "grant_type": "refresh_token",
            },
            timeout=10,
        )
        if response.status_code != 200:
            raise GmailOAuthError(f"Google OAuth token refresh failed (HTTP {response.status_code}).")
        payload = response.json()
    except GmailOAuthError:
        raise
    except (requests.RequestException, ValueError, TypeError) as exc:
        raise GmailOAuthError("Google OAuth token refresh failed; verify the OAuth client and refresh-token grant.") from exc

    access_token = payload.get("access_token") if isinstance(payload, dict) else None
    if not isinstance(access_token, str) or not access_token:
        raise GmailOAuthError("Google OAuth did not return an access token; reconnect the Gmail account.")
    return access_token
