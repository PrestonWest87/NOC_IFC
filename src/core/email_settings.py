"""Resolve the active outbound SMTP profile from the shared application config."""

from __future__ import annotations


def get_active_smtp_profile(config, overrides: dict | None = None) -> dict:
    """Return the selected SMTP profile, optionally applying pending admin edits.

    The existing configurable SMTP profile remains the default for compatibility.
    Gmail uses Google's fixed submission endpoint and OAuth2 refresh credentials;
    the default recipient remains shared so switching senders does not change
    message routing.
    """
    overrides = overrides or {}

    def value(name, default=None):
        if name in overrides:
            return overrides[name]
        return getattr(config, name, default) if config is not None else default

    provider = value("active_smtp_provider", "smtp") or "smtp"
    if provider == "gmail":
        username = value("gmail_smtp_username", "") or ""
        return {
            "provider": "gmail",
            "enabled": bool(value("gmail_smtp_enabled", False)),
            "server": "smtp.gmail.com",
            "port": 587,
            "username": username,
            "client_id": value("gmail_smtp_client_id", "") or "",
            "client_secret": value("gmail_smtp_client_secret", "") or "",
            "refresh_token": value("gmail_smtp_refresh_token", "") or "",
            "sender": value("gmail_smtp_sender", "") or username,
            "recipient": value("smtp_recipient", "") or "",
        }

    if provider == "smtp":
        return {
            "provider": "smtp",
            "enabled": bool(value("smtp_enabled", False)),
            "server": value("smtp_server", "") or "",
            "port": value("smtp_port", 587) or 587,
            "username": value("smtp_username", "") or "",
            "password": value("smtp_password", "") or "",
            "sender": value("smtp_sender", "") or "",
            "recipient": value("smtp_recipient", "") or "",
        }

    return {
        "provider": str(provider), "enabled": False, "server": "", "port": 587,
        "username": "", "password": "", "sender": "", "recipient": "",
    }


def smtp_profile_is_ready(profile: dict) -> bool:
    """Return whether the selected, enabled profile has the fields needed to send."""
    if not profile.get("enabled") or not profile.get("server") or not profile.get("sender"):
        return False
    if profile.get("provider") == "gmail":
        return bool(
            profile.get("username")
            and profile.get("client_id")
            and profile.get("client_secret")
            and profile.get("refresh_token")
        )
    return profile.get("provider") == "smtp"
