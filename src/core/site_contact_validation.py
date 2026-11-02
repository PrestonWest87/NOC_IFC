"""Shared validation and normalization for reference contacts attached to sites."""

import re


SITE_CONTACT_MAX_ENTRIES = 50
SITE_CONTACT_FIELD_LIMITS = {
    "name": 128,
    "phone": 64,
    "email": 254,
}

_EMAIL_PATTERN = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}$"
)
_PHONE_EXTENSION_PATTERN = re.compile(
    r" *(?:ext\.?|x|#) *[0-9]{1,10}$", re.IGNORECASE
)
_PHONE_CORE_PATTERN = re.compile(
    r"^\+?(?:[0-9]|\([0-9]{1,5}\))[0-9(). -]*$"
)


def normalize_site_contact_value(field: str, value):
    """Trim one optional contact value and validate its type, size, and syntax."""
    if field not in SITE_CONTACT_FIELD_LIMITS:
        raise ValueError(f"Unsupported site contact field: {field}.")
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"Contact {field} must be text.")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError(f"Contact {field} cannot contain control characters.")

    normalized = value.strip()
    if not normalized:
        return None
    if len(normalized) > SITE_CONTACT_FIELD_LIMITS[field]:
        raise ValueError(
            f"Contact {field} must be at most {SITE_CONTACT_FIELD_LIMITS[field]} characters."
        )

    if field == "email" and not _EMAIL_PATTERN.fullmatch(normalized):
        raise ValueError("Contact email must be a valid single email address.")
    if field == "phone":
        extension = _PHONE_EXTENSION_PATTERN.search(normalized)
        number = normalized[:extension.start()].rstrip() if extension else normalized
        if not _PHONE_CORE_PATTERN.fullmatch(number):
            raise ValueError(
                "Contact phone must use digits, an optional leading +, common phone separators, "
                "and an optional extension."
            )
        if number.count("(") != number.count(")") or number.count("(") > 1:
            raise ValueError("Contact phone must use balanced parentheses.")
        if "(" in number:
            opening = number.index("(")
            closing = number.find(")", opening + 1)
            if closing < 0 or number.find(")") != closing:
                raise ValueError("Contact phone must use balanced parentheses.")
            if not number[opening + 1:closing].isdigit():
                raise ValueError("Contact phone parentheses must contain digits.")
        digit_count = sum(character.isdigit() for character in number)
        if not 7 <= digit_count <= 15:
            raise ValueError(
                "Contact phone must contain 7 to 15 digits, excluding an optional extension."
            )
    return normalized


def normalize_site_contact(contact):
    """Return the optional name/phone/email fields from one contact-like mapping."""
    if not isinstance(contact, dict):
        raise ValueError("Each site contact must be an object.")
    return {
        field: normalize_site_contact_value(field, contact.get(field))
        for field in SITE_CONTACT_FIELD_LIMITS
    }


def normalize_site_contacts(contacts):
    """Validate an ordered list, dropping entries whose optional fields are all blank."""
    if not isinstance(contacts, list):
        raise ValueError("Site contacts must be a list.")
    if len(contacts) > SITE_CONTACT_MAX_ENTRIES:
        raise ValueError(f"A site can have at most {SITE_CONTACT_MAX_ENTRIES} contacts.")
    normalized = []
    for contact in contacts:
        values = normalize_site_contact(contact)
        if any(value is not None for value in values.values()):
            normalized.append(values)
    return normalized
