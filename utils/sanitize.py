"""
Input Sanitization for NoSQL Injection Prevention
==================================================

MongoDB query operators start with $ (e.g., $ne, $gt, $regex).
If a user sends {"domain": {"$ne": ""}} as a JSON body,
MongoDB interprets it as "find where domain != empty"
instead of treating it as a literal value.

This module ensures all user inputs are plain strings
before they touch any MongoDB query.

Usage:
    from utils.sanitize import sanitize_domain, sanitize_string, sanitize_object_id

    domain = sanitize_domain(data.get("domain"))
    org_name = sanitize_string(data.get("org_name", ""), "org_name")
    vuln_id = sanitize_object_id(vuln_id)
"""


def sanitize_string(value, field_name="input"):
    """
    Ensure value is a plain string, not a dict/list that could
    be interpreted as a MongoDB operator.

    Args:
        value: The input to sanitize
        field_name: Name of the field (for error messages)

    Returns:
        Stripped string

    Raises:
        ValueError: If value is None, dict, list, or starts with $
    """
    if value is None:
        raise ValueError(f"{field_name} is required")
    if isinstance(value, dict):
        raise ValueError(f"{field_name} contains invalid characters")
    if isinstance(value, list):
        raise ValueError(f"{field_name} must be a string, not a list")

    result = str(value).strip()

    # Reject strings that look like MongoDB operators
    if result.startswith("$"):
        raise ValueError(f"{field_name} contains invalid characters")

    return result


def sanitize_string_optional(value, field_name="input", default=""):
    """
    Like sanitize_string but allows None/empty — returns default instead.

    Use for optional fields like org_name, description.
    """
    if value is None or value == "":
        return default
    return sanitize_string(value, field_name)


def sanitize_domain(value):
    """
    Validate and sanitize a domain name.

    - Ensures it's a plain string
    - Lowercases
    - Strips protocol prefixes (http://, https://, www.)
    - Validates format (must contain a dot)
    - Rejects overly long domains

    Args:
        value: Raw domain input

    Returns:
        Clean, lowercase domain string

    Raises:
        ValueError: If domain is invalid
    """
    domain = sanitize_string(value, "domain").lower()

    if not domain:
        raise ValueError("Domain is required")

    # Remove protocol if accidentally included
    for prefix in ["https://", "http://", "www."]:
        if domain.startswith(prefix):
            domain = domain[len(prefix):]

    # Remove trailing dots/slashes
    domain = domain.rstrip("/.")

    if "." not in domain:
        raise ValueError(f"Invalid domain: '{domain}'")

    if len(domain) > 253:
        raise ValueError("Domain name too long (max 253 characters)")

    # Basic character validation
    allowed = set(
        "abcdefghijklmnopqrstuvwxyz0123456789.-"
    )
    if not all(c in allowed for c in domain):
        raise ValueError(
            f"Invalid domain: '{domain}' — "
            f"only letters, numbers, dots, and hyphens allowed"
        )

    return domain


def sanitize_object_id(value, field_name="id"):
    """
    Validate that a value looks like a valid MongoDB ObjectId.

    ObjectIds are 24-character hexadecimal strings.
    This prevents invalid IDs from causing bson.errors.InvalidId exceptions
    and provides a cleaner error message.

    Args:
        value: Raw ID input
        field_name: Name for error messages

    Returns:
        Validated ObjectId string

    Raises:
        ValueError: If not a valid ObjectId format
    """
    value = sanitize_string(value, field_name)

    if len(value) != 24:
        raise ValueError(
            f"'{value}' is not a valid {field_name} "
            f"(expected 24 hex characters)"
        )

    try:
        int(value, 16)  # Must be valid hexadecimal
    except ValueError:
        raise ValueError(
            f"'{value}' is not a valid {field_name} "
            f"(must be hexadecimal)"
        )

    return value


def sanitize_status(value, allowed_statuses, field_name="status"):
    """
    Validate a status value against an allowed set.

    Args:
        value: Raw status input
        allowed_statuses: Tuple/set of valid status strings
        field_name: Name for error messages

    Returns:
        Lowercase validated status string

    Raises:
        ValueError: If status not in allowed set
    """
    status = sanitize_string(value, field_name).lower()

    if status not in allowed_statuses:
        raise ValueError(
            f"Invalid {field_name}: '{status}'. "
            f"Allowed: {', '.join(sorted(allowed_statuses))}"
        )

    return status


def sanitize_severity(value):
    """Shortcut to validate vulnerability severity level."""
    return sanitize_status(
        value,
        ("critical", "high", "medium", "low", "info"),
        "severity"
    )