"""
utils/helpers.py

Shared utility functions used across the Vulnerability Intelligence Engine.
"""

from typing import Any, Optional


def safe_get(data: dict, *keys: str, default: Any = None) -> Any:
    """
    Safely traverse a nested dictionary using a chain of keys.

    Args:
        data:    The source dictionary.
        *keys:   Sequence of keys to follow.
        default: Value returned when any key is missing or value is None.

    Returns:
        The found value, or `default`.

    Example:
        safe_get(resp, "cvssMetricV31", 0, "cvssData", "baseScore", default=0.0)
    """
    current = data
    for key in keys:
        if isinstance(current, dict):
            current = current.get(key)
        elif isinstance(current, list) and isinstance(key, int):
            try:
                current = current[key]
            except IndexError:
                return default
        else:
            return default
        if current is None:
            return default
    return current


def sanitize_package_name(name: str) -> str:
    """
    Strips whitespace and lowercases a package name for consistent comparison.

    Args:
        name: Raw package name string.

    Returns:
        Sanitized package name.
    """
    return name.strip().lower()


def is_valid_version(version: str) -> bool:
    """
    Basic version string validation.
    Accepts semver-like strings (e.g. '4.17.15', '2.25.0', '3.2').

    Args:
        version: Raw version string.

    Returns:
        True if the version string is non-empty and contains at least one digit.
    """
    if not version or not version.strip():
        return False
    return any(char.isdigit() for char in version)


def deduplicate_cves(vulnerabilities: list[dict]) -> list[dict]:
    """
    Remove duplicate vulnerability entries that share the same CVE ID.

    Args:
        vulnerabilities: List of normalized vulnerability dicts.

    Returns:
        De-duplicated list preserving first occurrence.
    """
    seen: set[str] = set()
    unique: list[dict] = []
    for vuln in vulnerabilities:
        cve_id: Optional[str] = vuln.get("cve_id")
        key = cve_id if cve_id else id(vuln)
        if key not in seen:
            seen.add(key)
            unique.append(vuln)
    return unique
