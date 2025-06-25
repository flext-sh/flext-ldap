"""Simple DN utilities without complex dependencies.

Provides basic DN manipulation utilities that can be used
without importing the complex event system.
"""


def simple_parse_dn(dn_string: str) -> list[tuple[str, str]]:
    """Simple DN parser that returns list of (attribute, value) tuples.

    Args:
        dn_string: DN string to parse

    Returns:
        List of (attribute, value) tuples

    Raises:
        ValueError: If DN format is invalid
    """
    if not dn_string or not dn_string.strip():
        msg = "DN cannot be empty"
        raise ValueError(msg)

    components: list[tuple[str, str]] = []
    # Simple DN parsing (would need more sophisticated parsing for complex cases)
    parts = [part.strip() for part in dn_string.split(",")]

    for part in parts:
        if "=" not in part:
            msg = f"Invalid DN component: {part}"
            raise ValueError(msg)

        attr, value = part.split("=", 1)
        components.append((attr.strip().lower(), value.strip()))

    return components


def simple_normalize_dn(dn_string: str) -> str:
    """Simple DN normalization.

    Args:
        dn_string: DN string to normalize

    Returns:
        Normalized DN string
    """
    components = simple_parse_dn(dn_string)
    return ",".join(f"{attr}={value}" for attr, value in components)


def simple_is_child_dn(child_dn: str, parent_dn: str) -> bool:
    """Check if one DN is a child of another (simple version).

    Args:
        child_dn: Potential child DN
        parent_dn: Potential parent DN

    Returns:
        True if child_dn is a child of parent_dn
    """
    try:
        child_components = simple_parse_dn(child_dn)
        parent_components = simple_parse_dn(parent_dn)

        if len(child_components) <= len(parent_components):
            return False

        # Check if parent components match the end of child components
        parent_start = len(child_components) - len(parent_components)
        child_suffix = child_components[parent_start:]

        for i, (p_attr, p_val) in enumerate(parent_components):
            c_attr, c_val = child_suffix[i]
            if p_attr.lower() != c_attr.lower() or p_val.lower() != c_val.lower():
                return False

        return True
    except ValueError:
        return False
