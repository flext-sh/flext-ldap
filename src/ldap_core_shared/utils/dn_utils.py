"""
DN (Distinguished Name) manipulation utilities.

Provides utilities for parsing, validating, and manipulating
LDAP Distinguished Names.
"""
from __future__ import annotations

from ldap_core_shared.domain.value_objects import LdapDn


def parse_dn(dn_string: str) -> LdapDn:
    """
    Parse DN string into LdapDn object.

    Args:
        dn_string: DN string to parse

    Returns:
        LdapDn object

    Raises:
        ValueError: If DN format is invalid
    """
    return LdapDn.from_string(dn_string)


def normalize_dn(dn_string: str) -> str:
    """
    Normalize DN string to standard format.

    Args:
        dn_string: DN string to normalize

    Returns:
        Normalized DN string
    """
    dn = parse_dn(dn_string)
    normalized = dn.normalize()
    return str(normalized)


def is_child_dn(child_dn: str, parent_dn: str) -> bool:
    """
    Check if one DN is a child of another.

    Args:
        child_dn: Potential child DN
        parent_dn: Potential parent DN

    Returns:
        True if child_dn is a child of parent_dn
    """
    child = parse_dn(child_dn)
    parent = parse_dn(parent_dn)
    return child.is_child_of(parent)


def get_parent_dn(dn_string: str) -> str | None:
    """
    Get parent DN of the given DN.

    Args:
        dn_string: DN string

    Returns:
        Parent DN string or None if no parent
    """
    dn = parse_dn(dn_string)
    parent = dn.get_parent_dn()
    return str(parent) if parent else None


def get_rdn(dn_string: str) -> str:
    """
    Get the Relative DN (first component) of a DN.

    Args:
        dn_string: DN string

    Returns:
        RDN string
    """
    dn = parse_dn(dn_string)
    rdn = dn.get_rdn()
    return str(rdn)


def replace_base_dn(dn_string: str, old_base: str, new_base: str) -> str:
    """
    Replace the base DN portion of a DN.

    Args:
        dn_string: Original DN
        old_base: Old base DN to replace
        new_base: New base DN

    Returns:
        DN with replaced base

    Raises:
        ValueError: If DN is not a child of old_base
    """
    dn = parse_dn(dn_string)
    old_base_dn = parse_dn(old_base)
    new_base_dn = parse_dn(new_base)

    result = dn.replace_base_dn(old_base_dn, new_base_dn)
    return str(result)


def escape_dn_value(value: str) -> str:
    """
    Escape special characters in DN value.

    Args:
        value: Value to escape

    Returns:
        Escaped value
    """
    # Characters that need escaping in DN values
    escape_chars = {
        "\\": "\\\\",
        ",": "\\,",
        "+": "\\+",
        '"': '\\"',
        "<": "\\<",
        ">": "\\>",
        ";": "\\;",
        "=": "\\=",
        "#": "\\#",
    }

    escaped = value
    for escaped_char in escape_chars.values():
        escaped = escaped.replace(char, escaped_char)

    # Leading and trailing spaces also need escaping
    if escaped.startswith(" "):
        escaped = "\\ " + escaped[1:]
    if escaped.endswith(" "):
        escaped = escaped[:-1] + "\\ "

    return escaped


def unescape_dn_value(value: str) -> str:
    """
    Unescape DN value.

    Args:
        value: Escaped value

    Returns:
        Unescaped value
    """
    # Simple unescaping - reverse of escape_dn_value
    unescaped = value

    # Handle escaped characters
    unescaped = unescaped.replace("\\\\", "\\")
    unescaped = unescaped.replace("\\,", ",")
    unescaped = unescaped.replace("\\+", "+")
    unescaped = unescaped.replace('\\"', '"')
    unescaped = unescaped.replace("\\<", "<")
    unescaped = unescaped.replace("\\>", ">")
    unescaped = unescaped.replace("\\;", ";")
    unescaped = unescaped.replace("\\=", "=")
    unescaped = unescaped.replace("\\#", "#")
    return unescaped.replace("\\ ", " ")


def extract_attribute_value(dn_string: str, attribute: str) -> str | None:
    """
    Extract value of specific attribute from DN.

    Args:
        dn_string: DN string
        attribute: Attribute name to extract

    Returns:
        Attribute value or None if not found
    """
    try:
        dn = parse_dn(dn_string)
        for component in dn.components:
            if component.attribute.lower() == attribute.lower():
                return component.value
        return None
    except ValueError:
        return None


def build_dn(components: list[tuple[str, str]]) -> str:
    """
    Build DN string from list of (attribute, value) tuples.

    Args:
        components: List of (attribute, value) tuples

    Returns:
        DN string
    """
    dn_components: list = []
    for attr, value in components:
        escaped_value = escape_dn_value(value)
        dn_components.append(f"{attr}={escaped_value}")

    return ",".join(dn_components)


def split_dn_components(dn_string: str) -> list[tuple[str, str]]:
    """
    Split DN into list of (attribute, value) tuples.

    Args:
        dn_string: DN string

    Returns:
        List of (attribute, value) tuples
    """
    try:
        dn = parse_dn(dn_string)
        return [(comp.attribute, comp.value) for comp in dn.components]
    except ValueError:
        return []


def validate_dn_format(dn_string: str) -> tuple[bool, str | None]:
    """
    Validate DN format.

    Args:
        dn_string: DN string to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not dn_string or not dn_string.strip():
        return False, "DN cannot be empty"

    try:
        parse_dn(dn_string)
        return True, None
    except ValueError as e:
        return False, str(e)


def get_dn_depth(dn_string: str) -> int:
    """
    Get the depth (number of components) of a DN.

    Args:
        dn_string: DN string

    Returns:
        Number of DN components
    """
    try:
        dn = parse_dn(dn_string)
        return len(dn.components)
    except ValueError:
        return 0


def find_common_base_dn(dn_list: list[str]) -> str | None:
    """
    Find common base DN among a list of DNs.

    Args:
        dn_list: List of DN strings

    Returns:
        Common base DN or None if no common base
    """
    if not dn_list:
        return None

    if len(dn_list) == 1:
        parent = get_parent_dn(dn_list[0])
        return parent if parent else dn_list[0]

    try:
        # Parse all DNs
        parsed_dns = [parse_dn(dn) for dn in dn_list]

        # Find minimum depth
        min_depth = min(len(dn.components) for dn in parsed_dns)

        if min_depth == 0:
            return None

        # Check components from the end (base) backwards
        common_components: list = []
        for i in range(min_depth):
            # Get component at position from end
            pos = -(i + 1)
            components = [dn.components[pos] for dn in parsed_dns]

            # Check if all components at this position are the same
            first_comp = components[0]
            if all(
                comp.attribute.lower() == first_comp.attribute.lower()
                and comp.value.lower() == first_comp.value.lower()
                for comp in components
            ):
                common_components.insert(0, first_comp)
                break

        if common_components:
            common_dn = LdapDn(components=common_components)
            return str(common_dn)

        return None

    except ValueError:
        return None


def rewrite_dn_base(dn_string: str, base_mappings: dict[str, str]) -> str:
    """
    Rewrite DN base using mapping rules.

    Args:
        dn_string: Original DN
        base_mappings: Dict of old_base -> new_base mappings

    Returns:
        DN with rewritten base or original DN if no mapping found
    """
    for new_base in base_mappings.values():
        try:
            if is_child_dn(dn_string, old_base):
                return replace_base_dn(dn_string, old_base, new_base)
        except ValueError:
            continue

    return dn_string
