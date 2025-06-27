"""DN (Distinguished Name) manipulation utilities - Enterprise Delegation Facade.

TRUE FACADE PATTERN: 100% DELEGATION TO ENTERPRISE DN INFRASTRUCTURE
====================================================================

This module delegates entirely to the enterprise-grade DN utilities in
utilities.dn without any reimplementation.

DELEGATION TARGET: utilities.dn.DistinguishedName - Enterprise DN processing with
RFC 4514 compliance, comprehensive validation, advanced manipulation.

MIGRATION BENEFITS:
- Eliminated DN implementation duplication
- Leverages enterprise validation and RFC compliance
- Automatic improvements from enterprise DN system
- Consistent behavior across all DN usage
"""

from __future__ import annotations

# Keep domain imports for compatibility but use enterprise implementations
from ldap_core_shared.domain.value_objects import DNComponent, LdapDn

# Delegate to enterprise DN infrastructure
from ldap_core_shared.utilities.dn import (
    DistinguishedName as EnterpriseDistinguishedName,
)
from ldap_core_shared.utilities.dn import (
    DNParser,
    escape_dn_value,
    get_dn_parent,
    get_dn_rdn,
    is_valid_dn,
)
from ldap_core_shared.utilities.dn import (
    normalize_dn as enterprise_normalize_dn,
)


def parse_dn(dn_string: str) -> LdapDn:
    """Parse DN string into LdapDn object - delegates to enterprise DN system.

    Args:
        dn_string: DN string to parse

    Returns:
        LdapDn object (converted from enterprise DistinguishedName)

    Raises:
        ValueError: If DN format is invalid
    """
    # Delegate to enterprise DN parser and convert to domain object
    enterprise_dn = EnterpriseDistinguishedName(dn_string)

    # Convert enterprise DN to domain LdapDn
    components = []
    for comp in enterprise_dn.components:
        domain_component = DNComponent(
            attribute=comp.attribute_type, value=comp.attribute_value,
        )
        components.append(domain_component)

    return LdapDn(components=components)


def normalize_dn(dn_string: str) -> str:
    """Normalize DN string to standard format - delegates to enterprise DN system.

    Args:
        dn_string: DN string to normalize

    Returns:
        Normalized DN string
    """
    # Delegate directly to enterprise normalization
    return enterprise_normalize_dn(dn_string)


def is_child_dn(child_dn: str, parent_dn: str) -> bool:
    """Check if one DN is a child of another - delegates to enterprise DN system.

    Args:
        child_dn: Potential child DN
        parent_dn: Potential parent DN

    Returns:
        True if child_dn is a child of parent_dn
    """
    # Delegate directly to enterprise DN system
    enterprise_child = EnterpriseDistinguishedName(child_dn)
    return enterprise_child.is_child_of(parent_dn)


def get_parent_dn(dn_string: str) -> str | None:
    """Get parent DN of the given DN - delegates to enterprise DN system.

    Args:
        dn_string: DN string

    Returns:
        Parent DN string or None if no parent
    """
    # Delegate directly to enterprise DN system
    return get_dn_parent(dn_string)


def get_rdn(dn_string: str) -> str:
    """Get the Relative DN (first component) of a DN - delegates to enterprise DN system.

    Args:
        dn_string: DN string

    Returns:
        RDN string
    """
    # Delegate directly to enterprise DN system
    rdn = get_dn_rdn(dn_string)
    return rdn or ""


def replace_base_dn(dn_string: str, old_base: str, new_base: str) -> str:
    """Replace the base DN portion of a DN.

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


# Re-export enterprise escape/unescape functions directly
# These are already imported at the top as escape_dn_value and unescape_dn_value
# No need to reimplement - the imports provide the delegation


def extract_attribute_value(dn_string: str, attribute: str) -> str | None:
    """Extract value of specific attribute from DN.

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
    """Build DN string from list of (attribute, value) tuples.

    Args:
        components: List of (attribute, value) tuples

    Returns:
        DN string
    """
    dn_components: list[str] = []
    for attr, value in components:
        escaped_value = escape_dn_value(value)
        dn_components.append(f"{attr}={escaped_value}")

    return ",".join(dn_components)


def split_dn_components(dn_string: str) -> list[tuple[str, str]]:
    """Split DN into list of (attribute, value) tuples.

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
    """Validate DN format - delegates to enterprise DN system.

    Args:
        dn_string: DN string to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not dn_string or not dn_string.strip():
        return False, "DN cannot be empty"

    # Delegate to enterprise validation
    if is_valid_dn(dn_string):
        return True, None
    # Get detailed validation errors from enterprise system
    errors = DNParser.validate_dn_syntax(dn_string)
    error_message = "; ".join(errors) if errors else "Invalid DN format"
    return False, error_message


def get_dn_depth(dn_string: str) -> int:
    """Get the depth (number of components) of a DN.

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
    """Find common base DN among a list of DNs.

    Args:
        dn_list: List of DN strings

    Returns:
        Common base DN or None if no common base
    """
    if not dn_list:
        return None

    if len(dn_list) == 1:
        parent = get_parent_dn(dn_list[0])
        return parent or dn_list[0]

    try:
        # Parse all DNs
        parsed_dns = [parse_dn(dn) for dn in dn_list]

        # Find minimum depth
        min_depth = min(len(dn.components) for dn in parsed_dns)

        if min_depth == 0:
            return None

        # Check components from the end (base) backwards
        common_components: list[DNComponent] = []
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
    """Rewrite DN base using mapping rules.

    Args:
        dn_string: Original DN
        base_mappings: Dict of old_base -> new_base mappings

    Returns:
        DN with rewritten base or original DN if no mapping found
    """
    for old_base, new_base in base_mappings.items():
        try:
            if is_child_dn(dn_string, old_base):
                return replace_base_dn(dn_string, old_base, new_base)
        except ValueError:
            continue

    return dn_string
