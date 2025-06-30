"""Simple DN utilities - Enterprise Delegation Facade.

TRUE FACADE PATTERN: 100% DELEGATION TO ENTERPRISE DN INFRASTRUCTURE
====================================================================

This module provides simple DN utilities by delegating entirely to the
enterprise-grade DN utilities in utilities.dn.

DELEGATION TARGET: utilities.dn.DistinguishedName - Enterprise DN processing
with RFC 4514 compliance, comprehensive validation, advanced manipulation.

MIGRATION BENEFITS:
- Eliminated simple DN implementation duplication
- Leverages enterprise validation and RFC compliance
- Automatic improvements from enterprise DN system
- Consistent behavior with simplified interface
"""

# Delegate to enterprise DN infrastructure
from flext_ldapn import (
    normalize_dn as enterprise_normalize_dn,
)

from flext_ldap.utilities.dn import (
    DistinguishedName as EnterpriseDistinguishedName,
)


def simple_parse_dn(dn_string: str) -> list[tuple[str, str]]:
    """Simple DN parser that returns list of (attribute, value) tuples - delegates to enterprise DN.

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

    # Delegate to enterprise DN parsing
    enterprise_dn = EnterpriseDistinguishedName(dn_string)

    # Convert to simple tuple format with lowercase attributes for backward compatibility
    return [
        (comp.attribute_type.lower(), comp.attribute_value) for comp in enterprise_dn.components
    ]


def simple_normalize_dn(dn_string: str) -> str:
    """Simple DN normalization - delegates to enterprise DN system.

    Args:
        dn_string: DN string to normalize

    Returns:
        Normalized DN string
    """
    # Delegate directly to enterprise normalization
    return enterprise_normalize_dn(dn_string)


def simple_is_child_dn(child_dn: str, parent_dn: str) -> bool:
    """Check if one DN is a child of another (simple version) - delegates to enterprise DN.

    Args:
        child_dn: Potential child DN
        parent_dn: Potential parent DN

    Returns:
        True if child_dn is a child of parent_dn
    """
    try:
        # Delegate to enterprise DN system
        enterprise_child = EnterpriseDistinguishedName(child_dn)
        return enterprise_child.is_child_of(parent_dn)
    except Exception:
        return False
