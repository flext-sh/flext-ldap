"""FLEXT-LDAP Value Objects Module.

This module provides a clean import interface for LDAP value objects,
re-exporting the ValueObjects class from models.py to maintain backward
compatibility with test imports.

Following FLEXT architectural patterns, this is a thin wrapper that
delegates to the actual implementation in models.py.
"""

from __future__ import annotations

from flext_ldap.models import FlextLdapModels

# Re-export the ValueObjects for backward compatibility
# Note: This is intentional re-export for backward compatibility

__all__ = ["FlextLdapModels"]
