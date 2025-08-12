"""FLEXT-LDAP Domain - Consolidated Domain Layer (DDD).

🎯 CONSOLIDATES ALL domain_*.py FILES INTO SINGLE PEP8 MODULE

This module provides domain-driven design patterns for FLEXT-LDAP.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class FlextLdapSpecification(ABC):
    """Base specification for LDAP domain validation."""

    @abstractmethod
    def is_satisfied_by(self, candidate: object) -> bool:
        """Check if specification is satisfied."""
        ...


class FlextLdapUserSpecification(FlextLdapSpecification):
    """Specification for LDAP user validation."""

    def is_satisfied_by(self, candidate: object) -> bool:
        """Check if candidate is valid LDAP user."""
        return hasattr(candidate, "uid") and hasattr(candidate, "dn")


class FlextLdapGroupSpecification(FlextLdapSpecification):
    """Specification for LDAP group validation."""

    def is_satisfied_by(self, candidate: object) -> bool:
        """Check if candidate is valid LDAP group."""
        return hasattr(candidate, "cn") and hasattr(candidate, "members")


class FlextLdapDistinguishedNameSpecification(FlextLdapSpecification):
    """Specification for DN validation."""

    def is_satisfied_by(self, candidate: object) -> bool:
        """Check if candidate is valid DN."""
        if not isinstance(candidate, str):
            return False
        return "=" in candidate and "," in candidate


class FlextLdapActiveUserSpecification(FlextLdapSpecification):
    """Specification for active user validation."""

    def is_satisfied_by(self, candidate: object) -> bool:
        """Check if user is active."""
        return hasattr(candidate, "is_active") and candidate.is_active()


class FlextLdapValidPasswordSpecification(FlextLdapSpecification):
    """Specification for password validation."""

    def is_satisfied_by(self, candidate: object) -> bool:
        """Check if password is valid."""
        if not isinstance(candidate, str):
            return False
        return len(candidate) >= 6


class FlextLdapEntrySpecification(FlextLdapSpecification):
    """Specification for LDAP entry validation."""

    def is_satisfied_by(self, candidate: object) -> bool:
        """Check if candidate is valid LDAP entry."""
        return hasattr(candidate, "dn") and hasattr(candidate, "object_classes")


class FlextLdapValidEntrySpecification(FlextLdapSpecification):
    """Specification for valid entry validation."""

    def is_satisfied_by(self, candidate: object) -> bool:
        """Check if entry is valid."""
        return (hasattr(candidate, "validate_domain_rules") and
                candidate.validate_domain_rules().is_success)


class FlextLdapFilterSpecification(FlextLdapSpecification):
    """Specification for LDAP filter validation."""

    def is_satisfied_by(self, candidate: object) -> bool:
        """Check if filter is valid."""
        if not isinstance(candidate, str):
            return False
        return candidate.startswith("(") and candidate.endswith(")")


class FlextLdapNonEmptyGroupSpecification(FlextLdapSpecification):
    """Specification for non-empty group validation."""

    def is_satisfied_by(self, candidate: object) -> bool:
        """Check if group is not empty."""
        return hasattr(candidate, "members") and len(candidate.members) > 0


# Export all domain classes
__all__ = [
    "FlextLdapActiveUserSpecification",
    "FlextLdapDistinguishedNameSpecification",
    "FlextLdapEntrySpecification",
    "FlextLdapFilterSpecification",
    "FlextLdapGroupSpecification",
    "FlextLdapNonEmptyGroupSpecification",
    "FlextLdapSpecification",
    "FlextLdapUserSpecification",
    "FlextLdapValidEntrySpecification",
    "FlextLdapValidPasswordSpecification",
]
