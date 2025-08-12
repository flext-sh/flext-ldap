"""LDAP Domain Specifications - Business Rules.

🏗️ CLEAN ARCHITECTURE: Domain Specifications
Built on flext-core foundation patterns.

Specifications encapsulate business rules that can be combined and reused.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Generic, TypeVar

from flext_core import get_logger

# Type variable for specification subjects
T = TypeVar("T")

logger = get_logger(__name__)


# FBT smell elimination constants - SOLID DRY Principle
class PasswordSpecialCharsRequirement:
    """Password special characters requirement constants."""

    REQUIRED = True
    NOT_REQUIRED = False


if TYPE_CHECKING:
    from flext_ldap.entities import (
        FlextLdapEntry,
        FlextLdapGroup,
        FlextLdapUser,
    )


class FlextLdapSpecification(ABC, Generic[T]):  # noqa: UP046
    """Base specification pattern for domain objects."""

    @abstractmethod
    def is_satisfied_by(self, candidate: T) -> bool:
        """Check if candidate satisfies the specification."""


class FlextLdapEntrySpecification(FlextLdapSpecification["FlextLdapEntry"]):
    """Base specification for LDAP entries."""

    def is_satisfied_by(self, entry: FlextLdapEntry) -> bool:
        """Check if entry satisfies the specification.

        Args:
            entry: LDAP entry to check

        Returns:
            True if entry satisfies specification

        """
        return bool(entry.dn and entry.attributes)


class FlextLdapValidEntrySpecification(FlextLdapEntrySpecification):
    """Specification for valid LDAP entries."""

    def is_satisfied_by(self, entry: FlextLdapEntry) -> bool:
        """Check if entry is valid.

        Args:
            entry: LDAP entry to validate

        Returns:
            True if entry is valid

        """
        if not super().is_satisfied_by(entry):
            return False

        # Must have at least one object class
        object_classes = entry.attributes.get("objectClass", [])
        if not object_classes:
            return False

        # DN must be properly formatted
        return bool(entry.dn and "=" in str(entry.dn))


class FlextLdapUserSpecification(FlextLdapSpecification["FlextLdapUser"]):
    """Base specification for LDAP users."""

    def is_satisfied_by(self, user: FlextLdapUser) -> bool:
        """Check if user satisfies the specification.

        Args:
            user: LDAP user to check

        Returns:
            True if user satisfies specification

        """
        return bool(user.dn and user.uid)


class FlextLdapActiveUserSpecification(FlextLdapUserSpecification):
    """Specification for active LDAP users."""

    def is_satisfied_by(self, user: FlextLdapUser) -> bool:
        """Check if user is active.

        Args:
            user: LDAP user to check

        Returns:
            True if user is active

        """
        if not super().is_satisfied_by(user):
            return False

        # Check if account is disabled
        user_account_control: list[str] | str = user.attributes.get(
            "userAccountControl",
            [],
        )
        if isinstance(user_account_control, str):
            user_account_control = [user_account_control]
        if user_account_control:
            # Bit 2 (0x02) indicates disabled account in AD
            try:
                control_value = int(user_account_control[0])
                if control_value & 0x02:
                    return False
            except (ValueError, IndexError) as e:
                # EXPLICIT TRANSPARENCY: Active Directory userAccountControl parsing fallback
                logger.warning(
                    f"Failed to parse userAccountControl: {type(e).__name__}: {e}",
                )
                logger.debug(f"userAccountControl value: {user_account_control}")
                logger.info(
                    "Continuing with fallback behavior - checking accountDisabled attribute",
                )
                # Continue with fallback behavior - check accountDisabled attribute instead

        # Check for explicit disabled flag
        account_disabled: list[str] | str = user.attributes.get("accountDisabled", [])
        if isinstance(account_disabled, str):
            account_disabled = [account_disabled]
        return not (account_disabled and account_disabled[0].lower() == "true")


class FlextLdapValidPasswordSpecification(FlextLdapSpecification[str]):
    """Specification for valid passwords."""

    def __init__(
        self,
        min_length: int = 8,
        *,
        require_special_chars: bool = PasswordSpecialCharsRequirement.REQUIRED,
    ) -> None:
        """Initialize password specification.

        Args:
            min_length: Minimum password length
            require_special_chars: Whether to require special characters

        """
        self.min_length = min_length
        self.require_special_chars = require_special_chars

    def is_satisfied_by(self, password: str) -> bool:
        """Check if password meets requirements.

        Args:
            password: Password to validate

        Returns:
            True if password is valid

        """
        if len(password) < self.min_length:
            return False

        if self.require_special_chars:
            special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
            if not any(char in special_chars for char in password):
                return False

        return True


class FlextLdapGroupSpecification(FlextLdapSpecification["FlextLdapGroup"]):
    """Base specification for LDAP groups."""

    def is_satisfied_by(self, group: FlextLdapGroup) -> bool:
        """Check if group satisfies the specification.

        Args:
            group: LDAP group to check

        Returns:
            True if group satisfies specification

        """
        return bool(group.dn and group.cn)


class FlextLdapNonEmptyGroupSpecification(FlextLdapGroupSpecification):
    """Specification for non-empty groups."""

    def is_satisfied_by(self, group: FlextLdapGroup) -> bool:
        """Check if group has members.

        Args:
            group: LDAP group to check

        Returns:
            True if group has members

        """
        if not super().is_satisfied_by(group):
            return False

        members = group.members
        return len(members) > 0


class FlextLdapDistinguishedNameSpecification(FlextLdapSpecification[str]):
    """Specification for valid distinguished names."""

    def is_satisfied_by(self, dn: str) -> bool:
        """Check if DN is valid.

        Args:
            dn: Distinguished name to validate

        Returns:
            True if DN is valid

        """
        if not dn or not isinstance(dn, str):
            return False

        # Basic DN validation - must contain = and proper structure
        if "=" not in dn:
            return False

        # Split by commas and validate each component
        components = dn.split(",")
        for raw_component in components:
            component = raw_component.strip()
            if "=" not in component:
                return False

            attr_name, attr_value = component.split("=", 1)
            if not attr_name.strip() or not attr_value.strip():
                return False

        return True


class FlextLdapFilterSpecification(FlextLdapSpecification[str]):
    """Specification for valid LDAP filters."""

    def is_satisfied_by(self, ldap_filter: str) -> bool:
        """Check if LDAP filter is valid.

        Args:
            ldap_filter: LDAP filter to validate

        Returns:
            True if filter is valid

        """
        if not ldap_filter or not isinstance(ldap_filter, str):
            return False

        # Basic filter validation - must be wrapped in parentheses
        if not (ldap_filter.startswith("(") and ldap_filter.endswith(")")):
            return False

        # Check for balanced parentheses
        open_count = ldap_filter.count("(")
        close_count = ldap_filter.count(")")

        return open_count == close_count
