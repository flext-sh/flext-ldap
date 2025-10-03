"""Domain logic and specifications for flext-ldap.

This module contains domain services, specifications, and business rules
that are independent of infrastructure concerns. Implements Clean Architecture
domain layer patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Protocol

from flext_core import FlextLogger, FlextResult
from flext_ldap.entities import FlextLdapEntities
from flext_ldap.value_objects import FlextLdapValueObjects

_logger = FlextLogger(__name__)


class FlextLdapDomain:
    """Namespace class for all LDAP domain logic and specifications.

    Contains domain services, specifications, and business rules that
    implement LDAP-specific domain logic independent of infrastructure.
    """

    class UserSpecification:
        """Specification for user-related business rules."""

        @staticmethod
        def is_valid_username(username: str) -> bool:
            """Check if username meets domain requirements."""
            if not username or len(username.strip()) < 3:
                return False

            # Check for valid characters (alphanumeric, underscore, dash)
            import re

            return bool(re.match(r"^[a-zA-Z0-9_-]+$", username))

        @staticmethod
        def is_valid_email(email: str) -> bool:
            """Check if email format is valid."""
            if not email or "@" not in email:
                return False

            # Basic email validation
            import re

            pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
            return bool(re.match(pattern, email))

        @staticmethod
        def meets_password_policy(password: str) -> FlextResult[bool]:
            """Check if password meets domain security requirements."""
            if not password:
                return FlextResult[bool].fail("Password cannot be empty")

            if len(password) < 8:
                return FlextResult[bool].fail("Password must be at least 8 characters")

            # Check for complexity
            has_upper = any(c.isupper() for c in password)
            has_lower = any(c.islower() for c in password)
            has_digit = any(c.isdigit() for c in password)

            if not (has_upper and has_lower and has_digit):
                return FlextResult[bool].fail(
                    "Password must contain uppercase, lowercase, and numeric characters"
                )

            return FlextResult[bool].ok(True)

    class GroupSpecification:
        """Specification for group-related business rules."""

        @staticmethod
        def can_add_member_to_group(
            group: FlextLdapEntities.Group, member_dn: str, max_members: int = 1000
        ) -> FlextResult[bool]:
            """Check if a member can be added to a group."""
            if not member_dn or not member_dn.strip():
                return FlextResult[bool].fail("Member DN cannot be empty")

            # Check current member count
            if group.member_count() >= max_members:
                return FlextResult[bool].fail(
                    f"Group exceeds maximum members ({max_members})"
                )

            # Check if already a member
            if group.has_member(member_dn):
                return FlextResult[bool].fail("Member is already in the group")

            return FlextResult[bool].ok(True)

        @staticmethod
        def is_valid_group_name(name: str) -> bool:
            """Check if group name is valid."""
            if not name or len(name.strip()) < 2:
                return False

            # Check for valid characters
            import re

            return bool(re.match(r"^[a-zA-Z0-9_-]+$", name))

    class SearchSpecification:
        """Specification for search-related business rules."""

        @staticmethod
        def is_safe_search_filter(filter_str: str) -> FlextResult[bool]:
            """Check if search filter is safe from LDAP injection."""
            if not filter_str:
                return FlextResult[bool].fail("Filter cannot be empty")

            # Check for potentially dangerous patterns
            dangerous_patterns = [
                r"\*[\*]*",  # Multiple consecutive asterisks
                r"[\(\)]\s*[\(\)]",  # Nested parentheses without content
            ]

            import re

            for pattern in dangerous_patterns:
                if re.search(pattern, filter_str):
                    return FlextResult[bool].fail(
                        f"Unsafe filter pattern detected: {pattern}"
                    )

            return FlextResult[bool].ok(True)

        @staticmethod
        def validate_search_scope(
            base_dn: str, scope: FlextLdapValueObjects.Scope, max_depth: int = 5
        ) -> FlextResult[bool]:
            """Validate search scope against business rules."""
            if not base_dn:
                return FlextResult[bool].fail("Base DN cannot be empty")

            # For subtree searches, check depth
            if scope.value == "subtree":
                dn_components = base_dn.count(",") + 1
                if dn_components > max_depth:
                    return FlextResult[bool].fail(
                        f"Search depth exceeds maximum ({max_depth})"
                    )

            return FlextResult[bool].ok(True)

    class DomainServices:
        """Domain services implementing business logic."""

        @staticmethod
        def calculate_user_display_name(user: FlextLdapEntities.User) -> str:
            """Calculate display name for user based on domain rules."""
            # Priority: displayName > givenName + sn > cn > uid
            if user.display_name:
                return user.display_name

            if user.given_name and user.sn:
                return f"{user.given_name} {user.sn}"

            if user.cn:
                return user.cn

            return user.uid or "Unknown User"

        @staticmethod
        def determine_user_status(user: FlextLdapEntities.User) -> str:
            """Determine user status based on LDAP attributes."""
            # Check for account lock attributes
            lock_attrs = [
                "nsAccountLock",
                "userAccountControl",
                "ds-pwp-account-disabled",
            ]

            for attr in lock_attrs:
                value = user.get_attribute(attr)
                if value:
                    if isinstance(value, str) and value.lower() in ("true", "1", "yes"):
                        return "locked"
                    if isinstance(value, int) and value & 2:  # ADS_UF_ACCOUNTDISABLE
                        return "disabled"

            # Check password expiry
            pwd_expiry = user.get_attribute("pwdChangedTime")
            if pwd_expiry:
                # Simplified check - in real implementation would compare with policy
                return "active"

            return "active"  # Default to active

        @staticmethod
        def validate_group_membership_rules(
            user: FlextLdapEntities.User, group: FlextLdapEntities.Group
        ) -> FlextResult[bool]:
            """Validate if user can be member of group based on business rules."""
            # Example business rule: users must have email for certain groups
            if group.cn and "admin" in group.cn.lower():
                if not user.mail:
                    return FlextResult[bool].fail(
                        "Admin group members must have email addresses"
                    )

            # Example business rule: users must be active
            if not user.is_active():
                return FlextResult[bool].fail(
                    "Inactive users cannot be added to groups"
                )

            return FlextResult[bool].ok(True)

        @staticmethod
        def generate_unique_username(
            base_name: str,
            existing_users: list[FlextLdapEntities.User],
            max_attempts: int = 100,
        ) -> FlextResult[str]:
            """Generate unique username based on domain rules."""
            if not base_name:
                return FlextResult[str].fail("Base name cannot be empty")

            # Normalize base name
            username = base_name.lower().replace(" ", "_")

            # Remove invalid characters
            import re

            username = re.sub(r"[^a-zA-Z0-9_-]", "", username)

            if not username:
                return FlextResult[str].fail("Base name contains no valid characters")

            # Check if base username is available
            existing_uids = {u.uid for u in existing_users if u.uid}
            if username not in existing_uids:
                return FlextResult[str].ok(username)

            # Generate unique username with number suffix
            for i in range(1, max_attempts):
                candidate = f"{username}{i}"
                if candidate not in existing_uids:
                    return FlextResult[str].ok(candidate)

            return FlextResult[str].fail(
                f"Could not generate unique username after {max_attempts} attempts"
            )

    class LdapEntrySpecification(ABC):
        """Abstract base class for LDAP entry specifications."""

        @abstractmethod
        def is_satisfied_by(self, entry: FlextLdapEntities.Entry) -> bool:
            """Check if entry satisfies this specification."""

        def and_spec(self, other: LdapEntrySpecification) -> AndSpecification:
            """Combine with another specification using AND."""
            return AndSpecification(self, other)

        def or_spec(self, other: LdapEntrySpecification) -> OrSpecification:
            """Combine with another specification using OR."""
            return OrSpecification(self, other)

        def not_spec(self) -> NotSpecification:
            """Negate this specification."""
            return NotSpecification(self)

    class UserSpecificationClass(LdapEntrySpecification):
        """Specification for user entries."""

        def __init__(self, uid: str | None = None, email: str | None = None):
            self.uid = uid
            self.email = email

        def is_satisfied_by(self, entry: FlextLdapEntities.Entry) -> bool:
            """Check if entry is a user matching criteria."""
            if not entry.has_object_class("person"):
                return False

            if self.uid:
                entry_uid = entry.get_attribute("uid")
                if entry_uid != self.uid:
                    return False

            if self.email:
                entry_email = entry.get_attribute("mail")
                if entry_email != self.email:
                    return False

            return True

    class GroupSpecificationClass("LdapEntrySpecification"):
        """Specification for group entries."""

        def __init__(self, cn: str | None = None, min_members: int = 0):
            self.cn = cn
            self.min_members = min_members

        def is_satisfied_by(self, entry: FlextLdapEntities.Entry) -> bool:
            """Check if entry is a group matching criteria."""
            if not entry.has_object_class("groupOfNames"):
                return False

            if self.cn:
                entry_cn = entry.get_attribute("cn")
                if entry_cn != self.cn:
                    return False

            # Check member count
            members = entry.get_attribute_list("member")
            if len(members) < self.min_members:
                return False

            return True

    class AndSpecification("LdapEntrySpecification"):
        """AND combination of specifications."""

        def __init__(self, left: LdapEntrySpecification, right: LdapEntrySpecification):
            self.left = left
            self.right = right

        def is_satisfied_by(self, entry: FlextLdapEntities.Entry) -> bool:
            return self.left.is_satisfied_by(entry) and self.right.is_satisfied_by(
                entry
            )

    class OrSpecification("LdapEntrySpecification"):
        """OR combination of specifications."""

        def __init__(self, left: LdapEntrySpecification, right: LdapEntrySpecification):
            self.left = left
            self.right = right

        def is_satisfied_by(self, entry: FlextLdapEntities.Entry) -> bool:
            return self.left.is_satisfied_by(entry) or self.right.is_satisfied_by(entry)

    class NotSpecification("LdapEntrySpecification"):
        """NOT specification."""

        def __init__(self, spec: LdapEntrySpecification):
            self.spec = spec

        def is_satisfied_by(self, entry: FlextLdapEntities.Entry) -> bool:
            return not self.spec.is_satisfied_by(entry)

    # Protocol definitions for domain services
    class LdapDomainServiceProtocol(Protocol):
        """Protocol for LDAP domain services."""

        def validate_user_creation(
            self, user_request: FlextLdapEntities.CreateUserRequest
        ) -> FlextResult[bool]:
            """Validate user creation request against business rules."""
            ...

        def validate_search_request(
            self, search_request: FlextLdapEntities.SearchRequest
        ) -> FlextResult[bool]:
            """Validate search request against business rules."""
            ...

        def enrich_user_data(
            self, user: FlextLdapEntities.User
        ) -> FlextResult[FlextLdapEntities.User]:
            """Enrich user data with domain-specific information."""
            ...


__all__ = [
    "FlextLdapDomain",
]
