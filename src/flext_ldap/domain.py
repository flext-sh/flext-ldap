"""Domain logic and specifications for flext-ldap.

This module contains domain services, specifications, and business rules
that are independent of infrastructure concerns. Implements Clean Architecture
domain layer patterns with simplified approach focusing on core functionality.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import re

from flext_core import FlextCore

from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels
from flext_ldap.validations import FlextLdapValidations

logger = FlextCore.Logger(__name__)


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
            min_length = FlextLdapConstants.Defaults.MIN_USERNAME_LENGTH
            if not username or len(username.strip()) < min_length:
                return False

            # Check for valid characters (alphanumeric, underscore, dash)

            return bool(re.match(r"^[a-zA-Z0-9_-]+$", username))

        @staticmethod
        def meets_password_policy(password: str) -> FlextCore.Result[bool]:
            """Check if password meets domain security requirements - delegates basic validation."""
            # First check basic password validation (length) via FlextLdapValidations
            basic_validation = FlextLdapValidations.validate_password(password)
            if basic_validation.is_failure:
                return basic_validation  # Return the validation error

            # Domain-specific complexity requirements (beyond basic validation)
            has_upper = any(c.isupper() for c in password)
            has_lower = any(c.islower() for c in password)
            has_digit = any(c.isdigit() for c in password)

            if not (has_upper and has_lower and has_digit):
                return FlextCore.Result[bool].fail(
                    "Password must contain uppercase, lowercase, and numeric characters",
                )

            return FlextCore.Result[bool].ok(True)

        @staticmethod
        def is_valid_email(email: str) -> bool:
            """Check if email address meets domain requirements."""
            if not email or "@" not in email:
                return False

            # Basic email pattern validation
            email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
            return bool(re.match(email_pattern, email))

    class GroupSpecification:
        """Specification for group-related business rules."""

        @staticmethod
        def can_add_member_to_group(
            group: FlextLdapModels.Group,
            member_dn: str,
            max_members: int = 1000,
        ) -> FlextCore.Result[bool]:
            """Check if a member can be added to a group."""
            if not member_dn or not member_dn.strip():
                return FlextCore.Result[bool].fail("Member DN cannot be empty")

            # Check current member count
            member_count = len(group.member_dns) + len(group.unique_member_dns)
            if member_count >= max_members:
                return FlextCore.Result[bool].fail(
                    f"Group exceeds maximum members ({max_members})",
                )

            # Check if already a member
            if group.has_member(member_dn):
                return FlextCore.Result[bool].fail("Member is already in the group")

            return FlextCore.Result[bool].ok(True)

        @staticmethod
        def is_valid_group_name(name: str) -> bool:
            """Check if group name is valid."""
            if (
                not name
                or len(name.strip()) < FlextLdapConstants.Defaults.MIN_GROUP_NAME_LENGTH
            ):
                return False

            # Check for valid characters

            return bool(re.match(r"^[a-zA-Z0-9_-]+$", name))

    class SearchSpecification:
        """Specification for search-related business rules."""

        @staticmethod
        def is_safe_search_filter(filter_str: str) -> FlextCore.Result[bool]:
            """Check if search filter is safe from LDAP injection."""
            if not filter_str:
                return FlextCore.Result[bool].fail("Filter cannot be empty")

            # Check for potentially dangerous patterns
            dangerous_patterns = [
                r"\*[\*]*",  # Multiple consecutive asterisks
                r"[\(\)]\s*[\(\)]",  # Nested parentheses without content
            ]

            for pattern in dangerous_patterns:
                if re.search(pattern, filter_str):
                    return FlextCore.Result[bool].fail(
                        f"Unsafe filter pattern detected: {pattern}",
                    )

            return FlextCore.Result[bool].ok(True)

        @staticmethod
        def validate_search_scope(
            base_dn: str,
            scope: FlextLdapModels.Scope,
            max_depth: int = 5,
        ) -> FlextCore.Result[bool]:
            """Validate search scope against business rules."""
            if not base_dn:
                return FlextCore.Result[bool].fail("Base DN cannot be empty")

            # For subtree searches, check depth
            if scope.value == "subtree":
                dn_components = base_dn.count(",") + 1
                if dn_components > max_depth:
                    return FlextCore.Result[bool].fail(
                        f"Search depth exceeds maximum ({max_depth})",
                    )

            return FlextCore.Result[bool].ok(True)

    class DomainServices:
        """Domain services implementing business logic."""

        @staticmethod
        def calculate_user_display_name(user: FlextLdapModels.LdapUser) -> str:
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
        def determine_user_status(user: FlextLdapModels.LdapUser) -> str:
            """Determine user status based on LDAP attributes."""
            # Check for account lock attributes
            lock_attrs = [
                "nsAccountLock",
                "userAccountControl",
                "ds-pwp-account-disabled",
            ]

            for attr in lock_attrs:
                value = user.additional_attributes.get(attr)
                if value:
                    if isinstance(value, str) and value.lower() in {"true", "1", "yes"}:
                        return "locked"
                    if isinstance(value, int) and value & 2:  # ADS_UF_ACCOUNTDISABLE
                        return "disabled"

            # Check password expiry
            pwd_expiry = user.additional_attributes.get("pwdChangedTime")
            if pwd_expiry:
                # Simplified check - in real implementation would compare with policy
                return "active"

            return "active"  # Default to active

        @staticmethod
        def validate_group_membership_rules(
            user: FlextLdapModels.LdapUser,
            group: FlextLdapModels.Group,
        ) -> FlextCore.Result[bool]:
            """Validate if user can be member of group based on business rules."""
            # Example business rule: users must have email for certain groups
            if group.cn and "REDACTED_LDAP_BIND_PASSWORD" in group.cn.lower() and not user.mail:
                return FlextCore.Result[bool].fail(
                    "Admin group members must have email addresses",
                )

            # Example business rule: users must be active
            if not user.is_active:
                return FlextCore.Result[bool].fail(
                    "Inactive users cannot be added to groups",
                )

            return FlextCore.Result[bool].ok(True)

        @staticmethod
        def generate_unique_username(
            base_name: str,
            existing_users: list[FlextLdapModels.LdapUser],
            max_attempts: int = 100,
        ) -> FlextCore.Result[str]:
            """Generate unique username based on domain rules."""
            if not base_name:
                return FlextCore.Result[str].fail("Base name cannot be empty")

            # Normalize base name
            username = base_name.lower().replace(" ", "_")

            # Remove invalid characters

            username = re.sub(r"[^a-zA-Z0-9_-]", "", username)

            if not username:
                return FlextCore.Result[str].fail(
                    "Base name contains no valid characters"
                )

            # Check if base username is available
            existing_uids = {u.uid for u in existing_users if u.uid}
            if username not in existing_uids:
                return FlextCore.Result[str].ok(username)

            # Generate unique username with number suffix
            for i in range(1, max_attempts):
                candidate = f"{username}{i}"
                if candidate not in existing_uids:
                    return FlextCore.Result[str].ok(candidate)

            return FlextCore.Result[str].fail(
                f"Could not generate unique username after {max_attempts} attempts",
            )


__all__ = [
    "FlextLdapDomain",
]
