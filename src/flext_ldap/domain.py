"""Domain logic and specifications for flext-ldap.

Domain services, specifications, and business rules independent of
infrastructure concerns. Clean Architecture domain layer with focus
on core functionality and business validation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re

from flext_core import FlextResult

from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels


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
        def meets_password_policy(password: str) -> FlextResult[bool]:
            """Check if password meets domain security requirements."""
            # First check basic password validation (length) via FlextLdapModels.Validations
            basic_validation = FlextLdapModels.Validations.validate_password(password)
            if basic_validation.is_failure:
                return basic_validation  # Return the validation error

            # Domain-specific complexity requirements (beyond basic validation)
            has_upper = any(c.isupper() for c in password)
            has_lower = any(c.islower() for c in password)
            has_digit = any(c.isdigit() for c in password)

            if not (has_upper and has_lower and has_digit):
                msg = "Password must contain uppercase, lowercase, and digits"
                return FlextResult[bool].fail(msg)

            return FlextResult[bool].ok(True)

    class GroupSpecification:
        """Specification for group-related business rules."""

        @staticmethod
        def can_add_member_to_group(
            group: FlextLdapModels.Entry,
            member_dn: str,
            max_members: int = 1000,
        ) -> FlextResult[bool]:
            """Check if a member can be added to a group."""
            if not member_dn or not member_dn.strip():
                return FlextResult[bool].fail("Member DN cannot be empty")

            # Check current member count
            member_count = len(group.member_dns) + len(group.unique_member_dns)
            if member_count >= max_members:
                return FlextResult[bool].fail(
                    f"Group exceeds maximum members ({max_members})",
                )

            # Check if already a member
            if group.has_member(member_dn):
                return FlextResult[bool].fail("Member is already in the group")

            return FlextResult[bool].ok(True)

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
        def is_safe_search_filter(filter_str: str) -> FlextResult[bool]:
            """Check if search filter is safe from LDAP injection."""
            if not filter_str:
                return FlextResult[bool].fail("Filter cannot be empty")

            # Check for potentially dangerous patterns
            dangerous_patterns = [
                r"\*[\*]+",  # Multiple consecutive asterisks (**, ***, etc.)
                r"\(\s*\)",  # Empty parentheses: ()
                r"\(\s*\*+\s*\)",  # Parentheses with only asterisks: (*), (**), etc.
            ]

            for pattern in dangerous_patterns:
                if re.search(pattern, filter_str):
                    return FlextResult[bool].fail(
                        f"Unsafe filter pattern detected: {pattern}",
                    )

            return FlextResult[bool].ok(True)

        @staticmethod
        def validate_search_scope(
            base_dn: str,
            scope: FlextLdapModels.Scope,
            max_depth: int = 5,
        ) -> FlextResult[bool]:
            """Validate search scope against business rules."""
            if not base_dn:
                return FlextResult[bool].fail("Base DN cannot be empty")

            # For subtree searches, check depth
            if scope.value == "subtree":
                dn_components = base_dn.count(",") + 1
                if dn_components > max_depth:
                    return FlextResult[bool].fail(
                        f"Search depth exceeds maximum ({max_depth})",
                    )

            return FlextResult[bool].ok(True)

    class DomainServices:
        """Domain services implementing business logic."""

        @staticmethod
        def calculate_user_display_name(user: FlextLdapModels.Entry) -> str:
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
        def determine_user_status(user: FlextLdapModels.Entry) -> str:
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
            user: FlextLdapModels.Entry,
            group: FlextLdapModels.Entry,
        ) -> FlextResult[bool]:
            """Validate if user can be member of group based on business rules."""
            # Example business rule: users must have email for certain groups
            if group.cn and "admin" in group.cn.lower() and not user.mail:
                return FlextResult[bool].fail(
                    "Admin group members must have email addresses",
                )

            # Example business rule: users must be active
            if not user.is_active():
                return FlextResult[bool].fail(
                    "Inactive users cannot be added to groups",
                )

            return FlextResult[bool].ok(True)

        @staticmethod
        def generate_unique_username(
            base_name: str,
            existing_users: list[FlextLdapModels.Entry],
            max_attempts: int = 100,
        ) -> FlextResult[str]:
            """Generate unique username based on domain rules."""
            if not base_name:
                return FlextResult[str].fail("Base name cannot be empty")

            # Normalize base name
            username = base_name.lower().replace(" ", "_")

            # Remove invalid characters

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
                f"Could not generate unique username after {max_attempts} attempts",
            )


__all__ = [
    "FlextLdapDomain",
]
