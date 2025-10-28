"""Domain services implementing LDAP business logic.

Provides domain-specific business operations including user and group
management, membership validation, and username generation based on
domain-driven design principles.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re

from flext_core import FlextResult

from flext_ldap.models import FlextLdapModels


class DomainServices:
    """Domain services implementing business logic.

    Provides reusable domain business logic for LDAP operations including
    user management, group operations, and identity validation according
    to domain requirements.
    """

    @staticmethod
    def calculate_user_display_name(user: FlextLdapModels.Entry) -> str:
        """Calculate display name for user based on domain rules.

        Priority: displayName > givenName + sn > cn > uid

        Args:
            user: LDAP user entry

        Returns:
            Formatted display name for user

        """
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
        """Determine user status based on LDAP attributes.

        Checks for account lock indicators, disabled accounts, and other
        status-related attributes to determine overall user status.

        Args:
            user: LDAP user entry

        Returns:
            User status string ("active", "locked", "disabled")

        """
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
        """Validate if user can be member of group based on business rules.

        Checks domain-specific business rules for group membership including
        email requirements and user activity status.

        Args:
            user: LDAP user entry
            group: LDAP group entry

        Returns:
            FlextResult indicating if membership is valid

        """
        # Example business rule: users must have email for certain groups
        if group.cn and "REDACTED_LDAP_BIND_PASSWORD" in group.cn.lower() and not user.mail:
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
        """Generate unique username based on domain rules.

        Creates a unique username from a base name by normalizing and
        checking against existing users, appending numbers if needed.

        Args:
            base_name: Base name to derive username from
            existing_users: List of existing LDAP user entries
            max_attempts: Maximum attempts to generate unique name (default: 100)

        Returns:
            FlextResult with generated unique username or error

        """
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
