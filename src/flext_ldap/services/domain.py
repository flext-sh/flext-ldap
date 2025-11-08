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
from flext_ldif import FlextLdifModels
from flext_ldif.services import FlextLdifValidation

from flext_ldap.constants import FlextLdapConstants


class DomainServices:
    """Domain services implementing business logic.

    Provides reusable domain business logic for LDAP operations including
    user management, group operations, and identity validation according
    to domain requirements.

    Uses FlextLdifValidation for attribute validation to eliminate duplication.
    """

    _validation_service = FlextLdifValidation()

    @staticmethod
    def calculate_user_display_name(user: FlextLdifModels.Entry) -> str:
        """Calculate display name for user based on domain rules.

        Priority: displayName > givenName + sn > cn > uid

        Args:
            user: LDAP user entry

        Returns:
            Formatted display name for user

        """
        # Priority: displayName > givenName + sn > cn > uid
        display_name = user.attributes.get("displayName") if user.attributes else None
        if display_name:
            return (
                str(display_name[0])
                if isinstance(display_name, list)
                else str(display_name)
            )

        given_name = user.attributes.get("givenName") if user.attributes else None
        sn = user.attributes.get("sn") if user.attributes else None
        if given_name and sn:
            given_str = (
                str(given_name[0]) if isinstance(given_name, list) else str(given_name)
            )
            sn_str = str(sn[0]) if isinstance(sn, list) else str(sn)
            return f"{given_str} {sn_str}"

        cn = user.attributes.get("cn") if user.attributes else None
        if cn:
            return str(cn[0]) if isinstance(cn, list) else str(cn)

        uid = user.attributes.get("uid") if user.attributes else None
        return (
            str(uid[0])
            if uid and isinstance(uid, list)
            else (str(uid) if uid else FlextLdapConstants.ErrorStrings.UNKNOWN_USER)
        )

    @staticmethod
    def determine_user_status(user: FlextLdifModels.Entry) -> str:
        """Determine user status based on LDAP attributes.

        Checks for account lock indicators, disabled accounts, and other
        status-related attributes to determine overall user status.

        Args:
            user: LDAP user entry

        Returns:
            User status string ("active", "locked", "disabled")

        """
        # Check for account lock attributes
        lock_attrs = FlextLdapConstants.LockAttributes.ALL_LOCK_ATTRIBUTES

        for attr in lock_attrs:
            value = user.attributes.get(attr) if user.attributes else None
            if value:
                value_str = str(value[0]) if isinstance(value, list) else str(value)
                if value_str.lower() in {
                    FlextLdapConstants.BooleanStrings.TRUE,
                    FlextLdapConstants.BooleanStrings.ONE,
                    FlextLdapConstants.BooleanStrings.YES,
                }:
                    return FlextLdapConstants.UserStatus.LOCKED
                try:
                    if (
                        isinstance(value, (int, str))
                        and int(value)
                        & FlextLdapConstants.ActiveDirectoryFlags.ADS_UF_ACCOUNTDISABLE
                    ):
                        return FlextLdapConstants.UserStatus.DISABLED
                except (ValueError, TypeError):
                    pass

        # Check password expiry
        pwd_expiry = (
            user.attributes.get(
                FlextLdapConstants.ActiveDirectoryAttributes.PWD_LAST_SET,
            )
            if user.attributes
            else None
        )
        if pwd_expiry:
            # Simplified check - in real implementation would compare with policy
            return FlextLdapConstants.UserStatus.ACTIVE

        return FlextLdapConstants.UserStatus.ACTIVE  # Default to active

    @staticmethod
    def validate_group_membership_rules(
        user: FlextLdifModels.Entry,
        group: FlextLdifModels.Entry,
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
        group_cn = group.attributes.get("cn") if group.attributes else None
        user_mail = user.attributes.get("mail") if user.attributes else None

        if group_cn:
            group_cn_str = (
                str(group_cn[0]) if isinstance(group_cn, list) else str(group_cn)
            )
            if "REDACTED_LDAP_BIND_PASSWORD" in group_cn_str.lower() and not user_mail:
                return FlextResult[bool].fail(
                    "Admin group members must have email addresses",
                )

        # Example business rule: check for active status (entries without lock attributes are active)
        lock_attrs = FlextLdapConstants.LockAttributes.ALL_LOCK_ATTRIBUTES
        is_locked = False
        for attr in lock_attrs:
            value = user.attributes.get(attr) if user.attributes else None
            if value:
                is_locked = True
                break

        if is_locked:
            return FlextResult[bool].fail(
                "Inactive users cannot be added to groups",
            )

        return FlextResult[bool].ok(True)

    @staticmethod
    def generate_unique_username(
        base_name: str,
        existing_users: list[FlextLdifModels.Entry],
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

        # Remove invalid characters (using LDAP attribute name validation rules)
        username = re.sub(
            FlextLdapConstants.RegexPatterns.USERNAME_SANITIZE_PATTERN,
            "",
            username,
        )

        if not username:
            return FlextResult[str].fail("Base name contains no valid characters")

        # Validate username format using FlextLdifValidation (RFC 4512 compliant)
        validation_result = DomainServices._validation_service.validate_attribute_name(
            username,
        )
        if validation_result.is_failure or not validation_result.unwrap():
            return FlextResult[str].fail(
                f"Generated username '{username}' does not meet LDAP attribute name requirements",
            )

        # Check if base username is available
        existing_uids = set()
        for user in existing_users:
            uid_values = user.attributes.get("uid") if user.attributes else None
            if uid_values:
                uid_str = (
                    str(uid_values[0])
                    if isinstance(uid_values, list)
                    else str(uid_values)
                )
                existing_uids.add(uid_str)

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
