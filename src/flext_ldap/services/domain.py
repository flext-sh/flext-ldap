"""Domain services implementing LDAP business logic.

Provides domain-specific business operations including user and group
management, membership validation, and username generation based on
domain-driven design principles.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re

from flext_core import FlextResult, FlextRuntime
from flext_ldif import FlextLdifModels

# FlextLdifUtilities.Validation doesn't exist yet - needs to be added to utilities.py
# Importing directly from service (internal use only - will be refactored to public API)
from flext_ldif.services.validation import FlextLdifValidation

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
    def _get_entry_attribute(
        entry: FlextLdifModels.Entry, attr_name: str
    ) -> object | None:
        """Safely get attribute value from LDAP entry using functional approach.

        DRY helper method for safe attribute access with proper type checking.
        Handles FlextLdifModels.LdifAttributes structure correctly.

        Args:
            entry: LDAP entry to extract attribute from
            attr_name: Name of the attribute to retrieve

        Returns:
            Attribute value or None if not found

        """
        if not entry.attributes or not hasattr(entry.attributes, "attributes"):
            return None
        attr_dict = entry.attributes.attributes
        if not isinstance(attr_dict, dict):
            return None
        return attr_dict.get(attr_name)

    @staticmethod
    def _normalize_attribute_value(attr_value: object | None) -> str | None:
        """Normalize LDAP attribute value to string using functional approach.

        DRY helper for converting LDAP attribute values (which can be lists or single values)
        to normalized string format. Handles list unpacking and type conversion.

        Args:
            attr_value: Raw LDAP attribute value (list or single value)

        Returns:
            Normalized string value or None if invalid/empty

        """
        if attr_value is None:
            return None

        # Handle list values (most common LDAP format)
        if FlextRuntime.is_list_like(attr_value) and len(attr_value) > 0:
            return str(attr_value[0])

        # Handle single values
        try:
            str_value = str(attr_value).strip()
            return str_value or None
        except (TypeError, AttributeError):
            return None

    @staticmethod
    def _get_normalized_attribute(
        entry: FlextLdifModels.Entry, attr_name: str
    ) -> str | None:
        """Get and normalize LDAP attribute value using functional composition.

        Combines safe attribute access with value normalization for clean,
        consistent attribute retrieval across all domain operations.

        Args:
            entry: LDAP entry to extract attribute from
            attr_name: Name of the attribute to retrieve and normalize

        Returns:
            Normalized string value or None if not found/invalid

        """
        raw_value = DomainServices._get_entry_attribute(entry, attr_name)
        return DomainServices._normalize_attribute_value(raw_value)

    def _build_display_name_from_parts(
        self,
        given_name: str | None,
        sn: str | None,
    ) -> str | None:
        """Build display name from given name and surname parts using builder pattern.

        DRY helper for constructing full names from individual components.
        Handles None values gracefully with proper spacing.

        Args:
            given_name: User's given/first name
            sn: User's surname/last name

        Returns:
            Formatted full name or None if insufficient parts

        """
        if given_name and sn:
            return f"{given_name} {sn}"
        return None

    def _get_display_name_priority_list(
        self, user: FlextLdifModels.Entry
    ) -> list[str | None]:
        """Get prioritized list of display name candidates using functional approach.

        Builder pattern helper that creates ordered list of display name options
        based on domain priority rules. Eliminates complex nested conditions.

        Args:
            user: LDAP user entry

        Returns:
            Ordered list of display name candidates (first non-None wins)

        """
        return [
            # Priority 1: displayName attribute
            self._get_normalized_attribute(user, "displayName"),
            # Priority 2: givenName + sn combination
            self._build_display_name_from_parts(
                self._get_normalized_attribute(user, "givenName"),
                self._get_normalized_attribute(user, "sn"),
            ),
            # Priority 3: cn (common name)
            self._get_normalized_attribute(user, "cn"),
            # Priority 4: uid (user ID) - fallback
            self._get_normalized_attribute(user, "uid"),
        ]

    @staticmethod
    def calculate_user_display_name(user: FlextLdifModels.Entry) -> str:
        """Calculate display name for user based on domain rules using builder pattern.

        Uses prioritized attribute lookup with functional composition.
        Eliminates complex nested conditions through helper methods.

        Priority: displayName > givenName + sn > cn > uid

        Args:
            user: LDAP user entry

        Returns:
            Formatted display name for user or UNKNOWN_USER fallback

        """
        # Create priority-ordered list of display name candidates
        display_options = DomainServices()._get_display_name_priority_list(user)  # noqa: SLF001

        # Return first valid option or fallback
        for option in display_options:
            if option:
                return option

        return FlextLdapConstants.ErrorStrings.UNKNOWN_USER

    def _check_lock_attributes(self, user: FlextLdifModels.Entry) -> str | None:
        """Check user lock attributes using functional approach.

        DRY helper for checking all lock-related attributes.
        Returns status if user is locked/disabled, None if active.

        Args:
            user: LDAP user entry to check

        Returns:
            Status string if locked/disabled, None if active

        """
        lock_attrs = FlextLdapConstants.LockAttributes.ALL_LOCK_ATTRIBUTES

        for attr in lock_attrs:
            attr_value = self._get_entry_attribute(user, attr)
            if attr_value is None:
                continue

            normalized_value = self._normalize_attribute_value(attr_value)
            if not normalized_value:
                continue

            # Check boolean string values
            if normalized_value.lower() in {
                FlextLdapConstants.BooleanStrings.TRUE.lower(),
                FlextLdapConstants.BooleanStrings.ONE,
                FlextLdapConstants.BooleanStrings.YES.lower(),
            }:
                return FlextLdapConstants.UserStatus.LOCKED

            # Check Active Directory flags (bitwise)
            try:
                if (
                    int(normalized_value)
                    & FlextLdapConstants.ActiveDirectoryFlags.ADS_UF_ACCOUNTDISABLE
                ):
                    return FlextLdapConstants.UserStatus.DISABLED
            except (ValueError, TypeError):
                continue

        return None

    def _check_password_expiry(self, user: FlextLdifModels.Entry) -> bool:
        """Check if user password is expired using domain logic.

        Helper for password expiry validation. In real implementation,
        this would compare against domain password policy.

        Args:
            user: LDAP user entry to check

        Returns:
            True if password is considered expired (simplified check)

        """
        pwd_last_set = self._get_entry_attribute(
            user, FlextLdapConstants.ActiveDirectoryAttributes.PWD_LAST_SET
        )
        # Simplified check - real implementation would validate against policy
        return pwd_last_set is not None

    @staticmethod
    def determine_user_status(user: FlextLdifModels.Entry) -> str:
        """Determine user status based on LDAP attributes using builder pattern.

        Uses helper methods to check lock attributes and password expiry.
        Eliminates complex nested conditions through functional composition.

        Args:
            user: LDAP user entry

        Returns:
            User status string ("active", "locked", "disabled")

        """
        domain_service = DomainServices()

        # Check lock attributes first (highest priority)
        lock_status = domain_service._check_lock_attributes(user)
        if lock_status:
            return lock_status

        # Check password expiry (indicates active account)
        if domain_service._check_password_expiry(user):
            return FlextLdapConstants.UserStatus.ACTIVE

        # Default to active if no lock indicators found
        return FlextLdapConstants.UserStatus.ACTIVE

    def _check_group_email_requirement(
        self,
        user: FlextLdifModels.Entry,
        group: FlextLdifModels.Entry,
    ) -> str | None:
        """Check if group requires email membership using domain rules.

        Business rule helper: admin groups require email addresses.
        Returns error message if requirement not met, None if valid.

        Args:
            user: LDAP user entry
            group: LDAP group entry

        Returns:
            Error message if requirement not met, None if valid

        """
        group_cn = self._get_normalized_attribute(group, "cn")
        user_email = self._get_normalized_attribute(user, "mail")

        if group_cn and "admin" in group_cn.lower() and not user_email:
            return "Admin group members must have email addresses"

        return None

    def _check_user_active_status(self, user: FlextLdifModels.Entry) -> bool:
        """Check if user is active (not locked) using domain logic.

        Helper for user status validation in group membership.
        Uses lock attribute checking for activity determination.

        Args:
            user: LDAP user entry

        Returns:
            True if user is active, False if locked

        """
        lock_status = self._check_lock_attributes(user)
        return lock_status is None  # None means no locks found (active)

    @staticmethod
    def validate_group_membership_rules(
        user: FlextLdifModels.Entry,
        group: FlextLdifModels.Entry,
    ) -> FlextResult[bool]:
        """Validate if user can be member of group based on business rules.

        Uses builder pattern with helper methods for clean validation logic.
        Checks email requirements and user activity status.

        Args:
            user: LDAP user entry
            group: LDAP group entry

        Returns:
            FlextResult indicating if membership is valid

        """
        domain_service = DomainServices()

        # Check email requirement for admin groups
        email_error = domain_service._check_group_email_requirement(user, group)
        if email_error:
            return FlextResult[bool].fail(email_error)

        # Check user active status
        if not domain_service._check_user_active_status(user):
            return FlextResult[bool].fail("Inactive users cannot be added to groups")

        return FlextResult[bool].ok(True)

    def _normalize_username_base(self, base_name: str) -> FlextResult[str]:
        """Normalize username base using domain rules and validation.

        DRY helper for username normalization with comprehensive validation.
        Applies domain rules for username sanitization and LDAP compliance.

        Args:
            base_name: Raw base name to normalize

        Returns:
            FlextResult with normalized username or validation error

        """
        if not base_name:
            return FlextResult[str].fail("Base name cannot be empty")

        # Apply domain normalization rules
        username = base_name.lower().replace(" ", "_")

        # Remove invalid characters using LDAP patterns
        username = re.sub(
            FlextLdapConstants.RegexPatterns.USERNAME_SANITIZE_PATTERN,
            "",
            username,
        )

        if not username:
            return FlextResult[str].fail("Base name contains no valid characters")

        # Validate against LDAP attribute name requirements
        validation_result = self._validation_service.validate_attribute_name(username)
        if validation_result.is_failure or not validation_result.unwrap():
            return FlextResult[str].fail(
                f"Generated username '{username}' does not meet LDAP attribute name requirements"
            )

        return FlextResult[str].ok(username)

    def _collect_existing_uids(
        self, existing_users: list[FlextLdifModels.Entry]
    ) -> set[str]:
        """Collect existing UIDs from user entries using functional approach.

        DRY helper for gathering existing usernames with proper normalization.
        Handles different UID attribute formats consistently.

        Args:
            existing_users: List of existing LDAP user entries

        Returns:
            Set of normalized existing UIDs

        """
        existing_uids = set()
        for user in existing_users:
            uid_value = self._get_normalized_attribute(user, "uid")
            if uid_value:
                existing_uids.add(uid_value)
        return existing_uids

    def _generate_username_with_suffix(
        self,
        base_username: str,
        existing_uids: set[str],
        max_attempts: int,
    ) -> FlextResult[str]:
        """Generate unique username with numeric suffix using builder pattern.

        Helper for creating unique usernames by appending numbers.
        Uses functional approach to find first available candidate.

        Args:
            base_username: Base username to extend
            existing_uids: Set of existing usernames to avoid
            max_attempts: Maximum suffix attempts

        Returns:
            FlextResult with unique username or failure

        """
        # Check if base username is available
        if base_username not in existing_uids:
            return FlextResult[str].ok(base_username)

        # Generate candidates with numeric suffixes
        for i in range(1, max_attempts):
            candidate = f"{base_username}{i}"
            if candidate not in existing_uids:
                return FlextResult[str].ok(candidate)

        return FlextResult[str].fail(
            f"Could not generate unique username after {max_attempts} attempts"
        )

    @staticmethod
    def generate_unique_username(
        base_name: str,
        existing_users: list[FlextLdifModels.Entry],
        max_attempts: int = 100,
    ) -> FlextResult[str]:
        """Generate unique username based on domain rules using builder pattern.

        Uses functional composition with helper methods for clean,
        maintainable username generation logic.

        Args:
            base_name: Base name to derive username from
            existing_users: List of existing LDAP user entries
            max_attempts: Maximum attempts to generate unique name

        Returns:
            FlextResult with generated unique username or error

        """
        domain_service = DomainServices()

        # Normalize and validate base username
        normalized_result = domain_service._normalize_username_base(base_name)
        if normalized_result.is_failure:
            return normalized_result

        base_username = normalized_result.unwrap()

        # Collect existing UIDs for uniqueness check
        existing_uids = domain_service._collect_existing_uids(existing_users)

        # Generate unique username with suffix if needed
        return domain_service._generate_username_with_suffix(
            base_username, existing_uids, max_attempts
        )
