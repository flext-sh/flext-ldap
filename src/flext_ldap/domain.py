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
from flext_ldap.services.domain_service import DomainServices


class FlextLdapDomain:
    """Namespace class for all LDAP domain logic and specifications.

    Contains domain services, specifications, and business rules that
    implement LDAP-specific domain logic independent of infrastructure.
    """

    # Backward compatibility: DomainServices is now in services module
    DomainServices = DomainServices

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


__all__ = [
    "FlextLdapDomain",
]
