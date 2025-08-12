"""LDAP Domain Models - Value Objects using FLEXT Core Patterns.

Domain models extending FlextValueObject from flext-core without duplicating functionality.
Uses FlextValueObject as base class for all LDAP domain value objects following DDD patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from dataclasses import dataclass

from flext_core import FlextResult, FlextValue

from flext_ldap.constants import (
    FlextLdapAttributeConstants,
    FlextLdapObjectClassConstants,
    FlextLdapScope,
)
from flext_ldap.value_objects import FlextLdapDistinguishedName


@dataclass(frozen=True)
class FlextLdapUserCreateData:
    """Data structure for user creation parameters."""

    dn: str
    uid: str
    cn: str
    sn: str
    given_name: str | None = None
    mail: str | None = None
    password: str | None = None
    object_classes: list[str] | None = None


# FlextLdapDistinguishedName: CONSOLIDATED to value_objects.py (RFC 4514 compliant)
# Import from: from flext_ldap.value_objects import FlextLdapDistinguishedName


# FlextLdapFilter: CONSOLIDATED to value_objects.py (RFC 4515 compliant)
# Import from: from flext_ldap.value_objects import FlextLdapFilter


class FlextLdapScopeValue(FlextValue):
    """LDAP Search Scope value object extending FlextValue."""

    scope: FlextLdapScope

    def validate_domain_rules(self) -> FlextResult[None]:
        """Validate scope is valid LDAP scope."""
        valid_scopes = [
            FlextLdapScope.BASE,
            FlextLdapScope.ONE,
            FlextLdapScope.SUB,
            FlextLdapScope.CHILDREN,
        ]
        if self.scope not in valid_scopes:
            return FlextResult.fail(f"Invalid LDAP scope: {self.scope}")
        return FlextResult.ok(None)

    @classmethod
    def create(cls, scope: str | FlextLdapScope) -> FlextResult[FlextLdapScopeValue]:
        """Create scope value object with validation."""
        try:
            scope_enum = FlextLdapScope(scope) if isinstance(scope, str) else scope

            instance = cls(scope=scope_enum)
            validation_result = instance.validate_domain_rules()
            if validation_result.is_failure:
                return FlextResult.fail(validation_result.error or "Validation failed")
            return FlextResult.ok(instance)
        except ValueError:
            return FlextResult.fail(f"Invalid LDAP scope: {scope}")
        except Exception as e:
            return FlextResult.fail(f"Failed to create scope: {e}")


# FlextLdapCreateUserRequest: CONSOLIDATED to value_objects.py (comprehensive validation)
# Import from: from flext_ldap.value_objects import FlextLdapCreateUserRequest


class FlextLdapCreateGroupRequest(FlextValue):
    """LDAP Create Group Request value object extending FlextValue."""

    dn: str
    cn: str
    description: str | None = None
    members: list[str] | None = None
    object_classes: list[str] | None = None

    def validate_domain_rules(self) -> FlextResult[None]:
        """Validate group creation request."""
        if not self.dn or not self.dn.strip():
            return FlextResult.fail("DN is required for group creation")

        if not self.cn or not self.cn.strip():
            return FlextResult.fail("Common Name (cn) is required")

        # Validate DN format
        dn_result = FlextLdapDistinguishedName.create(self.dn)
        if dn_result.is_failure:
            return FlextResult.fail(f"Invalid DN format: {dn_result.error}")

        # Validate member DNs if provided
        if self.members:
            for member_dn in self.members:
                member_dn_result = FlextLdapDistinguishedName.create(member_dn)
                if member_dn_result.is_failure:
                    return FlextResult.fail(
                        f"Invalid member DN '{member_dn}': {member_dn_result.error}",
                    )

        return FlextResult.ok(None)

    @classmethod
    def create(
        cls,
        dn: str,
        cn: str,
        description: str | None = None,
        members: list[str] | None = None,
        object_classes: list[str] | None = None,
    ) -> FlextResult[FlextLdapCreateGroupRequest]:
        """Create group request with validation."""
        try:
            if object_classes is None:
                object_classes = [FlextLdapObjectClassConstants.GROUP_OF_NAMES]

            instance = cls(
                dn=dn.strip(),
                cn=cn.strip(),
                description=description.strip() if description else None,
                members=members or [],
                object_classes=object_classes,
            )

            validation_result = instance.validate_domain_rules()
            if validation_result.is_failure:
                return FlextResult.fail(validation_result.error or "Validation failed")
            return FlextResult.ok(instance)
        except Exception as e:
            return FlextResult.fail(f"Failed to create group request: {e}")

    def to_ldap_attributes(self) -> dict[str, object]:
        """Convert to LDAP attributes dictionary."""
        attributes: dict[str, object] = {
            FlextLdapAttributeConstants.OBJECT_CLASS: self.object_classes or [],
            FlextLdapAttributeConstants.COMMON_NAME: self.cn,
        }

        if self.description:
            attributes[FlextLdapAttributeConstants.DESCRIPTION] = self.description

        if self.members:
            attributes[FlextLdapAttributeConstants.MEMBER] = self.members

        return attributes
