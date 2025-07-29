"""LDAP authentication patterns moved from flext-core.

This module contains LDAP-specific authentication and validation patterns
that were extracted from flext-core for better separation of concerns.
"""

from __future__ import annotations

# 🚨 ARCHITECTURAL COMPLIANCE: Using flext-core root imports
from flext_core import FlextResult, FlextValueObject
from pydantic import Field, field_validator


class FlextLdapConfig(FlextValueObject):
    """LDAP authentication configuration - consolidated pattern."""

    server_uri: str = Field(..., description="LDAP server URI")
    bind_dn: str = Field(..., description="LDAP bind DN")
    bind_password: str = Field(
        ...,
        description="LDAP bind password",
        json_schema_extra={"secret": True},
    )
    base_dn: str = Field(..., description="LDAP base DN for searches")
    user_filter: str = Field(
        default="(uid={username})",
        description="LDAP user search filter",
    )
    group_filter: str = Field(
        default="(member={user_dn})",
        description="LDAP group search filter",
    )

    def validate_domain_rules(self) -> FlextResult[None]:
        """Validate domain rules for LDAP configuration."""
        if not self.server_uri:
            return FlextResult.fail("LDAP config must have server_uri")
        if not self.bind_dn:
            return FlextResult.fail("LDAP config must have bind_dn")
        if not self.base_dn:
            return FlextResult.fail("LDAP config must have base_dn")
        if not self.server_uri.startswith(("ldap://", "ldaps://")):
            return FlextResult.fail("LDAP URI must start with ldap:// or ldaps://")
        return FlextResult.ok(None)

    @field_validator("server_uri")
    @classmethod
    def validate_ldap_uri(cls, v: str) -> str:
        """Validate LDAP URI format."""
        if not v.startswith(("ldap://", "ldaps://")):
            msg = "LDAP URI must start with ldap:// or ldaps://"
            raise ValueError(msg)
        return v.rstrip("/")


def validate_ldap_uri_field(v: object) -> str:
    """Validate LDAP URI - used in LDAP projects."""
    if not isinstance(v, str):
        msg = "LDAP URI must be a string"
        raise TypeError(msg)
    if not v.startswith(("ldap://", "ldaps://")):
        msg = "LDAP URI must start with ldap:// or ldaps://"
        raise ValueError(msg)
    return v.rstrip("/")


__all__ = [
    "FlextLdapConfig",
    "validate_ldap_uri_field",
]
