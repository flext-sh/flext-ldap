"""ACL Manager for FLEXT LDAP.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextResult
from flext_ldap.acl.constants import FlextLdapAclConstants
from flext_ldap.acl.converters import FlextLdapAclConverters
from flext_ldap.acl.parsers import FlextLdapAclParsers
from flext_ldap.models import FlextLdapModels


class FlextLdapAclManager:
    """ACL Manager for comprehensive ACL operations."""

    def __init__(self) -> None:
        """Initialize ACL Manager."""
        self._parsers = FlextLdapAclParsers
        self._converters = FlextLdapAclConverters

    def parse_acl(
        self, acl_string: str, format_type: str
    ) -> FlextResult[FlextLdapModels.UnifiedAcl]:
        """Parse ACL from specific format to unified representation."""
        if not acl_string or not acl_string.strip():
            return FlextResult[FlextLdapModels.UnifiedAcl].fail(
                "ACL string cannot be empty"
            )

        if format_type == FlextLdapAclConstants.AclFormat.OPENLDAP:
            return self._parsers.OpenLdapAclParser.parse(acl_string)

        if format_type == FlextLdapAclConstants.AclFormat.ORACLE:
            return self._parsers.OracleAclParser.parse(acl_string)

        if format_type == FlextLdapAclConstants.AclFormat.ACI:
            return self._parsers.AciParser.parse(acl_string)

        return FlextResult[FlextLdapModels.UnifiedAcl].fail(
            f"Unsupported ACL format: {format_type}"
        )

    def convert_acl(
        self, acl_string: str, source_format: str, target_format: str
    ) -> FlextResult[FlextLdapModels.ConversionResult]:
        """Convert ACL from source format to target format."""
        if not acl_string or not acl_string.strip():
            return FlextResult[FlextLdapModels.ConversionResult].fail(
                "ACL string cannot be empty"
            )

        return self._converters.UniversalConverter.convert(
            acl_string, source_format, target_format
        )

    def convert_to_openldap(
        self, unified_acl: FlextLdapModels.UnifiedAcl
    ) -> FlextResult[str]:
        """Convert unified ACL to OpenLDAP format."""
        if not unified_acl:
            return FlextResult[str].fail("Unified ACL cannot be None")

        return self._converters.OpenLdapConverter.from_unified(unified_acl)

    def convert_to_oracle(
        self, unified_acl: FlextLdapModels.UnifiedAcl
    ) -> FlextResult[str]:
        """Convert unified ACL to Oracle Directory format."""
        if not unified_acl:
            return FlextResult[str].fail("Unified ACL cannot be None")

        return self._converters.OracleConverter.from_unified(unified_acl)

    def convert_to_aci(
        self, unified_acl: FlextLdapModels.UnifiedAcl
    ) -> FlextResult[str]:
        """Convert unified ACL to ACI format."""
        if not unified_acl:
            return FlextResult[str].fail("Unified ACL cannot be None")

        return self._converters.AciConverter.from_unified(unified_acl)

    def batch_convert(
        self, acl_list: list[str], source_format: str, target_format: str
    ) -> FlextResult[list[FlextLdapModels.ConversionResult]]:
        """Convert multiple ACLs from source to target format."""
        if not acl_list:
            return FlextResult[list[FlextLdapModels.ConversionResult]].fail(
                "ACL list cannot be empty"
            )

        results = []
        warnings = []

        for acl_string in acl_list:
            conversion_result = self.convert_acl(
                acl_string, source_format, target_format
            )

            if conversion_result.is_failure:
                warnings.append(
                    f"Failed to convert: {acl_string} - {conversion_result.error}"
                )
                continue

            results.append(conversion_result.unwrap())

        if not results and warnings:
            return FlextResult[list[FlextLdapModels.ConversionResult]].fail(
                f"All conversions failed: {'; '.join(warnings)}"
            )

        return FlextResult[list[FlextLdapModels.ConversionResult]].ok(results)

    def validate_acl_syntax(
        self, acl_string: str, format_type: str
    ) -> FlextResult[bool]:
        """Validate ACL syntax for specific format."""
        if not acl_string or not acl_string.strip():
            return FlextResult[bool].fail("ACL string cannot be empty")

        parse_result = self.parse_acl(acl_string, format_type)

        if parse_result.is_failure:
            return FlextResult[bool].fail(f"Invalid ACL syntax: {parse_result.error}")

        return FlextResult[bool].ok(True)

    def create_unified_acl(
        self,
        target: FlextLdapModels.AclTarget,
        subject: FlextLdapModels.AclSubject,
        permissions: FlextLdapModels.AclPermissions,
        name: str = "",
        priority: int = 0,
    ) -> FlextResult[FlextLdapModels.UnifiedAcl]:
        """Create unified ACL from components."""
        if not target:
            return FlextResult[FlextLdapModels.UnifiedAcl].fail(
                "ACL target is required"
            )

        if not subject:
            return FlextResult[FlextLdapModels.UnifiedAcl].fail(
                "ACL subject is required"
            )

        if not permissions:
            return FlextResult[FlextLdapModels.UnifiedAcl].fail(
                "ACL permissions are required"
            )

        return FlextLdapModels.UnifiedAcl.create(
            target=target,
            subject=subject,
            permissions=permissions,
            name=name,
            priority=priority,
        )


__all__ = ["FlextLdapAclManager"]
