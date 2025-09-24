"""ACL Manager for FLEXT LDAP.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextHandlers, FlextResult
from flext_ldap.acl.constants import FlextLdapAclConstants
from flext_ldap.acl.converters import FlextLdapAclConverters
from flext_ldap.acl.parsers import FlextLdapAclParsers
from flext_ldap.models import FlextLdapModels

# Constants for ACL parsing
MIN_ACL_PARTS = 6


class FlextLdapAclManager(FlextHandlers[object, FlextResult[object]]):
    """ACL Manager for comprehensive ACL operations."""

    def __init__(self: object) -> None:
        """Initialize ACL Manager."""
        self._parsers = FlextLdapAclParsers
        self._converters = FlextLdapAclConverters

    def handle(self, request: object) -> FlextResult[FlextResult[object]]:
        """Handle ACL management request."""
        # Use request parameter to avoid unused argument warning
        _request = request  # Acknowledge the parameter
        return FlextResult[FlextResult[object]].fail("ACL handling not implemented")

    def parse_acl(
        self, acl_string: str, format_type: str
    ) -> FlextResult[FlextLdapModels.UnifiedAcl]:
        """Parse ACL from specific format to unified representation."""
        if not acl_string or not acl_string.strip():
            return FlextResult[FlextLdapModels.UnifiedAcl].fail(
                "ACL string cannot be empty"
            )

        if format_type == FlextLdapAclConstants.AclFormat.OPENLDAP:
            return self._parse_openldap_acl(acl_string)

        if format_type == FlextLdapAclConstants.AclFormat.ORACLE:
            return self._parse_oracle_acl(acl_string)

        if format_type == FlextLdapAclConstants.AclFormat.ACI:
            return FlextResult[FlextLdapModels.UnifiedAcl].fail(
                "ACI ACL parser not yet implemented"
            )

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

        result = self._converters.UniversalConverter.convert(
            acl_string, source_format, target_format
        )
        if result.is_success:
            # Convert the object result to ConversionResult
            conversion_result = FlextLdapModels.ConversionResult(
                source_format=source_format,
                target_format=target_format,
                converted_acl=str(result.value),
            )
            return FlextResult[FlextLdapModels.ConversionResult].ok(conversion_result)
        return FlextResult[FlextLdapModels.ConversionResult].fail(
            result.error or "Conversion failed"
        )

    def convert_to_openldap(
        self, unified_acl: FlextLdapModels.UnifiedAcl
    ) -> FlextResult[str]:
        """Convert unified ACL to OpenLDAP format."""
        if not unified_acl:
            return FlextResult[str].fail("Unified ACL cannot be None")

        return FlextResult[str].fail("OpenLDAP converter not yet implemented")

    def convert_to_oracle(
        self, unified_acl: FlextLdapModels.UnifiedAcl
    ) -> FlextResult[str]:
        """Convert unified ACL to Oracle Directory format."""
        if not unified_acl:
            return FlextResult[str].fail("Unified ACL cannot be None")

        return FlextResult[str].fail("Oracle converter not yet implemented")

    def convert_to_aci(
        self, unified_acl: FlextLdapModels.UnifiedAcl
    ) -> FlextResult[str]:
        """Convert unified ACL to ACI format."""
        if not unified_acl:
            return FlextResult[str].fail("Unified ACL cannot be None")

        return FlextResult[str].fail("ACI converter not yet implemented")

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

    def _parse_openldap_acl(
        self, acl_string: str
    ) -> FlextResult[FlextLdapModels.UnifiedAcl]:
        """Parse OpenLDAP ACL string to unified representation."""
        try:
            # Basic OpenLDAP ACL parsing
            # Format: "access to <target> by <subject> <permissions>"
            parts = acl_string.strip().split()

            if len(parts) < MIN_ACL_PARTS:
                return FlextResult[FlextLdapModels.UnifiedAcl].fail(
                    "Invalid OpenLDAP ACL format"
                )

            # Find "access to" and "by" keywords
            access_idx = parts.index("access") if "access" in parts else -1
            to_idx = parts.index("to") if "to" in parts else -1
            by_idx = parts.index("by") if "by" in parts else -1

            if access_idx == -1 or to_idx == -1 or by_idx == -1:
                return FlextResult[FlextLdapModels.UnifiedAcl].fail(
                    "Missing required keywords in OpenLDAP ACL"
                )

            # Extract target (between "to" and "by")
            target_parts = parts[to_idx + 1 : by_idx]
            target_str = " ".join(target_parts)

            # Extract subject and permissions (after "by")
            subject_perms = parts[by_idx + 1 :]

            # Parse target
            target = self._parse_openldap_target(target_str)

            # Parse subject and permissions
            subject, permissions = self._parse_openldap_subject_permissions(
                subject_perms
            )

            # Create unified ACL
            unified_acl = FlextLdapModels.UnifiedAcl(
                target=target,
                subject=subject,
                permissions=permissions,
                name=f"openldap_acl_{hash(acl_string)}",
                priority=100,
            )

            return FlextResult[FlextLdapModels.UnifiedAcl].ok(unified_acl)

        except Exception as e:
            return FlextResult[FlextLdapModels.UnifiedAcl].fail(
                f"Failed to parse OpenLDAP ACL: {e}"
            )

    def _parse_openldap_target(self, target_str: str) -> FlextLdapModels.AclTarget:
        """Parse OpenLDAP ACL target."""
        # Handle different target types
        if target_str.startswith("attrs="):
            # Attribute target: "attrs=mail,cn"
            attrs_str = target_str[6:]  # Remove "attrs="
            attributes = [attr.strip() for attr in attrs_str.split(",")]
            return FlextLdapModels.AclTarget(
                target_type="attributes",
                attributes=attributes,
                dn_pattern="*",
                filter_expression="",
            )
        if target_str.startswith("dn="):
            # DN target: "dn.base=ou=people"
            dn_pattern = target_str[3:]  # Remove "dn="
            return FlextLdapModels.AclTarget(
                target_type="dn",
                attributes=[],
                dn_pattern=dn_pattern,
                filter_expression="",
            )
        if target_str.startswith("filter="):
            # Filter target: "filter=(objectClass=person)"
            filter_pattern = target_str[7:]  # Remove "filter="
            return FlextLdapModels.AclTarget(
                target_type="filter",
                attributes=[],
                dn_pattern="*",
                filter_expression=filter_pattern,
            )
        # Default to entry target
        return FlextLdapModels.AclTarget(
            target_type="entry",
            attributes=[],
            dn_pattern="*",
            filter_expression="",
        )

    def _parse_openldap_subject_permissions(
        self, subject_perms: list[str]
    ) -> tuple[FlextLdapModels.AclSubject, FlextLdapModels.AclPermissions]:
        """Parse OpenLDAP ACL subject and permissions."""
        # Simple parsing - in a real implementation, this would be more robust
        if not subject_perms:
            subject_str = "anonymous"
            perms_str = "read"
        else:
            # Extract subject
            subject_str = subject_perms[0]

            # Extract permissions (remaining parts)
            perms_str = (
                " ".join(subject_perms[1:]) if len(subject_perms) > 1 else "read"
            )

        # Parse permissions
        permissions = self._parse_openldap_permissions(perms_str)

        # Create subject
        subject = FlextLdapModels.AclSubject(
            subject_type="self",
            identifier=subject_str,
        )

        return subject, permissions

    def _parse_openldap_permissions(
        self, perms_str: str
    ) -> FlextLdapModels.AclPermissions:
        """Parse OpenLDAP ACL permissions."""
        permissions = []

        # Map OpenLDAP permissions to string values
        perm_mapping = {
            "read": "read",
            "write": "write",
            "add": "add",
            "delete": "delete",
            "search": "search",
            "compare": "compare",
            "selfwrite": "selfwrite",
            "selfadd": "selfadd",
            "selfdelete": "selfdelete",
        }

        # Parse permissions string
        for perm_name, perm_value in perm_mapping.items():
            if perm_name in perms_str.lower():
                permissions.append(perm_value)

        # Default to read if no permissions found
        if not permissions:
            permissions.append("read")

        return FlextLdapModels.AclPermissions(
            permissions=permissions, denied_permissions=[], grant_type="allow"
        )

    def _parse_oracle_acl(
        self, acl_string: str
    ) -> FlextResult[FlextLdapModels.UnifiedAcl]:
        """Parse Oracle ACL string to unified representation."""
        try:
            # Use the Oracle ACL parser
            return FlextLdapAclParsers.OracleAclParser.parse(acl_string)
        except Exception as e:
            return FlextResult[FlextLdapModels.UnifiedAcl].fail(
                f"Failed to parse Oracle ACL: {e}"
            )


__all__ = ["FlextLdapAclManager"]
