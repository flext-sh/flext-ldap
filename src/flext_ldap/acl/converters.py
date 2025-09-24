"""ACL Converters for FLEXT LDAP.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextResult
from flext_ldap.acl.constants import FlextLdapAclConstants
from flext_ldap.models import FlextLdapModels


class FlextLdapAclConverters:
    """ACL converters for bidirectional format conversion."""

    class OpenLdapConverter:
        """Convert unified ACL to OpenLDAP format."""

        @classmethod
        def from_unified(
            cls, unified_acl: FlextLdapModels.UnifiedAcl
        ) -> FlextResult[str]:
            """Convert unified ACL to OpenLDAP access line."""
            if not unified_acl:
                return FlextResult[str].fail("Unified ACL cannot be None")

            target_spec = cls._build_target(unified_acl.target)
            by_clause = cls._build_by_clause(
                unified_acl.subject, unified_acl.permissions
            )

            access_line = f"access to {target_spec} {by_clause}"

            return FlextResult[str].ok(access_line)

        @classmethod
        def _build_target(cls, target: FlextLdapModels.AclTarget) -> str:
            """Build OpenLDAP target specification."""
            parts = []

            if target.attributes:
                attrs = ",".join(target.attributes)
                parts.append(f"attrs={attrs}")

            if target.dn_pattern and target.dn_pattern != "*":
                parts.append(f'dn.exact="{target.dn_pattern}"')

            if target.filter_expression:
                parts.append(f"filter={target.filter_expression}")

            return " ".join(parts) if parts else "*"

        @classmethod
        def _build_by_clause(
            cls,
            subject: FlextLdapModels.AclSubject,
            permissions: FlextLdapModels.AclPermissions,
        ) -> str:
            """Build OpenLDAP by clause."""
            subject_spec = cls._map_subject(subject)

            perm_spec = cls._map_permissions(permissions)

            return f"by {subject_spec} {perm_spec}"

        @classmethod
        def _map_subject(cls, subject: FlextLdapModels.AclSubject) -> str:
            """Map subject to OpenLDAP format."""
            if subject.subject_type == FlextLdapAclConstants.SubjectType.SELF:
                return "self"
            if subject.subject_type == FlextLdapAclConstants.SubjectType.ANONYMOUS:
                return "anonymous"
            if subject.subject_type == FlextLdapAclConstants.SubjectType.AUTHENTICATED:
                return "users"
            if subject.subject_type == FlextLdapAclConstants.SubjectType.GROUP:
                return f"group={subject.identifier}"
            if subject.subject_type == FlextLdapAclConstants.SubjectType.DN:
                return f"dn={subject.identifier}"

            return "*"

        @classmethod
        def _map_permissions(
            cls, permissions: FlextLdapModels.AclPermissions
        ) -> str:
            """Map permissions to OpenLDAP format."""
            if permissions.permissions:
                return permissions.permissions[0].lower()

            return "none"

    class OracleConverter:
        """Convert unified ACL to Oracle Directory format."""

        @classmethod
        def from_unified(
            cls, unified_acl: FlextLdapModels.UnifiedAcl
        ) -> FlextResult[str]:
            """Convert unified ACL to Oracle orclaci format."""
            if not unified_acl:
                return FlextResult[str].fail("Unified ACL cannot be None")

            target_spec = cls._build_target(unified_acl.target)
            subject_spec = cls._build_subject(unified_acl.subject)
            perms_spec = cls._build_permissions(unified_acl.permissions)

            orclaci = f"access to {target_spec} by {subject_spec} ({perms_spec})"

            return FlextResult[str].ok(orclaci)

        @classmethod
        def _build_target(cls, target: FlextLdapModels.AclTarget) -> str:
            """Build Oracle target specification."""
            if target.attributes:
                attrs = ", ".join(target.attributes)
                return f"attr=({attrs})"

            if target.target_type == FlextLdapAclConstants.TargetType.ENTRY:
                return "entry"

            return "attr=(*)"

        @classmethod
        def _build_subject(cls, subject: FlextLdapModels.AclSubject) -> str:
            """Build Oracle subject specification."""
            if subject.subject_type == FlextLdapAclConstants.SubjectType.GROUP:
                return f'group="{subject.identifier}"'

            if subject.subject_type == FlextLdapAclConstants.SubjectType.USER:
                return f'user="{subject.identifier}"'

            return 'group="*"'

        @classmethod
        def _build_permissions(
            cls, permissions: FlextLdapModels.AclPermissions
        ) -> str:
            """Build Oracle permissions specification."""
            if permissions.permissions:
                return ", ".join(permissions.permissions)

            return "none"

    class AciConverter:
        """Convert unified ACL to 389 DS/Apache DS ACI format."""

        @classmethod
        def from_unified(
            cls, unified_acl: FlextLdapModels.UnifiedAcl
        ) -> FlextResult[str]:
            """Convert unified ACL to ACI format."""
            if not unified_acl:
                return FlextResult[str].fail("Unified ACL cannot be None")

            target = unified_acl.target.dn_pattern or "*"
            name = unified_acl.name or "Converted ACL"
            grant_type = unified_acl.permissions.grant_type
            perms = cls._build_permissions(unified_acl.permissions)
            bind_rules = cls._build_bind_rules(unified_acl.subject)

            aci = (
                f'(target="{target}")'
                f'(version 3.0; acl "{name}"; {grant_type} ({perms}) {bind_rules};)'
            )

            return FlextResult[str].ok(aci)

        @classmethod
        def _build_permissions(
            cls, permissions: FlextLdapModels.AclPermissions
        ) -> str:
            """Build ACI permissions."""
            perm_list = (
                permissions.permissions
                if permissions.grant_type == "allow"
                else permissions.denied_permissions
            )

            return ", ".join(perm_list) if perm_list else "read"

        @classmethod
        def _build_bind_rules(cls, subject: FlextLdapModels.AclSubject) -> str:
            """Build ACI bind rules."""
            if subject.subject_type == FlextLdapAclConstants.SubjectType.DN:
                return f'userdn="{subject.identifier}"'

            if subject.subject_type == FlextLdapAclConstants.SubjectType.GROUP:
                return f'groupdn="{subject.identifier}"'

            return 'userdn="ldap:///anyone"'

    class UniversalConverter:
        """Universal converter for any format conversion."""

        @classmethod
        def convert(
            cls, acl_string: str, source_format: str, target_format: str
        ) -> FlextResult[FlextLdapModels.ConversionResult]:
            """Convert ACL from source format to target format."""
            if not acl_string or not acl_string.strip():
                return FlextResult[FlextLdapModels.ConversionResult].fail(
                    "ACL string cannot be empty"
                )

            if source_format not in {
                FlextLdapAclConstants.AclFormat.OPENLDAP,
                FlextLdapAclConstants.AclFormat.ORACLE,
                FlextLdapAclConstants.AclFormat.ACI,
            }:
                return FlextResult[FlextLdapModels.ConversionResult].fail(
                    f"Unsupported source format: {source_format}"
                )

            if target_format not in {
                FlextLdapAclConstants.AclFormat.OPENLDAP,
                FlextLdapAclConstants.AclFormat.ORACLE,
                FlextLdapAclConstants.AclFormat.ACI,
            }:
                return FlextResult[FlextLdapModels.ConversionResult].fail(
                    f"Unsupported target format: {target_format}"
                )

            unified_result = cls._parse_to_unified(acl_string, source_format)
            if unified_result.is_failure:
                return FlextResult[FlextLdapModels.ConversionResult].fail(
                    f"Parse failed: {unified_result.error}"
                )

            converted_result = cls._convert_from_unified(
                unified_result.unwrap(), target_format
            )
            if converted_result.is_failure:
                return FlextResult[FlextLdapModels.ConversionResult].fail(
                    f"Conversion failed: {converted_result.error}"
                )

            return FlextLdapModels.ConversionResult.create(
                converted_acl=converted_result.unwrap(),
                source_format=source_format,
                target_format=target_format,
                warnings=[],
            )

        @classmethod
        def _parse_to_unified(
            cls, acl_string: str, format_type: str
        ) -> FlextResult[FlextLdapModels.UnifiedAcl]:
            """Parse ACL string to unified format based on source format."""
            from flext_ldap.acl.parsers import FlextLdapAclParsers

            if format_type == FlextLdapAclConstants.AclFormat.OPENLDAP:
                return FlextLdapAclParsers.OpenLdapAclParser.parse(acl_string)

            if format_type == FlextLdapAclConstants.AclFormat.ORACLE:
                return FlextLdapAclParsers.OracleAclParser.parse(acl_string)

            if format_type == FlextLdapAclConstants.AclFormat.ACI:
                return FlextLdapAclParsers.AciParser.parse(acl_string)

            return FlextResult[FlextLdapModels.UnifiedAcl].fail(
                f"Unknown format: {format_type}"
            )

        @classmethod
        def _convert_from_unified(
            cls, unified_acl: FlextLdapModels.UnifiedAcl, target_format: str
        ) -> FlextResult[str]:
            """Convert unified ACL to target format."""
            if target_format == FlextLdapAclConstants.AclFormat.OPENLDAP:
                return FlextLdapAclConverters.OpenLdapConverter.from_unified(
                    unified_acl
                )

            if target_format == FlextLdapAclConstants.AclFormat.ORACLE:
                return FlextLdapAclConverters.OracleConverter.from_unified(unified_acl)

            if target_format == FlextLdapAclConstants.AclFormat.ACI:
                return FlextLdapAclConverters.AciConverter.from_unified(unified_acl)

            return FlextResult[str].fail(f"Unknown target format: {target_format}")


__all__ = ["FlextLdapAclConverters"]
