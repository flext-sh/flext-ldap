"""ACL Converters for FLEXT LDAP.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextHandlers, FlextResult
from flext_ldap.models import FlextLdapModels


class FlextLdapAclConverters(FlextHandlers[object, FlextResult[object]]):
    """ACL converters for bidirectional format conversion."""

    class OpenLdapConverter(FlextHandlers[object, FlextResult[object]]):
        """Convert unified ACL to OpenLDAP format."""

        @classmethod
        def from_unified(
            cls, _unified_acl: FlextLdapModels.UnifiedAcl
        ) -> FlextResult[str]:
            """Convert unified ACL to OpenLDAP ACL format.

            Args:
                _unified_acl: Unified ACL to convert.

            Returns:
                FlextResult containing OpenLDAP ACL string or error.

            """
            try:
                # Build OpenLDAP ACL: access to <target> by <subject> <permissions>
                acl_parts = ["access to"]

                # Add target
                if _unified_acl.target.target_type == "attributes":
                    attrs = ",".join(_unified_acl.target.attributes)
                    acl_parts.append(f"attrs={attrs}")
                elif (
                    _unified_acl.target.dn_pattern
                    and _unified_acl.target.dn_pattern != "*"
                ):
                    acl_parts.append(f'dn.exact="{_unified_acl.target.dn_pattern}"')
                else:
                    acl_parts.append("*")

                # Add by keyword
                acl_parts.append("by")

                # Add subject
                if _unified_acl.subject.subject_type == "self":
                    acl_parts.append("self")
                elif _unified_acl.subject.subject_type == "group":
                    acl_parts.append(f"group={_unified_acl.subject.identifier}")
                elif _unified_acl.subject.subject_type == "authenticated":
                    acl_parts.append("users")
                elif _unified_acl.subject.subject_type == "anyone":
                    acl_parts.append("*")
                else:
                    acl_parts.append(f"dn={_unified_acl.subject.identifier}")

                # Add permissions
                if _unified_acl.permissions.permissions:
                    perms = ",".join(_unified_acl.permissions.permissions)
                    acl_parts.append(perms)

                openldap_acl = " ".join(acl_parts)
                return FlextResult[str].ok(openldap_acl)

            except Exception as e:
                return FlextResult[str].fail(f"OpenLDAP ACL conversion failed: {e}")

    class OracleConverter(FlextHandlers[object, FlextResult[object]]):
        """Convert unified ACL to Oracle Directory format."""

        @classmethod
        def from_unified(
            cls, _unified_acl: FlextLdapModels.UnifiedAcl
        ) -> FlextResult[str]:
            """Convert unified ACL to Oracle ACL format.

            Args:
                _unified_acl: Unified ACL to convert.

            Returns:
                FlextResult containing Oracle ACL string or error.

            """
            try:
                # Build Oracle ACL: access to <target> by <subject> (<permissions>)
                acl_parts = ["access to"]

                # Add target
                if _unified_acl.target.target_type == "attributes":
                    attrs = ", ".join(_unified_acl.target.attributes)
                    acl_parts.append(f"attr=({attrs})")
                elif _unified_acl.target.target_type == "entry":
                    acl_parts.append("entry")
                else:
                    acl_parts.append("*")

                # Add by keyword
                acl_parts.append("by")

                # Add subject
                if _unified_acl.subject.subject_type == "self":
                    acl_parts.append("self")
                elif _unified_acl.subject.subject_type == "group":
                    acl_parts.append(f'group="{_unified_acl.subject.identifier}"')
                elif _unified_acl.subject.subject_type == "user":
                    acl_parts.append(f'user="{_unified_acl.subject.identifier}"')
                elif _unified_acl.subject.subject_type == "anonymous":
                    acl_parts.append("anonymous")
                else:
                    acl_parts.append(f'user="{_unified_acl.subject.identifier}"')

                # Add permissions (Oracle format with parentheses)
                if _unified_acl.permissions.permissions:
                    perms = ", ".join(_unified_acl.permissions.permissions)
                    acl_parts.append(f"({perms})")

                oracle_acl = " ".join(acl_parts)
                return FlextResult[str].ok(oracle_acl)

            except Exception as e:
                return FlextResult[str].fail(f"Oracle ACL conversion failed: {e}")

    class AciConverter(FlextHandlers[object, FlextResult[object]]):
        """Convert unified ACL to 389 DS/Apache DS ACI format."""

        @staticmethod
        def from_unified(_unified_acl: FlextLdapModels.UnifiedAcl) -> FlextResult[str]:
            """Convert unified ACL to ACI format."""
            try:
                # Basic ACI conversion - in a real implementation, this would be more robust
                target_str = FlextLdapAclConverters.AciConverter.format_target(
                    _unified_acl.target
                )
                subject_str = FlextLdapAclConverters.AciConverter.format_subject(
                    _unified_acl.subject
                )
                permissions_str = (
                    FlextLdapAclConverters.AciConverter.format_permissions(
                        _unified_acl.permissions
                    )
                )

                aci = f'(target="{target_str}")(version 3.0;acl "{_unified_acl.name}";allow ({permissions_str}) {subject_str};)'

                return FlextResult[str].ok(aci)
            except Exception as e:
                return FlextResult[str].fail(f"Failed to convert to ACI: {e}")

        @staticmethod
        def format_target(target: FlextLdapModels.AclTarget) -> str:
            """Format ACL target for ACI."""
            if target.target_type == "entry":
                return target.dn_pattern
            if target.target_type == "attributes":
                return f"attr={','.join(target.attributes)}"
            return target.dn_pattern

        @staticmethod
        def format_subject(subject: FlextLdapModels.AclSubject) -> str:
            """Format ACL subject for ACI."""
            if subject.subject_type == "user":
                return f'userdn="{subject.identifier}"'
            if subject.subject_type == "group":
                return f'groupdn="{subject.identifier}"'
            if subject.subject_type == "self":
                return 'userdn="ldap:///self"'
            return f'userdn="{subject.identifier}"'

        @staticmethod
        def format_permissions(permissions: FlextLdapModels.AclPermissions) -> str:
            """Format ACL permissions for ACI."""
            return ",".join(permissions.permissions)

    class UniversalConverter(FlextHandlers[object, FlextResult[object]]):
        """Universal converter that can handle any ACL format."""

        @staticmethod
        def convert(
            acl_content: str,
            source_format: str,
            target_format: str,
        ) -> FlextResult[object]:
            """Convert ACL from source format to target format."""
            if not acl_content or not acl_content.strip():
                return FlextResult[object].fail("ACL content cannot be empty")

            # Import parsers and converters at runtime to avoid circular imports
            from flext_ldap import (  # noqa: PLC0415
                FlextLdapAclConstants,
                FlextLdapAclParsers,
            )

            try:
                # Step 1: Parse source ACL to unified format
                if source_format == FlextLdapAclConstants.AclFormat.OPENLDAP:
                    parse_result = FlextLdapAclParsers.OpenLdapAclParser.parse(
                        acl_content
                    )
                elif source_format == FlextLdapAclConstants.AclFormat.ORACLE:
                    parse_result = FlextLdapAclParsers.OracleAclParser.parse(
                        acl_content
                    )
                elif source_format == FlextLdapAclConstants.AclFormat.ACI:
                    parse_result = FlextLdapAclParsers.AciParser.parse(acl_content)
                else:
                    return FlextResult[object].fail(
                        f"Unsupported source format: {source_format}"
                    )

                if parse_result.is_failure:
                    return FlextResult[object].fail(
                        f"Parsing failed: {parse_result.error}"
                    )

                unified_acl = parse_result.unwrap()

                # Step 2: Convert unified format to target format
                if target_format == FlextLdapAclConstants.AclFormat.OPENLDAP:
                    convert_result = (
                        FlextLdapAclConverters.OpenLdapConverter.from_unified(
                            unified_acl
                        )
                    )
                elif target_format == FlextLdapAclConstants.AclFormat.ORACLE:
                    convert_result = (
                        FlextLdapAclConverters.OracleConverter.from_unified(unified_acl)
                    )
                elif target_format == FlextLdapAclConstants.AclFormat.ACI:
                    convert_result = FlextLdapAclConverters.AciConverter.from_unified(
                        unified_acl
                    )
                else:
                    return FlextResult[object].fail(
                        f"Unsupported target format: {target_format}"
                    )

                if convert_result.is_failure:
                    return FlextResult[object].fail(
                        f"Conversion failed: {convert_result.error}"
                    )

                # Step 3: Create conversion result
                conversion_result = FlextLdapModels.ConversionResult(
                    source_format=source_format,
                    target_format=target_format,
                    converted_acl=convert_result.unwrap(),
                )

                return FlextResult[object].ok(conversion_result)

            except Exception as e:
                return FlextResult[object].fail(f"Conversion failed: {e}")


__all__ = ["FlextLdapAclConverters"]
