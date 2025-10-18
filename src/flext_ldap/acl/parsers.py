"""ACL Parsers for FLEXT LDAP.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import re

from flext_core import FlextResult

from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels


class FlextLdapAclParsers:
    """ACL parsers for different LDAP server formats."""

    class OpenLdapAclParser:
        """Parse OpenLDAP ACL format."""

        @classmethod
        def parse(cls, acl: str | None) -> FlextResult[FlextLdapModels.Acl]:
            """Parse OpenLDAP ACL string to unified ACL format.

            Args:
                acl: OpenLDAP ACL string to parse.

            Returns:
                FlextResult containing parsed ACL or error.

            """
            if not acl or not acl.strip():
                return FlextResult[FlextLdapModels.Acl].fail(
                    "ACL string cannot be empty",
                )

            try:
                # OpenLDAP ACL format: access to <target> by <subject> <permissions>
                parts = acl.strip().split()

                # Find "access to" keywords
                if (
                    len(parts) < FlextLdapConstants.MIN_ACL_PARTS
                    or parts[0] != "access"
                    or parts[1] != "to"
                ):
                    return FlextResult[FlextLdapModels.Acl].fail(
                        "Invalid OpenLDAP ACL format",
                    )

                # Find "by" keyword to split target and subject/permissions
                if "by" not in parts:
                    return FlextResult[FlextLdapModels.Acl].fail(
                        "Invalid OpenLDAP ACL format",
                    )

                by_idx = parts.index("by")

                # Extract target (between "to" and "by")
                target_parts = parts[2:by_idx]
                target_str = " ".join(target_parts)

                # Extract subject and permissions (after "by")
                subject_perms_parts = parts[by_idx + 1 :]
                if not subject_perms_parts:
                    return FlextResult[FlextLdapModels.Acl].fail(
                        "Invalid OpenLDAP ACL format",
                    )

                # Parse target
                target = cls._parse_openldap_target(target_str)

                # Parse subject (first part after "by")
                subject_str = subject_perms_parts[0]
                subject = cls._parse_openldap_subject(subject_str)

                # Parse permissions (remaining parts)
                perms_str = (
                    " ".join(subject_perms_parts[1:])
                    if len(subject_perms_parts) > 1
                    else "read"
                )
                permissions = cls._parse_openldap_permissions(perms_str)

                # Create unified ACL
                unified_acl = FlextLdapModels.Acl(
                    target=target,
                    subject=subject,
                    permissions=permissions,
                    server_type="openldap",
                    name=f"openldap_acl_{hash(acl)}",
                    priority=100,
                )

                return FlextResult[FlextLdapModels.Acl].ok(unified_acl)

            except Exception as e:
                return FlextResult[FlextLdapModels.Acl].fail(
                    f"Failed to parse OpenLDAP ACL: {e}",
                )

        @staticmethod
        def _parse_openldap_target(target_str: str) -> FlextLdapModels.AclTarget:
            """Parse OpenLDAP ACL target."""
            # Handle attrs= format
            if target_str.startswith("attrs="):
                attrs_str = target_str[6:]  # Remove "attrs="
                attributes = [attr.strip() for attr in attrs_str.split(",")]
                return FlextLdapModels.AclTarget(
                    target_type="attributes",  # Set for attributes
                    dn_pattern="*",
                    attributes=attributes,
                    filter_expression="",
                )

            # Handle dn.exact= format
            if target_str.startswith("dn.exact="):
                dn_pattern = target_str[9:].strip('"')  # Remove dn.exact= and quotes
                return FlextLdapModels.AclTarget(
                    target_type="dn",  # Explicitly set target type for DN
                    dn_pattern=dn_pattern,
                    attributes=[],
                    filter_expression="",
                )

            # Default to entry target
            return FlextLdapModels.AclTarget(
                target_type="entry",  # Explicitly set default type
                dn_pattern="*",
                attributes=[],
                filter_expression="",
            )

        @staticmethod
        def _parse_openldap_subject(subject_str: str) -> FlextLdapModels.AclSubject:
            """Parse OpenLDAP ACL subject."""
            # Map OpenLDAP subject keywords to subject types
            subject_mapping = {
                "self": "self",
                "users": "authenticated",
                "anonymous": "anonymous",
                "*": "anyone",
            }

            subject_type = subject_mapping.get(subject_str, "user")

            return FlextLdapModels.AclSubject(
                subject_type=subject_type,
                subject_dn=subject_str,
            )

        @staticmethod
        def _parse_openldap_permissions(
            perms_str: str,
        ) -> FlextLdapModels.AclPermissions:
            """Parse OpenLDAP ACL permissions."""
            # Map OpenLDAP permission keywords
            perm_mapping = {
                "read": "read",
                "write": "write",
                "add": "add",
                "delete": "delete",
                "search": "search",
                "compare": "compare",
                "auth": "auth",
            }

            permissions: list[str] = []
            for perm in perms_str.split(","):
                perm_clean = perm.strip().lower()
                if perm_clean in perm_mapping:
                    permissions.append(perm_mapping[perm_clean])

            # Default to read if no permissions found
            if not permissions:
                permissions.append("read")

            return FlextLdapModels.AclPermissions(
                granted_permissions=permissions,
                denied_permissions=[],
                grant_type="allow",
            )

    class OracleAclParser:
        """Parse Oracle Directory ACL format."""

        @staticmethod
        def parse(
            acl_string: str | None,
        ) -> FlextResult[FlextLdapModels.Acl]:
            """Parse Oracle ACL string to unified representation."""
            try:
                if not acl_string or not acl_string.strip():
                    return FlextResult[FlextLdapModels.Acl].fail(
                        "ACL string cannot be empty",
                    )

                # Basic Oracle ACL parsing
                # Format: access to <target> by <subject> (<permissions>)
                parts = acl_string.strip().split()

                if len(parts) < FlextLdapConstants.MIN_ACL_PARTS:
                    return FlextResult[FlextLdapModels.Acl].fail(
                        "Invalid Oracle ACL format",
                    )

                # Find "access to" and "by" keywords
                access_idx = parts.index("access") if "access" in parts else -1
                to_idx = parts.index("to") if "to" in parts else -1
                by_idx = parts.index("by") if "by" in parts else -1

                if access_idx == -1 or to_idx == -1 or by_idx == -1:
                    return FlextResult[FlextLdapModels.Acl].fail(
                        "Missing required keywords in Oracle ACL",
                    )

                # Extract target (between "to" and "by")
                target_parts = parts[to_idx + 1 : by_idx]
                target_str = " ".join(target_parts)

                # Extract subject and permissions (after "by")
                subject_perms = parts[by_idx + 1 :]

                # Parse target
                target = FlextLdapAclParsers.OracleAclParser.parse_oracle_target(
                    target_str,
                )

                # Parse subject and permissions
                subject, permissions = (
                    FlextLdapAclParsers.OracleAclParser.parse_oracle_subject_permissions(
                        subject_perms,
                    )
                )

                # Create unified ACL
                unified_acl = FlextLdapModels.Acl(
                    target=target,
                    subject=subject,
                    permissions=permissions,
                    server_type="oracle",
                    name=f"oracle_acl_{hash(acl_string)}",
                    priority=100,
                )

                return FlextResult[FlextLdapModels.Acl].ok(unified_acl)

            except Exception as e:
                return FlextResult[FlextLdapModels.Acl].fail(
                    f"Failed to parse Oracle ACL: {e}",
                )

        @staticmethod
        def parse_oracle_target(target_str: str) -> FlextLdapModels.AclTarget:
            """Parse Oracle ACL target."""
            # Handle different target types
            if target_str == "entry":
                return FlextLdapModels.AclTarget(
                    target_type="entry",
                    attributes=[],
                    dn_pattern="*",
                    filter_expression="",
                )
            if target_str.startswith("attrs="):
                # Attribute target: attrs=mail,cn
                attrs_str = target_str[6:]  # Remove "attrs="
                attributes = [attr.strip() for attr in attrs_str.split(",")]
                return FlextLdapModels.AclTarget(
                    target_type="attributes",
                    dn_pattern="*",
                    attributes=attributes,
                    filter_expression="",
                )
            if target_str.startswith("attr="):
                # Attribute target: attr=(userPassword)
                attrs_str = target_str[5:]  # Remove "attr="
                # Remove parentheses if present
                attrs_str = attrs_str.strip("()")
                attributes = [attrs_str.strip()]
                return FlextLdapModels.AclTarget(
                    target_type="attributes",
                    dn_pattern="*",
                    attributes=attributes,
                    filter_expression="",
                )
            # Default to entry target
            return FlextLdapModels.AclTarget(
                dn_pattern="*",
                attributes=[],
                filter_expression="",
            )

        @staticmethod
        def parse_oracle_subject_permissions(
            subject_perms: list[str],
        ) -> tuple[FlextLdapModels.AclSubject, FlextLdapModels.AclPermissions]:
            """Parse Oracle ACL subject and permissions."""
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
            permissions = FlextLdapAclParsers.OracleAclParser.parse_oracle_permissions(
                perms_str,
            )

            # Determine subject type based on subject string
            subject_type = "user"
            if "group=" in subject_str:
                subject_type = "group"
            elif "user=" in subject_str:
                subject_type = "user"
            elif subject_str == "self":
                subject_type = "self"
            elif subject_str == "anonymous":
                subject_type = "anonymous"

            # Create subject
            subject = FlextLdapModels.AclSubject(
                subject_type=subject_type,
                subject_dn=subject_str,
            )

            return subject, permissions

        @staticmethod
        def parse_oracle_permissions(perms_str: str) -> FlextLdapModels.AclPermissions:
            """Parse Oracle ACL permissions."""
            permissions = []

            # Remove parentheses if present
            perms_str = perms_str.strip("()")

            # Split by comma and clean up
            perm_list = [perm.strip() for perm in perms_str.split(",")]

            # Map Oracle permissions to string values
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

            # Parse permissions
            permissions = [
                perm_mapping[perm.lower()]
                for perm in perm_list
                if perm.lower() in perm_mapping
            ]

            # Default to read if no permissions found
            if not permissions:
                permissions.append("read")

            return FlextLdapModels.AclPermissions(
                granted_permissions=permissions,
                denied_permissions=[],
                grant_type="allow",
            )

    class AciParser:
        """Parse 389 DS/Apache DS ACI format."""

        @classmethod
        def parse(cls, aci: str) -> FlextResult[FlextLdapModels.Acl]:
            """Parse ACI string to unified ACL format.

            Args:
                aci: ACI string to parse.

            Returns:
                FlextResult containing parsed ACL or error.

            """
            if not aci or not aci.strip():
                return FlextResult[FlextLdapModels.Acl].fail(
                    "ACI string cannot be empty",
                )

            try:
                # ACI: (target)(v3.0; acl "name"; allow/deny (perms) subj;)
                # Extract target
                target_match = re.search(r'\(target="([^"]+)"\)', aci)
                if not target_match:
                    return FlextResult[FlextLdapModels.Acl].fail(
                        "Invalid ACI format: missing target",
                    )

                target_dn = target_match.group(1)

                # Extract ACL name
                name_match = re.search(r'acl\s+"([^"]+)"', aci)
                if not name_match:
                    return FlextResult[FlextLdapModels.Acl].fail(
                        "Invalid ACI format: missing ACL name",
                    )

                acl_name = name_match.group(1)

                # Extract grant type (allow or deny)
                grant_type_match = re.search(r";\s*(allow|deny)\s+", aci)
                if not grant_type_match:
                    return FlextResult[FlextLdapModels.Acl].fail(
                        "Invalid ACI format: missing grant type",
                    )

                grant_type = grant_type_match.group(1)

                # Extract permissions
                perms_match = re.search(r"(allow|deny)\s+\(([^)]+)\)", aci)
                if not perms_match:
                    return FlextResult[FlextLdapModels.Acl].fail(
                        "Invalid ACI format: missing permissions",
                    )

                perms_str = perms_match.group(2)
                permissions_list = [p.strip() for p in perms_str.split(",")]

                # Extract subject
                subject_match = re.search(r'(userdn|groupdn)="([^"]+)"', aci)
                if not subject_match:
                    return FlextResult[FlextLdapModels.Acl].fail(
                        "Invalid ACI format: missing subject",
                    )

                subject_type_str = subject_match.group(1)
                subject_identifier = subject_match.group(2)

                # Map subject type
                if subject_type_str == "groupdn":
                    subject_type = "group"
                elif "anyone" in subject_identifier:
                    subject_type = "anyone"
                else:
                    subject_type = "user"

                # Create target
                target = FlextLdapModels.AclTarget(
                    dn_pattern=target_dn,
                    attributes=[],
                    filter_expression="",
                )

                # Create subject
                subject = FlextLdapModels.AclSubject(
                    subject_type=subject_type,
                    subject_dn=subject_identifier,
                )

                # Create permissions
                if grant_type == "allow":
                    permissions = FlextLdapModels.AclPermissions(
                        granted_permissions=permissions_list,
                        denied_permissions=[],
                        grant_type="allow",
                    )
                else:  # deny
                    permissions = FlextLdapModels.AclPermissions(
                        granted_permissions=[],
                        denied_permissions=permissions_list,
                        grant_type="deny",
                    )

                # Create unified ACL
                unified_acl = FlextLdapModels.Acl(
                    target=target,
                    subject=subject,
                    permissions=permissions,
                    server_type="aci",
                    name=acl_name,
                    priority=100,
                )

                return FlextResult[FlextLdapModels.Acl].ok(unified_acl)

            except Exception as e:
                return FlextResult[FlextLdapModels.Acl].fail(
                    f"Failed to parse ACI: {e}",
                )

    class MicrosoftAdConverter:
        """Convert unified ACL format to Microsoft Active Directory format."""

        @staticmethod
        def from_unified(
            unified_acl: FlextLdapModels.Acl,
        ) -> FlextResult[str]:
            """Convert unified ACL to Microsoft AD format.

            Args:
                unified_acl: Unified ACL representation

            Returns:
                FlextResult containing AD format string or error

            """
            try:
                # Basic Microsoft AD ACL format conversion
                target_str = FlextLdapAclParsers.MicrosoftAdConverter.format_ad_target(
                    unified_acl.target,
                )
                subject_str = (
                    FlextLdapAclParsers.MicrosoftAdConverter.format_ad_subject(
                        unified_acl.subject,
                    )
                )
                permissions_str = (
                    FlextLdapAclParsers.MicrosoftAdConverter.format_ad_permissions(
                        unified_acl.permissions,
                    )
                )

                # Microsoft AD format: (target)(subject)(permissions)
                ad_acl = f"({target_str})({subject_str})({permissions_str})"

                return FlextResult[str].ok(ad_acl)

            except Exception as e:
                return FlextResult[str].fail(f"Microsoft AD conversion failed: {e}")

        @staticmethod
        def format_ad_target(target: FlextLdapModels.AclTarget) -> str:
            """Format target for Microsoft AD."""
            if target.attributes:
                attrs = ",".join(target.attributes)
                return f'target="ldap:///{target.dn_pattern};{attrs}"'
            return f'target="ldap:///{target.dn_pattern}"'

        @staticmethod
        def format_ad_subject(subject: FlextLdapModels.AclSubject) -> str:
            """Format subject for Microsoft AD."""
            if subject.subject_type == "user":
                return f'userdn="{subject.subject_dn}"'
            if subject.subject_type == "group":
                return f'groupdn="{subject.subject_dn}"'
            if subject.subject_type == "anyone":
                return 'userdn="ldap:///anyone"'
            return f'userdn="{subject.subject_dn}"'

        @staticmethod
        def format_ad_permissions(permissions: FlextLdapModels.AclPermissions) -> str:
            """Format permissions for Microsoft AD."""
            if permissions.grant_type == "deny":
                perms_str = ",".join(permissions.denied_permissions)
                return f"deny({perms_str})"
            perms_str = ",".join(permissions.permissions)
            return f"allow({perms_str})"

    class OpenLdapConverter:
        """Convert unified ACL format to OpenLDAP format."""

        @staticmethod
        def from_unified(
            unified_acl: FlextLdapModels.Acl,
        ) -> FlextResult[str]:
            """Convert unified ACL to OpenLDAP format.

            Args:
                unified_acl: Unified ACL representation

            Returns:
                FlextResult containing OpenLDAP format string or error

            """
            try:
                target_str = (
                    FlextLdapAclParsers.OpenLdapConverter.format_openldap_target(
                        unified_acl.target,
                    )
                )
                subject_str = (
                    FlextLdapAclParsers.OpenLdapConverter.format_openldap_subject(
                        unified_acl.subject,
                    )
                )
                permissions_str = (
                    FlextLdapAclParsers.OpenLdapConverter.format_openldap_permissions(
                        unified_acl.permissions,
                    )
                )

                acl = f"access to {target_str} by {subject_str} {permissions_str}"
                return FlextResult[str].ok(acl)

            except Exception as e:
                return FlextResult[str].fail(f"OpenLDAP conversion failed: {e}")

        @staticmethod
        def format_openldap_target(target: FlextLdapModels.AclTarget) -> str:
            """Format target for OpenLDAP."""
            if target.attributes:
                attrs = ",".join(target.attributes)
                return f"attrs={attrs}"
            if target.dn_pattern and target.dn_pattern != "*":
                return f'dn.exact="{target.dn_pattern}"'
            return "*"

        @staticmethod
        def format_openldap_subject(subject: FlextLdapModels.AclSubject) -> str:
            """Format subject for OpenLDAP."""
            if subject.subject_type == "self":
                return "self"
            if subject.subject_type == "authenticated":
                return "users"
            if subject.subject_type == "anonymous":
                return "anonymous"
            if subject.subject_type == "anyone":
                return "*"
            return subject.subject_dn

        @staticmethod
        def format_openldap_permissions(
            permissions: FlextLdapModels.AclPermissions,
        ) -> str:
            """Format permissions for OpenLDAP."""
            if permissions.grant_type == "deny":
                # OpenLDAP uses "none" for deny
                return "none"
            return ",".join(permissions.permissions)

    class AciConverter:
        """Convert unified ACL format to ACI (389 DS/Apache DS) format."""

        @staticmethod
        def from_unified(
            unified_acl: FlextLdapModels.Acl,
        ) -> FlextResult[str]:
            """Convert unified ACL to ACI format.

            Args:
                unified_acl: Unified ACL representation

            Returns:
                FlextResult containing ACI format string or error

            """
            try:
                # ACI format: (target)(v3.0; acl "name"; allow/deny (perms) subj;)
                target_str = FlextLdapAclParsers.AciConverter.format_aci_target(
                    unified_acl.target,
                )
                subject_str = FlextLdapAclParsers.AciConverter.format_aci_subject(
                    unified_acl.subject,
                )
                permissions_str = (
                    FlextLdapAclParsers.AciConverter.format_aci_permissions(
                        unified_acl.permissions,
                    )
                )
                gt = unified_acl.permissions.grant_type
                nm = unified_acl.name
                ps = permissions_str
                ss = subject_str
                acl = f'(target="{target_str})(v3.0; acl "{nm}"; {gt} ({ps}) {ss};)'
                return FlextResult[str].ok(acl)

            except Exception as e:
                return FlextResult[str].fail(f"ACI conversion failed: {e}")

        @staticmethod
        def format_aci_target(target: FlextLdapModels.AclTarget) -> str:
            """Format target for ACI."""
            return target.dn_pattern or "*"

        @staticmethod
        def format_aci_subject(subject: FlextLdapModels.AclSubject) -> str:
            """Format subject for ACI."""
            if subject.subject_type == "group":
                return f'groupdn="{subject.subject_dn}"'
            if subject.subject_type == "anyone":
                return 'userdn="ldap:///anyone"'
            return f'userdn="{subject.subject_dn}"'

        @staticmethod
        def format_aci_permissions(permissions: FlextLdapModels.AclPermissions) -> str:
            """Format permissions for ACI."""
            if permissions.grant_type == "deny":
                return ",".join(permissions.denied_permissions)
            return ",".join(permissions.permissions)

    def handle(self, message: object) -> FlextResult[FlextResult[object]]:
        """Handle ACL parsing operations with proper type safety."""
        try:
            # Type-safe message handling
            if not isinstance(message, dict):
                return FlextResult[FlextResult[object]].fail(
                    "Message must be a dictionary",
                )

            format_type_raw = message.get(
                FlextLdapConstants.LdapDictKeys.FORMAT,
                FlextLdapConstants.AclFormat.AUTO,
            )
            acl_string_raw = message.get(FlextLdapConstants.LdapDictKeys.ACL_STRING)

            format_type: str = (
                FlextLdapConstants.AclFormat.AUTO
                if not isinstance(format_type_raw, str)
                else format_type_raw
            )

            if not isinstance(acl_string_raw, str):
                return FlextResult[FlextResult[object]].fail(
                    "ACL string must be provided",
                )
            acl_string: str = acl_string_raw

            if not acl_string:
                return FlextResult[FlextResult[object]].fail(
                    "ACL string must be provided",
                )

            if not isinstance(format_type, str):
                format_type = FlextLdapConstants.AclFormat.AUTO

            # Route to appropriate parser based on format type
            if format_type == FlextLdapConstants.AclFormat.OPENLDAP:
                result = self.OpenLdapAclParser.parse(acl_string)
            elif format_type == FlextLdapConstants.AclFormat.ORACLE:
                result = self.OracleAclParser.parse(acl_string)
            elif format_type == FlextLdapConstants.AclFormat.ACI:
                result = self.AciParser.parse(acl_string)
            else:
                return FlextResult[FlextResult[object]].fail(
                    f"Unsupported ACL format: {format_type}",
                )

            # Wrap the result in another FlextResult to match expected return type
            wrapped_result = FlextResult[object].ok(
                result.unwrap() if result.is_success else None,
            )
            return FlextResult[FlextResult[object]].ok(wrapped_result)

        except Exception as e:
            return FlextResult[FlextResult[object]].fail(f"ACL parsing failed: {e}")


__all__ = ["FlextLdapAclParsers"]
