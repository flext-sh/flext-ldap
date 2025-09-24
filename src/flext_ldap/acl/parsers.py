"""ACL Parsers for FLEXT LDAP.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re
from typing import Final

from flext_core import FlextResult
from flext_ldap.acl.constants import FlextLdapAclConstants
from flext_ldap.models import FlextLdapModels


class FlextLdapAclParsers:
    """ACL parsers for different LDAP server formats."""

    class OpenLdapAclParser:
        """Parser for OpenLDAP ACL format.

        Format: access to <what> by <who> <access>
        Example: access to attrs=userPassword by self write by anonymous auth
        """

        ACCESS_PATTERN: Final[str] = r"access\s+to\s+(.+)\s+by\s+(.+)"
        MIN_BY_CLAUSE_PARTS: Final[int] = 2

        @classmethod
        def parse(cls, acl_line: str) -> FlextResult[FlextLdapModels.UnifiedAcl]:
            """Parse OpenLDAP ACL line to unified ACL."""
            if not acl_line or not acl_line.strip():
                return FlextResult[FlextLdapModels.UnifiedAcl].fail(
                    "ACL line cannot be empty"
                )

            access_match = re.match(cls.ACCESS_PATTERN, acl_line.strip())
            if not access_match:
                return FlextResult[FlextLdapModels.UnifiedAcl].fail(
                    f"Invalid OpenLDAP ACL format: {acl_line}"
                )

            target_spec = access_match.group(1)
            by_clauses_text = access_match.group(2)

            target_result = cls._parse_target(target_spec)
            if target_result.is_failure:
                return FlextResult[FlextLdapModels.UnifiedAcl].fail(
                    target_result.error or "Target parsing failed"
                )

            by_parts = by_clauses_text.strip().split()
            if len(by_parts) < cls.MIN_BY_CLAUSE_PARTS:
                return FlextResult[FlextLdapModels.UnifiedAcl].fail(
                    "Invalid by clause format"
                )

            by_clauses = [(by_parts[0], by_parts[1])]

            subject_result = cls._parse_subject(by_clauses[0][0])
            if subject_result.is_failure:
                return FlextResult[FlextLdapModels.UnifiedAcl].fail(
                    subject_result.error or "Subject parsing failed"
                )

            permissions_result = cls._parse_permissions(by_clauses[0][1])
            if permissions_result.is_failure:
                return FlextResult[FlextLdapModels.UnifiedAcl].fail(
                    permissions_result.error or "Permissions parsing failed"
                )

            return FlextLdapModels.UnifiedAcl.create(
                target=target_result.unwrap(),
                subject=subject_result.unwrap(),
                permissions=permissions_result.unwrap(),
                metadata={"source_format": FlextLdapAclConstants.AclFormat.OPENLDAP},
            )

        @classmethod
        def _parse_target(
            cls, target_spec: str
        ) -> FlextResult[FlextLdapModels.AclTarget]:
            """Parse OpenLDAP target specification."""
            dn_pattern = "*"
            attributes: list[str] = []
            filter_expr = ""
            scope = "subtree"

            if "attrs=" in target_spec:
                attr_match = re.search(r"attrs=([^\s]+)", target_spec)
                if attr_match:
                    attributes = attr_match.group(1).split(",")

            if "dn.exact=" in target_spec:
                dn_match = re.search(r'dn\.exact="([^"]+)"', target_spec)
                if dn_match:
                    dn_pattern = dn_match.group(1)

            if "filter=" in target_spec:
                filter_match = re.search(r"filter=(.+)", target_spec)
                if filter_match:
                    filter_expr = filter_match.group(1)

            target_type = (
                FlextLdapAclConstants.TargetType.ATTRIBUTES
                if attributes
                else FlextLdapAclConstants.TargetType.DN
            )

            return FlextLdapModels.AclTarget.create(
                target_type=target_type,
                dn_pattern=dn_pattern,
                attributes=attributes,
                filter_expression=filter_expr,
                scope=scope,
            )

        @classmethod
        def _parse_subject(
            cls, subject_spec: str
        ) -> FlextResult[FlextLdapModels.AclSubject]:
            """Parse OpenLDAP subject specification."""
            if subject_spec == "self":
                return FlextLdapModels.AclSubject.create(
                    subject_type=FlextLdapAclConstants.SubjectType.SELF,
                    identifier="self",
                )

            if subject_spec == "anonymous":
                return FlextLdapModels.AclSubject.create(
                    subject_type=FlextLdapAclConstants.SubjectType.ANONYMOUS,
                    identifier="anonymous",
                )

            if subject_spec == "users":
                return FlextLdapModels.AclSubject.create(
                    subject_type=FlextLdapAclConstants.SubjectType.AUTHENTICATED,
                    identifier="users",
                )

            if subject_spec.startswith("dn="):
                return FlextLdapModels.AclSubject.create(
                    subject_type=FlextLdapAclConstants.SubjectType.DN,
                    identifier=subject_spec[3:],
                )

            if subject_spec.startswith("group="):
                return FlextLdapModels.AclSubject.create(
                    subject_type=FlextLdapAclConstants.SubjectType.GROUP,
                    identifier=subject_spec[6:],
                )

            return FlextLdapModels.AclSubject.create(
                subject_type=FlextLdapAclConstants.SubjectType.DN,
                identifier=subject_spec,
            )

        @classmethod
        def _parse_permissions(
            cls, perm_spec: str
        ) -> FlextResult[FlextLdapModels.AclPermissions]:
            """Parse OpenLDAP permission specification."""
            perm_mapping = {
                "read": FlextLdapAclConstants.Permission.READ,
                "write": FlextLdapAclConstants.Permission.WRITE,
                "add": FlextLdapAclConstants.Permission.ADD,
                "delete": FlextLdapAclConstants.Permission.DELETE,
                "search": FlextLdapAclConstants.Permission.SEARCH,
                "compare": FlextLdapAclConstants.Permission.COMPARE,
                "auth": FlextLdapAclConstants.Permission.AUTH,
                "none": FlextLdapAclConstants.Permission.NONE,
            }

            permissions = [perm_mapping.get(perm_spec.lower(), perm_spec)]

            return FlextLdapModels.AclPermissions.create(
                permissions=permissions, grant_type="allow"
            )

    class OracleAclParser:
        """Parser for Oracle Directory ACL format.

        Format: access to attr=(...) by group="..." (read,write)
        """

        ORACLE_PATTERN: Final[str] = r"access\s+to\s+(.+?)\s+by\s+(.+?)\s*\((.+?)\)"

        @classmethod
        def parse(
            cls, orclaci_value: str
        ) -> FlextResult[FlextLdapModels.UnifiedAcl]:
            """Parse Oracle ACL to unified ACL."""
            if not orclaci_value or not orclaci_value.strip():
                return FlextResult[FlextLdapModels.UnifiedAcl].fail(
                    "Oracle ACL value cannot be empty"
                )

            match = re.match(cls.ORACLE_PATTERN, orclaci_value.strip())
            if not match:
                return FlextResult[FlextLdapModels.UnifiedAcl].fail(
                    f"Invalid Oracle ACL format: {orclaci_value}"
                )

            target_spec = match.group(1)
            subject_spec = match.group(2)
            perms_spec = match.group(3)

            target_result = cls._parse_target(target_spec)
            if target_result.is_failure:
                return FlextResult[FlextLdapModels.UnifiedAcl].fail(
                    target_result.error or "Target parsing failed"
                )

            subject_result = cls._parse_subject(subject_spec)
            if subject_result.is_failure:
                return FlextResult[FlextLdapModels.UnifiedAcl].fail(
                    subject_result.error or "Subject parsing failed"
                )

            permissions_result = cls._parse_permissions(perms_spec)
            if permissions_result.is_failure:
                return FlextResult[FlextLdapModels.UnifiedAcl].fail(
                    permissions_result.error or "Permissions parsing failed"
                )

            return FlextLdapModels.UnifiedAcl.create(
                target=target_result.unwrap(),
                subject=subject_result.unwrap(),
                permissions=permissions_result.unwrap(),
                metadata={"source_format": FlextLdapAclConstants.AclFormat.ORACLE},
            )

        @classmethod
        def _parse_target(
            cls, target_spec: str
        ) -> FlextResult[FlextLdapModels.AclTarget]:
            """Parse Oracle target specification."""
            if "attr=" in target_spec:
                attr_match = re.search(r"attr=\(([^)]+)\)", target_spec)
                if attr_match:
                    attrs = [a.strip() for a in attr_match.group(1).split(",")]
                    return FlextLdapModels.AclTarget.create(
                        target_type=FlextLdapAclConstants.TargetType.ATTRIBUTES,
                        attributes=attrs,
                    )

            if "entry" in target_spec:
                return FlextLdapModels.AclTarget.create(
                    target_type=FlextLdapAclConstants.TargetType.ENTRY
                )

            return FlextLdapModels.AclTarget.create(
                target_type=FlextLdapAclConstants.TargetType.DN
            )

        @classmethod
        def _parse_subject(
            cls, subject_spec: str
        ) -> FlextResult[FlextLdapModels.AclSubject]:
            """Parse Oracle subject specification."""
            if 'group="' in subject_spec:
                group_match = re.search(r'group="([^"]+)"', subject_spec)
                if group_match:
                    return FlextLdapModels.AclSubject.create(
                        subject_type=FlextLdapAclConstants.SubjectType.GROUP,
                        identifier=group_match.group(1),
                    )

            if 'user="' in subject_spec:
                user_match = re.search(r'user="([^"]+)"', subject_spec)
                if user_match:
                    return FlextLdapModels.AclSubject.create(
                        subject_type=FlextLdapAclConstants.SubjectType.USER,
                        identifier=user_match.group(1),
                    )

            return FlextLdapModels.AclSubject.create(
                subject_type=FlextLdapAclConstants.SubjectType.DN, identifier="*"
            )

        @classmethod
        def _parse_permissions(
            cls, perms_spec: str
        ) -> FlextResult[FlextLdapModels.AclPermissions]:
            """Parse Oracle permission specification."""
            perms = [p.strip() for p in perms_spec.split(",")]
            return FlextLdapModels.AclPermissions.create(
                permissions=perms, grant_type="allow"
            )

    class AciParser:
        """Parser for 389 DS/Apache DS ACI format.

        Format: (target)(version 3.0; acl "name"; allow (perms) userdn="...";)
        """

        ACI_PATTERN: Final[str] = (
            r'\(target\s*=\s*"([^"]+)"\)\s*'
            r'\(version\s+3\.0\s*;\s*acl\s+"([^"]+)"\s*;\s*'
            r"(allow|deny)\s*\(([^)]+)\)\s*"
            r"(.+?);?\s*\)"
        )

        @classmethod
        def parse(cls, aci_value: str) -> FlextResult[FlextLdapModels.UnifiedAcl]:
            """Parse ACI to unified ACL."""
            if not aci_value or not aci_value.strip():
                return FlextResult[FlextLdapModels.UnifiedAcl].fail(
                    "ACI value cannot be empty"
                )

            match = re.match(cls.ACI_PATTERN, aci_value.strip())
            if not match:
                return FlextResult[FlextLdapModels.UnifiedAcl].fail(
                    f"Invalid ACI format: {aci_value}"
                )

            target_dn = match.group(1)
            acl_name = match.group(2)
            grant_type = match.group(3)
            perms = match.group(4)
            bind_rules = match.group(5)

            target_result = FlextLdapModels.AclTarget.create(
                target_type=FlextLdapAclConstants.TargetType.DN, dn_pattern=target_dn
            )

            subject_result = cls._parse_bind_rules(bind_rules)
            if subject_result.is_failure:
                return FlextResult[FlextLdapModels.UnifiedAcl].fail(
                    subject_result.error or "Bind rules parsing failed"
                )

            perm_list = [p.strip() for p in perms.split(",")]
            permissions_result = FlextLdapModels.AclPermissions.create(
                permissions=perm_list if grant_type == "allow" else [],
                denied_permissions=perm_list if grant_type == "deny" else [],
                grant_type=grant_type,
            )

            return FlextLdapModels.UnifiedAcl.create(
                name=acl_name,
                target=target_result.unwrap(),
                subject=subject_result.unwrap(),
                permissions=permissions_result.unwrap(),
                metadata={"source_format": FlextLdapAclConstants.AclFormat.ACI},
            )

        @classmethod
        def _parse_bind_rules(
            cls, bind_rules: str
        ) -> FlextResult[FlextLdapModels.AclSubject]:
            """Parse ACI bind rules."""
            if 'userdn="' in bind_rules:
                dn_match = re.search(r'userdn="([^"]+)"', bind_rules)
                if dn_match:
                    return FlextLdapModels.AclSubject.create(
                        subject_type=FlextLdapAclConstants.SubjectType.DN,
                        identifier=dn_match.group(1),
                    )

            if 'groupdn="' in bind_rules:
                group_match = re.search(r'groupdn="([^"]+)"', bind_rules)
                if group_match:
                    return FlextLdapModels.AclSubject.create(
                        subject_type=FlextLdapAclConstants.SubjectType.GROUP,
                        identifier=group_match.group(1),
                    )

            return FlextLdapModels.AclSubject.create(
                subject_type=FlextLdapAclConstants.SubjectType.ANYONE, identifier="*"
            )


__all__ = ["FlextLdapAclParsers"]
