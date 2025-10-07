"""OpenLDAP 1.x server operations implementation.

Complete implementation for OpenLDAP 1.x (slapd.conf style) with access ACLs.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import override

from flext_core import FlextResult, FlextTypes
from flext_ldif import FlextLdifModels

from flext_ldap.servers.openldap2_operations import FlextLdapServersOpenLDAP2Operations


class FlextLdapServersOpenLDAP1Operations(FlextLdapServersOpenLDAP2Operations):
    """Complete OpenLDAP 1.x operations implementation.

    OpenLDAP 1.x Features:
    - slapd.conf static configuration (not cn=config)
    - access ACL attribute (not olcAccess)
    - Inherits most operations from OpenLDAP 2.x
    - Different ACL syntax (access to ... by ...)
    - Legacy objectClass support
    - Different replication mechanisms (slurpd vs syncrepl)
    """

    def __init__(self) -> None:
        """Initialize OpenLDAP 1.x operations."""
        super().__init__()
        self._server_type = "openldap1"

    @override
    def get_default_port(self, use_ssl: bool = False) -> int:
        """OpenLDAP 1.x uses standard LDAP ports."""
        return 636 if use_ssl else 389

    @override
    def get_schema_dn(self) -> str:
        """OpenLDAP 1.x schema location (subschemaSubentry)."""
        return "cn=Subschema"

    @override
    def get_acl_attribute_name(self) -> str:
        """OpenLDAP 1.x uses access attribute in slapd.conf."""
        return "access"

    @override
    def get_acl_format(self) -> str:
        """OpenLDAP 1.x ACL format identifier."""
        return "openldap1"

    @override
    def parse_acl(self, acl_string: str) -> FlextResult[FlextTypes.Dict]:
        """Parse access ACL string for OpenLDAP 1.x.

        OpenLDAP 1.x ACL format (slapd.conf):
        access to <what> by <who> <access> [by <who> <access>...]

        Examples:
        - access to * by self write by anonymous auth by * read
        - access to attrs=userPassword by self write by anonymous auth by * none
        - access to dn.subtree="ou=people,dc=example,dc=com" by self write

        Args:
            acl_string: access ACL string

        Returns:
            FlextResult containing parsed ACL with structure:
            {
                "raw": original string,
                "format": "openldap1",
                "server_type": "openldap1",
                "to": what clause,
                "rules": [{"who": subject, "access": level}, ...]
            }

        """
        try:
            acl_dict: FlextTypes.Dict = {
                "raw": acl_string,
                "format": "openldap1",
                "server_type": "openldap1",
            }

            # Parse OpenLDAP 1.x syntax: access to <what> by <who> <access>
            if acl_string.startswith("access to "):
                remainder = acl_string[10:]  # Skip "access to "

                # Split into "to" clause and "by" clauses
                by_split = remainder.split(" by ", 1)
                acl_dict["to"] = by_split[0].strip()

                if len(by_split) > 1:
                    # Parse multiple "by <who> <access>" rules
                    by_rules = by_split[1]
                    rules: list[FlextTypes.StringDict] = []

                    # Split by " by " to get individual rules
                    for rule in by_rules.split(" by "):
                        rule = rule.strip()
                        if rule:
                            # Each rule is "<who> <access>"
                            parts = rule.rsplit(" ", 1)
                            if len(parts) == 2:
                                rules.append({
                                    "who": parts[0].strip(),
                                    "access": parts[1].strip(),
                                })
                            else:
                                # Handle rule without explicit access level
                                rules.append({
                                    "who": rule,
                                    "access": "read",  # Default
                                })

                    acl_dict["rules"] = rules
                    # Keep legacy "by" field for backward compatibility
                    acl_dict["by"] = by_rules

            return FlextResult[FlextTypes.Dict].ok(acl_dict)

        except Exception as e:
            return FlextResult[FlextTypes.Dict].fail(
                f"OpenLDAP 1.x ACL parse failed: {e}"
            )

    @override
    def format_acl(self, acl_dict: FlextTypes.Dict) -> FlextResult[str]:
        """Format ACL dict to access string for OpenLDAP 1.x.

        Args:
            acl_dict: ACL dictionary with structure:
            {
                "to": what clause,
                "rules": [{"who": subject, "access": level}, ...],
                OR "by": legacy by clause string
            }

        Returns:
            FlextResult containing formatted ACL string

        Examples:
            - access to * by self write by * read
            - access to attrs=userPassword by self write

        """
        try:
            # Use raw if available
            if "raw" in acl_dict:
                return FlextResult[str].ok(str(acl_dict["raw"]))

            parts = ["access"]

            # Add "to" clause
            if "to" in acl_dict:
                parts.append(f"to {acl_dict['to']}")
            else:
                parts.append("to *")  # Default

            # Add "by" clauses from structured rules
            if "rules" in acl_dict:
                for rule in acl_dict["rules"]:
                    who = rule.get(FlextLdapConstants.DictKeys.WHO, "*")
                    access = rule.get(FlextLdapConstants.DictKeys.ACCESS, "read")
                    parts.append(f"by {who} {access}")
            # Fallback to legacy "by" string
            elif "by" in acl_dict:
                parts.append(f"by {acl_dict['by']}")
            else:
                # Default ACL
                parts.append("by * read")

            return FlextResult[str].ok(" ".join(parts))

        except Exception as e:
            return FlextResult[str].fail(f"OpenLDAP 1.x ACL format failed: {e}")

    @override
    def normalize_entry(
        self, entry: FlextLdifModels.Entry
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Normalize entry for OpenLDAP 1.x specifics.

        OpenLDAP 1.x Considerations:
        - Supports standard objectClasses but may have legacy classes
        - Uses access ACLs instead of olcAccess
        - Schema extensions via slapd.conf include directives

        Args:
            entry: FlextLdif Entry to normalize

        Returns:
            FlextResult containing normalized entry

        """
        try:
            # Access entry attributes
            attributes_dict = entry.attributes.attributes.copy()

            # Convert olcAccess to access if present (from 2.x migration)
            if "olcAccess" in attributes_dict:
                olc_access = attributes_dict.pop("olcAccess")
                attributes_dict["access"] = olc_access

            # Ensure objectClass compatibility
            if "objectClass" in attributes_dict:
                object_class_attr = attributes_dict["objectClass"]
                object_classes = object_class_attr.values

                # Map 2.x config objectClasses to 1.x equivalents
                mapped_classes = []
                for oc in object_classes:
                    if oc == "olcDatabaseConfig":
                        # 1.x doesn't use olc* objectClasses
                        continue
                    if oc.startswith("olc"):
                        # Remove olc prefix for 1.x compatibility
                        mapped_classes.append(oc[3:] if len(oc) > 3 else oc)
                    else:
                        mapped_classes.append(oc)

                if mapped_classes:
                    # Update objectClass with mapped values
                    attributes_dict["objectClass"] = FlextLdifModels.AttributeValues(
                        values=mapped_classes
                    )

            # Create normalized entry
            normalized_attributes = FlextLdifModels.LdifAttributes(
                attributes=attributes_dict
            )
            normalized_entry = FlextLdifModels.Entry(
                dn=entry.dn, attributes=normalized_attributes
            )

            return FlextResult[FlextLdifModels.Entry].ok(normalized_entry)

        except Exception as e:
            return FlextResult[FlextLdifModels.Entry].fail(
                f"OpenLDAP 1.x entry normalization failed: {e}"
            )

    def get_config_style(self) -> str:
        """Get configuration style for OpenLDAP 1.x.

        Returns:
            "slapd.conf" - static file configuration

        """
        return "slapd.conf"

    def get_replication_mechanism(self) -> str:
        """Get replication mechanism for OpenLDAP 1.x.

        Returns:
            "slurpd" - legacy replication daemon

        """
        return "slurpd"

    def supports_dynamic_config(self) -> bool:
        """Check if server supports dynamic configuration.

        OpenLDAP 1.x uses static slapd.conf, not cn=config.

        Returns:
            False - requires restart for config changes

        """
        return False
