"""OpenLDAP 1.x server operations implementation.

Complete implementation for OpenLDAP 1.x (slapd.conf style) with access ACLs.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import cast, override

from flext_core import FlextResult
from flext_ldif import FlextLdifModels
from ldap3 import Connection

from flext_ldap.constants import FlextLdapConstants
from flext_ldap.servers.openldap2_operations import FlextLdapServersOpenLDAP2Operations


class FlextLdapServersOpenLDAP1Operations(FlextLdapServersOpenLDAP2Operations):
    """Complete OpenLDAP 1.x operations implementation.

    OpenLDAP 1.x Features:
    - slapd.conf static configuration (not cn=config)
    - access ACL attribute (not olcAccess)
    - Inherits most operations from OpenLDAP 2.x
    - Different ACL syntax (access to... by...)
    - OpenLDAP 1.x objectClass support
    - Different replication mechanisms (slurpd vs syncrepl)
    """

    def __init__(self) -> None:
        """Initialize OpenLDAP 1.x operations."""
        super().__init__()
        self._server_type = FlextLdapConstants.ServerTypes.OPENLDAP1

    # --------------------------------------------------------------------- #
    # INHERITED METHODS (from FlextLdapServersOpenLDAP2Operations)
    # --------------------------------------------------------------------- #
    # These methods are inherited from OpenLDAP 2.x with minimal differences:
    # - get_default_port(): Returns 389 (standard LDAP port)
    # - supports_start_tls(): Returns True (standard LDAP feature)
    # - get_bind_mechanisms(): Returns OpenLDAP-specific bind mechanisms
    # - get_schema_dn(): Returns "cn=subschema" (OpenLDAP standard)
    # - discover_schema(): OpenLDAP-specific schema discovery
    # - parse_object_class(): OpenLDAP-specific objectClass parsing
    # - parse_attribute_type(): OpenLDAP-specific attributeType parsing
    # - get_acl_format(): Returns "openldap1" (OpenLDAP 1.x format)
    # - get_acls(): OpenLDAP-specific ACL retrieval
    # - set_acls(): OpenLDAP-specific ACL setting
    # - add_entry(): Generic entry addition
    # - modify_entry(): Generic entry modification
    # - delete_entry(): Generic entry deletion
    # - get_max_page_size(): Returns 1000 (standard page size)
    # - supports_paged_results(): Returns True (standard LDAP feature)
    # - supports_vlv(): Returns False (OpenLDAP VLV support limited)
    # - search_with_paging(): Generic paged search implementation
    # - get_supported_controls(): OpenLDAP-specific supported controls
    # - normalize_entry_for_server(): Generic entry normalization
    # - validate_entry_for_server(): OpenLDAP-specific entry validation
    #
    # --------------------------------------------------------------------- #
    # OVERRIDDEN METHODS (from FlextLdapServersOpenLDAP2Operations)
    # --------------------------------------------------------------------- #
    # These methods override the parent class with OpenLDAP 1.x-specific logic:
    # - get_acl_attribute_name(): Returns "access" (OpenLDAP 1.x ACL attribute)
    # - parse(): OpenLDAP 1.x-specific ACL parsing (access directive format)
    # - format_acl(): OpenLDAP 1.x-specific ACL formatting (access directive format)
    # - normalize_entry(): OpenLDAP 1.x-specific entry normalization
    # - get_config_style(): Returns "slapd.conf" (OpenLDAP 1.x config style)
    # - get_replication_mechanism(): Returns "slurpd" (OpenLDAP 1.x replication)
    # - supports_dynamic_config(): Returns False (OpenLDAP 1.x uses slapd.conf)
    # - get_root_dse_attributes(): OpenLDAP 1.x-specific Root DSE retrieval
    # - detect_server_type_from_root_dse(): OpenLDAP 1.x server detection logic

    # get_default_port() - Use base implementation

    @override
    def get_schema_dn(self) -> str:
        """OpenLDAP 1.x schema location (subschemaSubentry)."""
        return FlextLdapConstants.SyntheticDns.SUBS_SCHEMA_ALT

    @override
    def get_acl_attribute_name(self) -> str:
        """OpenLDAP 1.x uses access attribute in slapd.conf."""
        return FlextLdapConstants.AclAttributes.ACCESS

    @override
    def get_acl_format(self) -> str:
        """OpenLDAP 1.x ACL format identifier."""
        return "openldap1"

    @override
    def parse(self, acl_string: str) -> FlextResult[FlextLdifModels.Entry]:
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
                FlextLdapConstants.AclAttributes.RAW: original string,
                FlextLdapConstants.AclAttributes.FORMAT: FlextLdapConstants.AclFormat.OPENLDAP1,
                FlextLdapConstants.AclAttributes.SERVER_TYPE: FlextLdapConstants.ServerTypes.OPENLDAP1,
                "to": what clause,
                "rules": [{"who": subject, "access": level}, ...]
            }

        """
        try:
            acl_attributes: dict[str, list[str] | str] = {
                FlextLdapConstants.AclAttributes.RAW: [acl_string],
                FlextLdapConstants.AclAttributes.FORMAT: [
                    FlextLdapConstants.AclFormat.OPENLDAP1,
                ],
                FlextLdapConstants.AclAttributes.SERVER_TYPE_ALT: [
                    FlextLdapConstants.ServerTypes.OPENLDAP1,
                ],
            }

            # Parse OpenLDAP 1.x syntax: access to <what> by <who> <access>
            if acl_string.startswith(
                FlextLdapConstants.AclSyntaxKeywords.ACCESS_TO + " ",
            ):
                remainder = acl_string[
                    len(FlextLdapConstants.AclSyntaxKeywords.ACCESS_TO) + 1 :
                ]  # Skip "access to "

                # Split into "to" clause and "by" clauses
                by_split = remainder.split(
                    f" {FlextLdapConstants.AclSyntaxKeywords.BY} ",
                    1,
                )
                to_clause = by_split[0].strip()
                acl_attributes[FlextLdapConstants.AclAttributes.TO] = [to_clause]

                if len(by_split) > 1:
                    # Parse multiple "by <who> <access>" rules
                    by_rules = by_split[1]
                    rules_list: list[str] = []

                    # Split by " by " to get individual rules
                    for rule in by_rules.split(" by "):
                        rule_stripped = rule.strip()
                        if rule_stripped:
                            # Each rule is "<who> <access>"
                            parts = rule.rsplit(" ", 1)
                            if (
                                len(parts)
                                == FlextLdapConstants.AclParsing.ACL_RULE_PARTS
                            ):
                                rules_list.append(
                                    f"{parts[0].strip()}:{parts[1].strip()}",
                                )
                            else:
                                # Handle rule without explicit access level
                                rules_list.append(f"{rule_stripped}:read")

                    if rules_list:
                        acl_attributes[FlextLdapConstants.AclAttributes.RULES] = (
                            rules_list
                        )
                    acl_attributes[FlextLdapConstants.AclAttributes.BY] = [by_rules]

            # Use Entry.create() instead of LdifAttributes.create() + Entry()
            entry_result = FlextLdifModels.Entry.create(
                dn=FlextLdapConstants.SyntheticDns.ACL_RULE,
                attributes=acl_attributes,
            )
            if entry_result.is_failure:
                return FlextResult[FlextLdifModels.Entry].fail(
                    f"Failed to create ACL entry: {entry_result.error}",
                )
            return entry_result

        except Exception as e:
            return FlextResult[FlextLdifModels.Entry].fail(
                f"OpenLDAP 1.x ACL parse failed: {e}",
            )

    @override
    def format_acl(self, acl_entry: FlextLdifModels.Entry) -> FlextResult[str]:
        """Format ACL Entry to access string for OpenLDAP 1.x.

        Args:
            acl_entry: ACL Entry with attributes containing structure:
                {
                    "to": what clause,
                    "rules": [{"who": subject, "access": level}, ...],
                    OR "by": by clause string
                }

        Returns:
            FlextResult containing formatted ACL string

        Examples:
            - access to * by self write by * read
            - access to attrs=userPassword by self write

        """
        try:
            # Extract attributes from entry
            raw_attr = acl_entry.attributes.get(FlextLdapConstants.AclAttributes.RAW)
            if raw_attr and len(raw_attr) > 0:
                return FlextResult[str].ok(raw_attr[0])

            parts = [
                FlextLdapConstants.AclSyntaxKeywords.ACCESS_TO.split()[0],
            ]  # "access"

            # Add "to" clause
            to_attr = acl_entry.attributes.get(FlextLdapConstants.AclAttributes.TO)
            if to_attr and len(to_attr) > 0:
                parts.append(f"to {to_attr[0]}")
            else:
                parts.append("to *")  # Default

            # Add "by" clauses from structured rules
            rules_attr = acl_entry.attributes.get(
                FlextLdapConstants.AclAttributes.RULES,
            )
            if rules_attr:
                for rule_str in rules_attr:
                    if ":" in rule_str:
                        who, access = rule_str.split(":", 1)
                        parts.append(f"by {who} {access}")
                    else:
                        parts.append(f"by {rule_str}")
            else:
                # Fallback to "by" string
                by_attr = acl_entry.attributes.get(FlextLdapConstants.AclAttributes.BY)
                if by_attr and len(by_attr) > 0:
                    parts.append(f"by {by_attr[0]}")
                else:
                    # Default ACL
                    parts.append("by * read")

            return FlextResult[str].ok(" ".join(parts))

        except Exception as e:
            return FlextResult[str].fail(f"OpenLDAP 1.x ACL format failed: {e}")

    @override
    def normalize_entry(
        self,
        entry: FlextLdifModels.Entry,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Normalize entry for OpenLDAP 1.x specifics.

        OpenLDAP 1.x Considerations:
        - Supports standard objectClasses and OpenLDAP 1.x classes
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
            if FlextLdapConstants.AclAttributes.OLC_ACCESS in attributes_dict:
                olc_access = attributes_dict.pop(
                    FlextLdapConstants.AclAttributes.OLC_ACCESS,
                )
                attributes_dict[FlextLdapConstants.AclAttributes.ACCESS] = olc_access

            # Map objectClasses for OpenLDAP 1.x format
            if FlextLdapConstants.LdapAttributeNames.OBJECT_CLASS in attributes_dict:
                object_class_attr = attributes_dict[
                    FlextLdapConstants.LdapAttributeNames.OBJECT_CLASS
                ]
                # object_class_attr is already a list, don't call .values
                object_classes = (
                    object_class_attr
                    if isinstance(object_class_attr, list)
                    else [object_class_attr]
                )

                # Map 2.x config objectClasses to 1.x equivalents
                mapped_classes = []
                for oc in object_classes:
                    oc_str = str(oc)
                    if oc_str == "olcDatabaseConfig":
                        # 1.x doesn't use olc* objectClasses
                        continue
                    if oc_str.startswith("olc"):
                        # Remove olc prefix for OpenLDAP 1.x format
                        prefix_len = (
                            FlextLdapConstants.AclParsing.OPENLDAP_PREFIX_LENGTH
                        )
                        min_len = FlextLdapConstants.AclParsing.MIN_OC_LENGTH
                        mapped_classes.append(
                            oc_str[prefix_len:] if len(oc_str) > min_len else oc_str,
                        )
                    else:
                        mapped_classes.append(oc_str)

                if mapped_classes:
                    # Update objectClass with mapped values (use list directly)
                    attributes_dict[
                        FlextLdapConstants.LdapAttributeNames.OBJECT_CLASS
                    ] = mapped_classes

            # Use Entry.create() instead of constructing Entry directly
            normalized_entry_result = FlextLdifModels.Entry.create(
                dn=str(entry.dn),
                attributes=cast("dict[str, list[str] | str]", attributes_dict),
            )
            if normalized_entry_result.is_failure:
                return FlextResult[FlextLdifModels.Entry].fail(
                    f"Failed to create normalized entry: {normalized_entry_result.error}",
                )
            return normalized_entry_result

        except Exception as e:
            return FlextResult[FlextLdifModels.Entry].fail(
                f"OpenLDAP 1.x entry normalization failed: {e}",
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
            "slurpd" - replication daemon for OpenLDAP 1.x

        """
        return "slurpd"

    def supports_dynamic_config(self) -> bool:
        """Check if server supports dynamic configuration.

        OpenLDAP 1.x uses static slapd.conf, not cn=config.

        Returns:
        False - requires restart for config changes

        """
        return False

    @override
    def get_root_dse_attributes(
        self,
        connection: Connection,
    ) -> FlextResult[dict[str, object]]:
        """Get Root DSE attributes for OpenLDAP 1.x server."""
        try:
            # Use standard Root DSE search
            result = connection.search(
                search_base="",
                search_filter=FlextLdapConstants.Filters.ALL_ENTRIES_FILTER,
                search_scope=cast(
                    "FlextLdapConstants.Types.Ldap3Scope",
                    FlextLdapConstants.Scopes.BASE_LDAP3,
                ),
                attributes=["*"],
                size_limit=1,
            )

            if result and connection.entries:
                # Extract attributes from the first entry
                entry = connection.entries[0]
                attrs = {}
                for attr in entry.entry_attributes:
                    attrs[attr] = entry[attr].value
                return FlextResult[dict[str, object]].ok(attrs)

            return FlextResult[dict[str, object]].fail("No Root DSE found")

        except Exception as e:
            return FlextResult[dict[str, object]].fail(
                f"Root DSE retrieval failed: {e}",
            )

    @override
    def detect_server_type_from_root_dse(self, _root_dse: dict[str, object]) -> str:
        """Detect OpenLDAP version from Root DSE attributes."""
        # Check for vendorName
        if FlextLdapConstants.RootDseAttributes.VENDOR_NAME in _root_dse:
            vendor = str(
                _root_dse[FlextLdapConstants.RootDseAttributes.VENDOR_NAME],
            ).lower()
            if FlextLdapConstants.VendorNames.OPENLDAP in vendor:
                # Check for version to distinguish 1.x from 2.x
                if FlextLdapConstants.RootDseAttributes.VENDOR_VERSION in _root_dse:
                    version = str(
                        _root_dse[FlextLdapConstants.RootDseAttributes.VENDOR_VERSION],
                    ).lower()
                    if version.startswith(
                        FlextLdapConstants.VersionPrefixes.VERSION_1_PREFIX,
                    ):
                        return FlextLdapConstants.ServerTypes.OPENLDAP1
                    if version.startswith(
                        FlextLdapConstants.VersionPrefixes.VERSION_2_PREFIX,
                    ):
                        return FlextLdapConstants.ServerTypes.OPENLDAP2
                # Default to 2.x if version unclear
                return FlextLdapConstants.ServerTypes.OPENLDAP2

        # Fallback: check for configContext (2.x feature)
        if FlextLdapConstants.RootDseAttributes.CONFIG_CONTEXT in _root_dse:
            return FlextLdapConstants.ServerTypes.OPENLDAP2

        # Default to 1.x if no clear indicators
        return FlextLdapConstants.ServerTypes.OPENLDAP1

    @override
    def get_supported_controls(self, connection: Connection) -> FlextResult[list[str]]:
        """Get supported controls for OpenLDAP 1.x server."""
        try:
            if not connection or not connection.bound:
                return FlextResult[list[str]].fail("Connection not bound")

            # OpenLDAP 1.x standard controls
            openldap1_controls = [
                "1.2.840.113556.1.4.319",  # pagedResults (limited support)
                "2.16.840.1.113730.3.4.2",  # ManageDsaIT
                "1.3.6.1.4.1.1466.20037",  # StartTLS
            ]

            return FlextResult[list[str]].ok(openldap1_controls)

        except Exception as e:
            return FlextResult[list[str]].fail(f"Control retrieval failed: {e}")

    @override
    def normalize_entry_for_server(
        self,
        entry: FlextLdifModels.Entry,
        _target_server_type: str | None = None,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Normalize entry for OpenLDAP 1.x server specifics.

        Applies OpenLDAP 1.x-specific transformations:
        - Convert olcAccess to access ACLs
        - Map 2.x objectClasses to 1.x equivalents
        - Remove cn=config specific attributes

        Args:
        entry: Entry to normalize (accepts both LDAP and LDIF entry types)

        Returns:
        FlextResult containing normalized entry

        """
        # Entry is already FlextLdifModels.Entry, use it directly
        ldif_entry = entry

        # Reuse existing normalize_entry method which handles OpenLDAP 1.x specifics
        normalize_result = self.normalize_entry(ldif_entry)
        if normalize_result.is_failure:
            return FlextResult[FlextLdifModels.Entry].fail(normalize_result.error)

        # Get normalized entry
        normalized_ldif_entry = normalize_result.unwrap()

        # Return normalized entry directly (no cast needed)
        return FlextResult[FlextLdifModels.Entry].ok(normalized_ldif_entry)

    @override
    def validate_entry_for_server(
        self,
        entry: FlextLdifModels.Entry,
        _server_type: str | None = None,
    ) -> FlextResult[bool]:
        """Validate entry for OpenLDAP 1.x server.

        Checks:
        - Entry has DN
        - Entry has attributes
        - Entry has objectClass
        - No 2.x-specific objectClasses (olc*)
        - No cn=config attributes

        Args:
        entry: Entry to validate

        Returns:
        FlextResult[bool] indicating validation success

        """
        try:
            # Basic validation
            if not entry.dn:
                return FlextResult[bool].fail("Entry must have a DN")

            if not entry.attributes or not entry.attributes.attributes:
                return FlextResult[bool].fail("Entry must have attributes")

            # Check for objectClass
            attrs = entry.attributes.attributes
            if FlextLdapConstants.LdapAttributeNames.OBJECT_CLASS not in attrs:
                return FlextResult[bool].fail("Entry must have objectClass attribute")

            # OpenLDAP 1.x specific: reject olc* objectClasses
            object_class_attr = attrs[
                FlextLdapConstants.LdapAttributeNames.OBJECT_CLASS
            ]
            # object_class_attr is already a list, don't call .values
            object_classes = (
                object_class_attr
                if isinstance(object_class_attr, list)
                else [object_class_attr]
            )
            for oc in object_classes:
                oc_str = str(oc)
                if oc_str.startswith("olc"):
                    return FlextResult[bool].fail(
                        f"OpenLDAP 2.x objectClass '{oc_str}' not supported in 1.x",
                    )

            # Warn about access ACL format
            if FlextLdapConstants.AclAttributes.OLC_ACCESS in attrs:
                return FlextResult[bool].fail(
                    "Use 'access' attribute for OpenLDAP 1.x ACLs, not 'olcAccess'",
                )

            return FlextResult[bool].ok(True)

        except Exception as e:
            return FlextResult[bool].fail(f"Entry validation failed: {e}")
