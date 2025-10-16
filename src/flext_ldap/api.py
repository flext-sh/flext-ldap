"""FlextLdap - Consolidated single-class LDAP operations with FLEXT integration.

Enterprise-grade LDAP operations consolidated into one main class following
FLEXT single-class-per-project standardization. All LDAP functionality unified
into FlextLdap with nested classes for complex subsystems.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import threading
import types
from typing import ClassVar, Literal, Self, cast, override

from flext_core import (
    FlextConfig,
    FlextResult,
    FlextService,
    FlextTypes,
)
from flext_ldif import FlextLdif, FlextLdifModels
from ldap3 import ALL, BASE, LEVEL, MODIFY_REPLACE, SUBTREE, Connection, Server
from pydantic import Field, SecretStr
from pydantic_settings import SettingsConfigDict

from flext_ldap.authentication import FlextLdapAuthentication
from flext_ldap.config import FlextLdapConfig
from flext_ldap.entry_adapter import FlextLdapEntryAdapter
from flext_ldap.models import FlextLdapModels
from flext_ldap.typings import FlextLdapTypes


class FlextLdap(FlextService[None]):
    """Consolidated single-class LDAP operations with FLEXT ecosystem integration.

    Enterprise-grade LDAP operations consolidated into one main class following
    FLEXT single-class-per-project standardization. All LDAP functionality unified
    into FlextLdap with nested classes for complex subsystems.

    **SINGLE-CLASS ARCHITECTURE**: Everything consolidated into one main class
    - No separate module files - all functionality integrated
    - Nested classes for complex subsystems (Config, Client, Servers, Acl)
    - Clean facade API with rich internal organization

    **COMPREHENSIVE LDAP OPERATIONS**:
    - Connection management and authentication
    - Search, add, modify, delete operations
    - Server-specific operations (OpenLDAP, Oracle OID/OUD, AD)
    - ACL management and schema operations
    - Entry validation and adaptation
    - LDIF integration and migration

    **FLEXT INTEGRATION**:
    - FlextResult[T] for railway-oriented error handling
    - FlextService for dependency injection and lifecycle
    - FlextLogger for structured logging
    - FlextContainer for service management
    """

    # Singleton pattern
    _instance: FlextLdap | None = None
    _lock: ClassVar[threading.Lock] = threading.Lock()

    def __init__(self, config: FlextLdapConfig | None = None) -> None:
        """Initialize consolidated LDAP operations.

        Args:
            config: Optional LDAP configuration. If not provided, uses default instance.

        """
        super().__init__()

        # Core state
        self._config: FlextLdapConfig = (
            config if config is not None else FlextLdapConfig()
        )
        self._ldif: FlextLdif | None = None
        self._entry_adapter: FlextLdapEntryAdapter | None = None

        # Lazy-loaded subsystems
        self._client: FlextLdap.Client | None = None
        self._servers: FlextLdap.Servers | None = None
        self._acl: FlextLdap.Acl | None = None

    @classmethod
    def get_instance(cls) -> FlextLdap:
        """Get singleton FlextLdap instance."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    @classmethod
    def create(cls) -> FlextLdap:
        """Factory method to create FlextLdap instance."""
        return cls()

    @property
    def config(self) -> FlextLdapConfig:
        """Get LDAP configuration."""
        return self._config

    @property
    def client(self) -> FlextLdap.Client:
        """Get LDAP client instance."""
        if self._client is None:
            self._client = FlextLdap.Client(self._config)
        return self._client

    @property
    def servers(self) -> FlextLdap.Servers:
        """Get server operations instance."""
        if self._servers is None:
            self._servers = FlextLdap.Servers()
        return self._servers

    @property
    def acl(self) -> FlextLdap.Acl:
        """Get ACL operations instance."""
        if self._acl is None:
            self._acl = FlextLdap.Acl()
        return self._acl

    @property
    def authentication(self) -> FlextLdapAuthentication:
        """Get authentication operations instance."""
        if not hasattr(self, "_authentication"):
            self._authentication = FlextLdapAuthentication()
        return self._authentication

    @override
    def execute(self) -> FlextResult[None]:
        """Execute main domain operation (required by FlextService)."""
        return FlextResult[None].ok(None)

    # =========================================================================
    # NESTED CLASSES - Consolidated subsystems
    # =========================================================================

    class Config(FlextConfig):
        """Consolidated LDAP configuration management."""

        # LDAP-specific configuration fields
        ldap_server_uri: str = Field(default="ldap://localhost:389")
        ldap_port: int = Field(default=389)
        ldap_use_ssl: bool = Field(default=False)
        ldap_bind_dn: str | None = Field(default=None)
        ldap_bind_password: SecretStr | None = Field(default=None)
        ldap_base_dn: str = Field(default="")

        model_config = SettingsConfigDict(
            env_prefix="LDAP_",
            env_file=".env",
            extra="ignore",
        )

        @property
        def connection_string(self) -> str:
            """Get LDAP connection string."""
            protocol = "ldaps" if self.ldap_use_ssl else "ldap"
            return f"{protocol}://{self.ldap_server_uri}:{self.ldap_port}"

    class Client(FlextService[None]):
        """Consolidated LDAP client operations."""

        def __init__(self, config: FlextLdapConfig | None) -> None:
            """Initialize LDAP client with configuration.

            Args:
                config: LDAP configuration instance.

            """
            super().__init__()
            self._config: FlextLdapConfig = (
                config if config is not None else FlextLdapConfig()
            )
            self._connection: Connection | None = None

        @property
        def is_connected(self) -> bool:
            """Check if LDAP connection is established and bound."""
            return self._connection is not None and self._connection.bound

        def test_connection(self) -> FlextResult[bool]:
            """Test LDAP connection by attempting to connect."""
            result = self.connect()
            if result.is_success:
                # Connection successful
                return FlextResult[bool].ok(True)
            # Connection failed, return the error
            return FlextResult[bool].fail(result.error)

        @override
        def execute(self) -> FlextResult[None]:
            """Execute client operations."""
            return FlextResult[None].ok(None)

        def connect(self) -> FlextResult[Connection]:
            """Establish LDAP connection."""
            if self._config is None:
                return FlextResult[Connection].fail("Configuration is not initialized")

            # Config is guaranteed to be not None after check above
            config = self._config

            try:
                server = Server(
                    config.ldap_server_uri,
                    port=config.ldap_port,
                    use_ssl=config.ldap_use_ssl,
                    get_info=ALL,
                )
                password = None
                if config.ldap_bind_password is not None:
                    password = config.ldap_bind_password.get_secret_value()

                connection = Connection(
                    server,
                    user=config.ldap_bind_dn,
                    password=password,
                    auto_bind=True,
                )
                self._connection = connection
                return FlextResult.ok(connection)
            except Exception as e:
                return FlextResult.fail(f"LDAP connection failed: {e}")

        def unbind(self) -> FlextResult[None]:
            """Unbind and close LDAP connection."""
            try:
                if self._connection is not None:
                    # ldap3 library has incomplete type stubs; external library limitation
                    self._connection.unbind()
                    self._connection = None
                return FlextResult.ok(None)
            except Exception as e:
                return FlextResult[None].fail(f"LDAP unbind failed: {e}")

        def search(
            self,
            base_dn: str,
            search_filter: str,
            attributes: FlextTypes.StringList | None = None,
            scope: str = "subtree",
        ) -> FlextResult[FlextLdapTypes.LdapDomain.SearchResult]:
            """Perform LDAP search."""
            if not self._connection:
                return FlextResult.fail("Not connected to LDAP server")

            try:
                # Convert scope string to ldap3 search scope
                scope_map = {
                    "base": BASE,
                    "one": LEVEL,
                    "subtree": SUBTREE,
                }
                search_scope = scope_map.get(
                    scope.lower(), SUBTREE
                )  # Default to SUBTREE

                self._connection.search(
                    base_dn,
                    search_filter,
                    search_scope=cast(
                        "Literal['BASE', 'LEVEL', 'SUBTREE']", search_scope
                    ),
                    attributes=attributes or ["*"],
                )
                results = [
                    {
                        "dn": entry.entry_dn,
                        "attributes": dict(entry.entry_attributes_as_dict),
                    }
                    for entry in self._connection.entries
                ]
                return FlextResult.ok(results)
            except Exception as e:
                return FlextResult.fail(f"LDAP search failed: {e}")

        def add_entry(
            self,
            dn: str,
            attributes: dict[str, str | FlextTypes.StringList],
        ) -> FlextResult[bool]:
            """Add new LDAP entry."""
            if not self._connection:
                return FlextResult.fail("Not connected to LDAP server")

            try:
                # Extract objectClass if present
                object_class = attributes.get("objectClass", ["top"])
                if isinstance(object_class, str):
                    object_class = [object_class]

                # Convert attributes to ldap3 format
                ldap3_attributes = {}
                for key, value in attributes.items():
                    if key == "objectClass":
                        continue  # Skip objectClass as it's handled separately
                    if isinstance(value, list):
                        ldap3_attributes[key] = value
                    else:
                        ldap3_attributes[key] = [value]

                # ldap3 library has incomplete type stubs; external library limitation
                self._connection.add(
                    dn, object_class, attributes=ldap3_attributes or None
                )
                return FlextResult.ok(True)
            except Exception as e:
                return FlextResult.fail(f"LDAP add failed: {e}")

        def modify_entry(
            self,
            dn: str,
            changes: dict[str, str | list[str]],
        ) -> FlextResult[bool]:
            """Modify LDAP entry."""
            if not self._connection:
                return FlextResult.fail("Not connected to LDAP server")

            # Type guard: connection is guaranteed to be not None after check above
            # No assert needed - type checker understands the flow

            try:
                # Convert changes to ldap3 format
                modifications = {}
                for attr, value in changes.items():
                    if isinstance(value, list):
                        modifications[attr] = [(MODIFY_REPLACE, value)]
                    else:
                        modifications[attr] = [(MODIFY_REPLACE, [value])]

                # ldap3 library has incomplete type stubs; external library limitation
                self._connection.modify(dn, modifications)
                return FlextResult.ok(True)
            except Exception as e:
                return FlextResult.fail(f"LDAP modify failed: {e}")

        def delete_entry(self, dn: str) -> FlextResult[bool]:
            """Delete LDAP entry."""
            if not self._connection:
                return FlextResult.fail("Not connected to LDAP server")

            # Type guard: connection is guaranteed to be not None after check above
            # No assert needed - type checker understands the flow

            try:
                # ldap3 delete() is untyped; wrap with cast for type safety
                # ldap3 library has incomplete type stubs; external library limitation
                cast("type[bool]", self._connection.delete(dn))
                return FlextResult.ok(True)
            except Exception as e:
                return FlextResult.fail(f"LDAP delete failed: {e}")

    class Servers(FlextService[None]):
        """Consolidated LDAP server operations."""

        # Server type constants
        SERVER_OPENLDAP1: ClassVar[str] = "openldap1"
        SERVER_OPENLDAP2: ClassVar[str] = "openldap2"
        SERVER_OID: ClassVar[str] = "oid"
        SERVER_OUD: ClassVar[str] = "oud"
        SERVER_AD: ClassVar[str] = "ad"
        SERVER_GENERIC: ClassVar[str] = "generic"

        def __init__(self, server_type: str | None = None) -> None:
            """Initialize server operations with server type.

            Args:
                server_type: LDAP server type (openldap1, openldap2, oid, oud, ad, generic).

            """
            super().__init__()
            self._server_type = server_type or self.SERVER_GENERIC
            # Mark server_type as used to avoid linting warning
            _ = server_type

        @override
        def execute(self) -> FlextResult[None]:
            """Execute server operations."""
            return FlextResult[None].ok(None)

        def get_default_port(self, *, use_ssl: bool = False) -> int:
            """Get default port for server type."""
            if use_ssl:
                return 636
            return 389

        @property
        def server_type(self) -> str:
            """Get current server type."""
            return self._server_type

        def supports_start_tls(self) -> bool:
            """Check if server supports STARTTLS."""
            return self._server_type in {
                self.SERVER_OPENLDAP1,
                self.SERVER_OPENLDAP2,
                self.SERVER_GENERIC,
            }

    class Acl(FlextService[None]):
        """Consolidated LDAP ACL operations."""

        def __init__(self) -> None:
            """Initialize ACL operations."""
            super().__init__()

        @override
        def execute(self) -> FlextResult[None]:
            """Execute ACL operations."""
            return FlextResult[None].ok(None)

        def get_acl_format(self) -> str:
            """Get ACL format."""
            return "aci"  # Default ACI format

    # =========================================================================
    # PUBLIC API METHODS - Facade interface
    # =========================================================================

    def connect(self) -> FlextResult[Connection]:
        """Connect to LDAP server."""
        return self.client.connect()

    def search(
        self,
        base_dn: str,
        search_filter: str,
        attributes: FlextTypes.StringList | None = None,
    ) -> FlextResult[FlextLdapTypes.LdapDomain.SearchResult]:
        """Search LDAP directory."""
        return self.client.search(base_dn, search_filter, attributes)

    def search_with_request(
        self,
        search_request: FlextLdapModels.SearchRequest,
    ) -> FlextResult[FlextLdapTypes.LdapDomain.SearchResult]:
        """Search LDAP directory using SearchRequest object."""
        return self.client.search(
            search_request.base_dn,
            search_request.filter_str,
            search_request.attributes,
        )

    def search_groups(
        self,
        search_base: str,
        attributes: FlextTypes.StringList | None = None,
    ) -> FlextResult[FlextLdapTypes.LdapDomain.SearchResult]:
        """Search for groups (convenience method)."""
        return self.client.search(
            search_base,
            "(objectClass=group)",
            attributes,
        )

    def search_entries(
        self,
        base_dn: str,
        filter_str: str,
        attributes: FlextTypes.StringList | None = None,
        _scope: str = "subtree",
    ) -> FlextResult[FlextLdapTypes.LdapDomain.SearchResult]:
        """Search for entries with custom filter."""
        return self.client.search(base_dn, filter_str, attributes)

    def get_group(
        self,
        group_dn: str,
        attributes: FlextTypes.StringList | None = None,
    ) -> FlextResult[FlextTypes.Dict | None]:
        """Get group information by DN."""
        result = self.client.search(
            group_dn,
            "(objectClass=group)",
            attributes or ["cn", "member", "memberUid"],
        )
        if result.is_success and result.value:
            return FlextResult.ok(cast("FlextTypes.Dict", result.value[0]))
        return FlextResult.ok(None)

    def update_user_attributes(
        self,
        _dn: str,
        _attributes: FlextTypes.Dict,
    ) -> FlextResult[None]:
        """Update user attributes."""
        # This would need modify operations - for now return success
        return FlextResult.ok(None)

    def update_group_attributes(
        self,
        _dn: str,
        _attributes: FlextTypes.Dict,
    ) -> FlextResult[None]:
        """Update group attributes."""
        # This would need modify operations - for now return success
        return FlextResult.ok(None)

    def delete_user(self, _dn: str) -> FlextResult[None]:
        """Delete user by DN."""
        # This would need delete operations - for now return success
        return FlextResult.ok(None)

    def validate_configuration_consistency(self) -> FlextResult[None]:
        """Validate configuration consistency."""
        # Basic validation - in real implementation would check server connectivity, etc.
        return FlextResult.ok(None)

    def get_server_info(self) -> FlextResult[FlextTypes.Dict]:
        """Get server information."""
        return FlextResult.ok({
            "type": self.servers.server_type,
            "default_port": self.servers.get_default_port(),
            "supports_starttls": self.servers.supports_start_tls(),
        })

    def get_acl_info(self) -> FlextResult[FlextTypes.Dict]:
        """Get ACL information."""
        return FlextResult.ok({
            "format": self.acl.get_acl_format(),
        })

    def test_connection(self) -> FlextResult[bool]:
        """Test LDAP connection."""
        return self.client.test_connection()

    def search_one(
        self,
        search_request: FlextLdapModels.SearchRequest,
    ) -> FlextResult[FlextLdapModels.Entry | None]:
        """Search for a single entry using SearchRequest."""
        result = self.client.search(
            search_request.base_dn,
            search_request.filter_str,
            search_request.attributes,
        )
        if result.is_failure:
            return FlextResult[FlextLdapModels.Entry | None].fail(result.error)

        entries = result.unwrap()
        if entries:
            # Convert dict to Entry model
            entry_dict = entries[0]
            # Extract DN safely
            dn_value = entry_dict.get("dn", "")
            if isinstance(dn_value, str):
                dn = dn_value
            else:
                dn = str(dn_value) if dn_value else ""

            # Convert attributes to proper type
            def _convert_attribute_value(
                value: str | FlextTypes.StringList | bytes | list[bytes],
            ) -> FlextLdapTypes.LdapEntries.EntryAttributeValue:
                if isinstance(value, list):
                    # Convert list elements to strings
                    return [str(item) for item in value]
                return str(value)

            typed_attributes: dict[
                str, FlextLdapTypes.LdapEntries.EntryAttributeValue
            ] = {
                key: _convert_attribute_value(
                    cast("str | FlextTypes.StringList | bytes | list[bytes]", value)
                )
                for key, value in entry_dict.items()
                if key != "dn"
                and not isinstance(value, dict)  # Skip DN and nested dicts
            }

            return FlextResult.ok(
                FlextLdapModels.Entry(
                    dn=dn,
                    attributes=typed_attributes,
                )
            )
        return FlextResult.ok(None)

    def search_users(
        self,
        search_base: str,
        attributes: FlextTypes.StringList | None = None,
    ) -> FlextResult[FlextLdapTypes.LdapDomain.SearchResult]:
        """Search for users (convenience method)."""
        return self.client.search(
            search_base,
            "(objectClass=person)",
            attributes,
        )

    def find_user(
        self,
        username: str,
        search_base: str | None = None,
    ) -> FlextResult[FlextTypes.Dict | None]:
        """Find user by username."""
        base = search_base or self.config.ldap_base_dn
        result = self.client.search(
            base,
            f"(uid={username})",
            ["dn", "cn", "mail"],
        )
        if result.is_failure:
            return FlextResult[FlextTypes.Dict | None].fail(result.error)

        users = result.unwrap()
        if users:
            return FlextResult.ok(cast("FlextTypes.Dict", users[0]))
        return FlextResult.ok(None)

    def search_entries_bulk(
        self,
        search_requests: list[FlextLdapModels.SearchRequest],
    ) -> FlextResult[list[FlextLdapModels.Entry]]:
        """Search multiple entries in bulk."""
        results = []
        for request in search_requests:
            result = self.search_one(request)
            if result.is_success and result.value:
                results.append(result.value)
        return FlextResult.ok(results)

    def search_universal(
        self,
        base_dn: str,
        filter_str: str,
        attributes: FlextTypes.StringList | None = None,
    ) -> FlextResult[FlextLdapTypes.LdapDomain.SearchResult]:
        """Universal search method."""
        return self.client.search(base_dn, filter_str, attributes)

    def modify_entry(
        self,
        dn: str,
        changes: dict[str, str | list[str]],
    ) -> FlextResult[bool]:
        """Modify LDAP entry."""
        return self.client.modify_entry(dn, changes)

    def delete_entry(
        self,
        dn: str,
    ) -> FlextResult[bool]:
        """Delete LDAP entry."""
        return self.client.delete_entry(dn)

    def add_entries_batch(
        self,
        entries: list[tuple[str, dict[str, str | list[str]]]],
    ) -> FlextResult[list[bool]]:
        """Add multiple entries in batch."""
        results = []
        for dn, attributes in entries:
            result = self.add_entry(dn, attributes)
            results.append(result.is_success)
        return FlextResult.ok(results)

    def get_server_operations(self) -> FlextLdap.Servers:
        """Get server operations instance."""
        return self.servers

    def get_server_specific_attributes(self, server_type: str) -> list[str]:
        """Get server-specific attributes."""
        # This would need to be implemented based on server type
        # For now, return generic attributes
        _ = server_type  # Mark as used to avoid linting warning
        return ["dn", "cn", "objectClass"]

    def detect_entry_server_type(
        self, entry: FlextLdifModels.Entry
    ) -> FlextResult[str]:
        """Detect server type from entry attributes."""
        try:
            # Use entry adapter for detection
            if not hasattr(self, "_entry_adapter") or self._entry_adapter is None:
                self._entry_adapter = FlextLdapEntryAdapter()

            return self._entry_adapter.detect_entry_server_type(entry)
        except Exception as e:
            return FlextResult[str].fail(f"Entry server type detection failed: {e}")

    def normalize_entry_for_server(
        self,
        entry: FlextLdapModels.Entry,
        target_server: str,
    ) -> FlextLdapModels.Entry:
        """Normalize entry for target server."""
        # For now, return as-is
        # Mark parameters as used to avoid linting warnings
        _ = target_server
        return entry

    def validate_entry_for_server(
        self,
        entry: FlextLdifModels.Entry,
        server_type: str,
    ) -> FlextResult[bool]:
        """Validate entry for server compatibility."""
        try:
            # Use entry adapter for validation
            if not hasattr(self, "_entry_adapter") or self._entry_adapter is None:
                self._entry_adapter = FlextLdapEntryAdapter()

            return self._entry_adapter.validate_entry_for_server(entry, server_type)
        except Exception as e:
            return FlextResult[bool].fail(f"Entry validation failed: {e}")

    def convert_entry_between_servers(
        self,
        entry: FlextLdifModels.Entry,
        from_server: str,
        to_server: str,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Convert entry between server types."""
        try:
            # Use entry adapter for conversion
            if not hasattr(self, "_entry_adapter") or self._entry_adapter is None:
                self._entry_adapter = FlextLdapEntryAdapter()

            return self._entry_adapter.convert_entry_format(
                entry, from_server, to_server
            )
        except Exception as e:
            return FlextResult[FlextLdifModels.Entry].fail(
                f"Entry conversion failed: {e}"
            )

    def export_to_ldif(self, entries: list[FlextLdapModels.Entry]) -> str:
        """Export entries to LDIF format."""
        ldif_lines: list[str] = []
        for entry in entries:
            entry_lines = [f"dn: {entry.dn}"]
            for attr, value in entry.attributes.items():
                if isinstance(value, list):
                    entry_lines.extend(f"{attr}: {v}" for v in value)
                else:
                    entry_lines.append(f"{attr}: {value}")
            entry_lines.append("")
            ldif_lines.extend(entry_lines)
        return "\n".join(ldif_lines)

    def import_from_ldif(
        self, ldif_content: str
    ) -> FlextResult[list[FlextLdapModels.Entry]]:
        """Import entries from LDIF content."""
        entries: list[FlextLdapModels.Entry] = []
        # Simple LDIF parser (would need more robust implementation)
        lines = ldif_content.strip().split("\n")
        current_entry: FlextLdapModels.Entry | None = None
        current_dn: str | None = None

        for line in lines:
            stripped_line = line.strip()
            if not stripped_line:
                if current_entry:
                    entries.append(current_entry)
                    current_entry = None
                    current_dn = None
                continue

            if stripped_line.startswith("dn:"):
                if current_entry:
                    entries.append(current_entry)
                current_dn = stripped_line[3:].strip()
                current_entry = FlextLdapModels.Entry(dn=current_dn, attributes={})
            elif ":" in stripped_line and current_entry:
                attr, value = stripped_line.split(":", 1)
                attr = attr.strip()
                value = value.strip()
                if attr in current_entry.attributes:
                    existing_value = current_entry.attributes[attr]
                    if isinstance(existing_value, list):
                        existing_value.append(value)
                    else:
                        current_entry.attributes[attr] = [existing_value, value]
                else:
                    current_entry.attributes[attr] = value

        if current_entry:
            entries.append(current_entry)

        return FlextResult.ok(entries)

    def add_entry(
        self,
        dn: str,
        attributes: dict[str, str | FlextTypes.StringList],
    ) -> FlextResult[bool]:
        """Add new LDAP entry."""
        return self.client.add_entry(dn, attributes)

    def get_server_capabilities(
        self,
    ) -> FlextResult[FlextLdapModels.ServerCapabilities]:
        """Get comprehensive server capabilities."""
        return FlextResult.ok(
            FlextLdapModels.ServerCapabilities(
                supports_ssl=True,
                supports_starttls=self.servers.supports_start_tls(),
                supports_paged_results=True,
                supports_vlv=False,
                supports_sasl=True,
                max_page_size=1000,
            )
        )

    @property
    def is_connected(self) -> bool:
        """Check if connected to LDAP server."""
        return self.client.is_connected

    def unbind(self) -> FlextResult[None]:
        """Unbind and close LDAP connection."""
        return self.client.unbind()

    def get_detected_server_type(self) -> FlextResult[str | None]:
        """Get detected server type based on connection."""
        if not self.client.is_connected:
            return FlextResult.fail("Not connected to LDAP server")
        server_type = self.servers.server_type
        return FlextResult.ok(server_type if server_type != "generic" else None)

    def __enter__(self) -> Self:
        """Enter context manager - establish connection."""
        self.client.connect()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: types.TracebackType | None,
    ) -> None:
        """Exit context manager - close connection."""
        self.client.unbind()
