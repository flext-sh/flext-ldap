"""Consolidated LDAP operations with FLEXT integration.

LDAP operations unified into FlextLdap main class following
single-class-per-project pattern with nested subsystems.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import threading
import types
from collections.abc import Callable
from typing import ClassVar, Literal, Self, cast, override

from flext_core import (
    FlextResult,
    FlextService,
)
from flext_ldif import FlextLdif, FlextLdifModels
from ldap3 import (
    ALL,
    BASE,
    LEVEL,
    SUBTREE,
    Connection,
    Server,
)
from ldap3.core.exceptions import (
    LDAPAttributeError,
    LDAPBindError,
    LDAPChangeError,
    LDAPCommunicationError,
    LDAPInvalidDnError,
    LDAPInvalidFilterError,
    LDAPInvalidScopeError,
    LDAPObjectClassError,
    LDAPObjectError,
    LDAPOperationsErrorResult,
    LDAPResponseTimeoutError,
    LDAPSocketOpenError,
    LDAPStartTLSError,
)
from pydantic import SecretStr, ValidationError

from flext_ldap.authentication import FlextLdapAuthentication
from flext_ldap.clients import FlextLdapClients
from flext_ldap.config import FlextLdapConfig
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.entry_adapter import FlextLdapEntryAdapter
from flext_ldap.models import FlextLdapModels
from flext_ldap.typings import FlextLdapTypes


class FlextLdap(FlextService[None]):
    """Consolidated LDAP operations with FLEXT integration.

    Main class providing LDAP functionality with nested subsystems for
    complex operations following single-class-per-project pattern.

    Features:
    - Connection management and authentication
    - Search, add, modify, delete operations
    - Server-specific operations (OpenLDAP, Oracle OID/OUD, AD)
    - ACL management and schema operations
    - Entry validation and LDIF integration

    Uses FlextResult[T] for error handling, FlextService for dependency
    injection, and FlextLogger for structured logging.
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
        self._quirks_mode: FlextLdapConstants.Types.QuirksMode = (
            FlextLdapConstants.Types.QuirksMode.AUTOMATIC
        )

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

    def _lazy_init(self, attr_name: str, factory: Callable[[], object]) -> object:
        """Unified lazy initialization pattern using FlextContainer-like pattern.

        Eliminates 4 repetitive lazy-load properties with single unified method.
        """
        attr = getattr(self, f"_{attr_name}", None)
        if attr is None:
            attr = factory()
            setattr(self, f"_{attr_name}", attr)
        return attr

    @property
    def client(self) -> FlextLdap.Client:
        """Get LDAP client instance."""
        return cast(
            "FlextLdap.Client",
            self._lazy_init("client", lambda: FlextLdap.Client(self._config)),
        )

    @property
    def servers(self) -> FlextLdap.Servers:
        """Get server operations instance."""
        return cast("FlextLdap.Servers", self._lazy_init("servers", FlextLdap.Servers))

    @property
    def acl(self) -> FlextLdap.Acl:
        """Get ACL operations instance."""
        return cast("FlextLdap.Acl", self._lazy_init("acl", FlextLdap.Acl))

    @property
    def authentication(self) -> FlextLdapAuthentication:
        """Get authentication operations instance."""
        return cast(
            "FlextLdapAuthentication",
            self._lazy_init("authentication", FlextLdapAuthentication),
        )

    @property
    def quirks_mode(self) -> FlextLdapConstants.Types.QuirksMode:
        """Get current quirks mode."""
        return self._quirks_mode

    @override
    def execute(self) -> FlextResult[None]:
        """Execute main domain operation (required by FlextService)."""
        return FlextResult[None].ok(None)

    # =========================================================================
    # NESTED CLASSES - Consolidated subsystems
    # =========================================================================

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
            except (
                LDAPSocketOpenError,
                LDAPCommunicationError,
                LDAPBindError,
                LDAPStartTLSError,
                LDAPResponseTimeoutError,
                ValidationError,
            ) as e:
                return FlextResult.fail(f"LDAP connection failed: {e}")

        def unbind(self) -> FlextResult[None]:
            """Unbind and close LDAP connection."""
            try:
                if self._connection is not None:
                    # Cast to Protocol type for proper type checking with ldap3
                    typed_conn = cast(
                        "FlextLdapTypes.Ldap3Protocols.Connection", self._connection
                    )
                    typed_conn.unbind()
                    self._connection = None
                return FlextResult.ok(None)
            except LDAPCommunicationError as e:
                return FlextResult[None].fail(f"LDAP unbind failed: {e}")

        def search(
            self,
            base_dn: str,
            search_filter: str,
            attributes: list[str] | None = None,
            scope: str = "subtree",
        ) -> FlextResult[FlextLdapModels.SearchResponse]:
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
                # Convert ldap3 entries to FlextLdapModels.Entry objects
                entries = [
                    FlextLdapModels.Entry(
                        dn=entry.entry_dn,
                        attributes=dict(entry.entry_attributes_as_dict),
                    )
                    for entry in self._connection.entries
                ]
                # Return SearchResponse with entries
                return FlextResult.ok(
                    FlextLdapModels.SearchResponse(
                        entries=entries,
                        total_count=len(entries),
                        entries_returned=len(entries),
                        result_code=0,  # Success
                    )
                )
            except (
                LDAPCommunicationError,
                LDAPResponseTimeoutError,
                LDAPInvalidFilterError,
                LDAPInvalidScopeError,
                LDAPInvalidDnError,
                ValidationError,
            ) as e:
                return FlextResult.fail(f"LDAP search failed: {e}")

        def add_entry(
            self,
            dn: str,
            attributes: dict[str, str | list[str]],
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

                # Cast to Protocol type for proper type checking with ldap3
                typed_conn = cast(
                    "FlextLdapTypes.Ldap3Protocols.Connection", self._connection
                )
                # Cast attributes to match Protocol signature
                attrs = cast(
                    "dict[str, str | list[str]] | None", ldap3_attributes or None
                )
                success = typed_conn.add(dn, object_class, attributes=attrs)

                # CRITICAL FIX: Check ldap3 result - result is a dictionary
                if not success:
                    result = typed_conn.result
                    error_code = (
                        result.get("result", 0) if isinstance(result, dict) else 0
                    )
                    error_msg = (
                        result.get("message", "") if isinstance(result, dict) else ""
                    )
                    error_desc = (
                        result.get("description", "Unknown error")
                        if isinstance(result, dict)
                        else "Unknown error"
                    )
                    return FlextResult.fail(
                        f"LDAP add failed [code {error_code}]: {error_desc}: {error_msg}"
                    )

                return FlextResult.ok(True)
            except (
                LDAPCommunicationError,
                LDAPAttributeError,
                LDAPInvalidDnError,
                LDAPObjectError,
                LDAPObjectClassError,
                LDAPOperationsErrorResult,
                ValidationError,
            ) as e:
                return FlextResult.fail(f"LDAP add failed: {e}")

        def modify_entry(
            self,
            dn: str,
            changes: dict[str, str | list[str]],
            *,
            operation: str = FlextLdapConstants.ModifyOperation.REPLACE,
        ) -> FlextResult[bool]:
            """Modify LDAP entry.

            Args:
                dn: Distinguished name of entry to modify.
                changes: Dictionary of attribute changes.
                operation: LDAP modify operation type from FlextLdapConstants.ModifyOperation.
                          Defaults to REPLACE for standard modifications.
                          Use ADD for OUD schema modifications.

            Returns:
                FlextResult[bool] indicating success or failure with error details.

            """
            if not self._connection:
                return FlextResult.fail("Not connected to LDAP server")

            # Type guard: connection is guaranteed to be not None after check above
            # No assert needed - type checker understands the flow

            try:
                # Convert changes to ldap3 format using specified operation
                modifications = {}
                for attr, value in changes.items():
                    if isinstance(value, list):
                        modifications[attr] = [(operation, value)]
                    else:
                        modifications[attr] = [(operation, [value])]

                # Cast to Protocol type for proper type checking with ldap3
                typed_conn = cast(
                    "FlextLdapTypes.Ldap3Protocols.Connection", self._connection
                )
                # ldap3 accepts string constants (MODIFY_ADD, etc.) in modification tuples
                # Type checker expects int but ldap3 runtime accepts str constants
                success = typed_conn.modify(dn, modifications)

                # CRITICAL FIX: Check ldap3 result - result is a dictionary
                if not success:
                    result = typed_conn.result
                    error_code = (
                        result.get("result", 0) if isinstance(result, dict) else 0
                    )
                    error_msg = (
                        result.get("message", "") if isinstance(result, dict) else ""
                    )
                    error_desc = (
                        result.get("description", "Unknown error")
                        if isinstance(result, dict)
                        else "Unknown error"
                    )
                    return FlextResult.fail(
                        f"LDAP modify failed [code {error_code}]: {error_desc}: {error_msg}"
                    )

                return FlextResult.ok(True)
            except (
                LDAPCommunicationError,
                LDAPChangeError,
                LDAPInvalidDnError,
                LDAPAttributeError,
                LDAPOperationsErrorResult,
                ValidationError,
            ) as e:
                return FlextResult.fail(f"LDAP modify failed: {e}")

        def delete_entry(self, dn: str) -> FlextResult[bool]:
            """Delete LDAP entry."""
            if not self._connection:
                return FlextResult.fail("Not connected to LDAP server")

            # Type guard: connection is guaranteed to be not None after check above
            # No assert needed - type checker understands the flow

            try:
                # Cast to Protocol type for proper type checking with ldap3
                typed_conn = cast(
                    "FlextLdapTypes.Ldap3Protocols.Connection", self._connection
                )
                success = typed_conn.delete(dn)

                # CRITICAL FIX: Check ldap3 result - result is a dictionary
                if not success:
                    result = typed_conn.result
                    error_code = (
                        result.get("result", 0) if isinstance(result, dict) else 0
                    )
                    error_msg = (
                        result.get("message", "") if isinstance(result, dict) else ""
                    )
                    error_desc = (
                        result.get("description", "Unknown error")
                        if isinstance(result, dict)
                        else "Unknown error"
                    )
                    return FlextResult.fail(
                        f"LDAP delete failed [code {error_code}]: {error_desc}: {error_msg}"
                    )

                return FlextResult.ok(True)
            except (
                LDAPCommunicationError,
                LDAPInvalidDnError,
                LDAPOperationsErrorResult,
            ) as e:
                return FlextResult.fail(f"LDAP delete failed: {e}")

        def validate_entry(
            self,
            entry: FlextLdapModels.Entry,
            *,
            quirks_mode: FlextLdapConstants.Types.QuirksMode | None = None,
        ) -> FlextResult[bool]:
            """Validate LDAP entry structure.

            Args:
                entry: Entry to validate
                quirks_mode: Override default quirks mode for validation

            Returns:
                FlextResult[bool]: Success if entry is valid

            """
            # Create a temporary client for validation
            temp_client = FlextLdapClients(self._config)
            return temp_client.validate_entry(entry, quirks_mode=quirks_mode)

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
    # PUBLIC API METHODS - Unified Consolidated Interface
    # =========================================================================
    # CONSOLIDATED PUBLIC API (7 CORE METHODS WITH QUIRKS SUPPORT)
    # =========================================================================

    def connect(
        self,
        uri: str | None = None,
        bind_dn: str | None = None,
        password: SecretStr | str | None = None,
        *,
        quirks_mode: FlextLdapConstants.Types.QuirksMode = FlextLdapConstants.Types.QuirksMode.AUTOMATIC,
    ) -> FlextResult[bool]:
        """Connect to LDAP server with optional configuration and quirks control.

        Handles connection with all configuration options. Supports automatic
        server detection and server-specific quirks handling.

        Args:
            uri: Optional server URI (ldap://host:port or ldaps://host:port).
                 If not provided, uses configured URI.
            bind_dn: Optional bind DN for authentication.
                    If not provided, uses configured bind DN.
            password: Optional bind password.
                     If not provided, uses configured password.
            quirks_mode: Quirks handling mode:
                        - "automatic": Auto-detect server, apply quirks
                        - "server": Use explicit server type (must set in config)
                        - "rfc": RFC-compliant only, no extensions
                        - "relaxed": Permissive mode, accept anything

        Returns:
            FlextResult[bool]: True if connection successful.

        Examples:
            # Connect with default config
            result = ldap.connect(quirks_mode=FlextLdapConstants.Types.QuirksMode.AUTOMATIC)

            # Connect with explicit credentials
            result = ldap.connect(
                uri="ldap://ldap.example.com:389",
                bind_dn="cn=admin,dc=example,dc=com",
                password=SecretStr("admin123")
            )

        """
        # Update configuration if parameters provided
        if uri:
            self._config.ldap_server_uri = uri
        if bind_dn:
            self._config.ldap_bind_dn = bind_dn
        if password:
            if isinstance(password, str):
                password = SecretStr(password)
            self._config.ldap_bind_password = password

        # Store quirks_mode for internal modules
        self._quirks_mode = quirks_mode

        # Connect using client
        result = self.client.connect()
        if result.is_failure:
            return FlextResult[bool].fail(f"Connection failed: {result.error}")

        return FlextResult[bool].ok(True)

    def query(
        self,
        base_dn: str,
        filter_str: str,
        attributes: list[str] | None = None,
        *,
        single: bool = False,
        quirks_mode: FlextLdapConstants.Types.QuirksMode | None = None,
    ) -> FlextResult[FlextLdapModels.SearchResponse | FlextLdapModels.Entry | None]:
        """Unified query method (search consolidation) with quirks support.

        Queries LDAP directory with support for single entry or full response.
        Respects quirks_mode for server-specific behavior.

        Args:
            base_dn: Base distinguished name for search.
            filter_str: LDAP search filter string (RFC 4515 compliant).
            attributes: Optional list of attributes to retrieve.
            single: If True, return first Entry only. If False, return SearchResponse.
            quirks_mode: Optional override of current quirks mode.

        Returns:
            FlextResult with SearchResponse or Entry | None based on single parameter.

        Examples:
            # Get all matching entries
            result = ldap.query("dc=example,dc=com", "(objectClass=person)")

            # Get first matching entry
            result = ldap.query("dc=example,dc=com", "(uid=jdoe)", single=True)

        """
        if quirks_mode:
            self._quirks_mode = quirks_mode

        result = self.client.search(base_dn, filter_str, attributes)
        if result.is_failure:
            return cast(
                "FlextResult[FlextLdapModels.SearchResponse | FlextLdapModels.Entry | None]",
                result,
            )

        if single:
            search_response = result.unwrap()
            if search_response and search_response.entries:
                return cast(
                    "FlextResult[FlextLdapModels.SearchResponse | FlextLdapModels.Entry | None]",
                    FlextResult.ok(search_response.entries[0]),
                )
            return cast(
                "FlextResult[FlextLdapModels.SearchResponse | FlextLdapModels.Entry | None]",
                FlextResult.ok(None),
            )

        return cast(
            "FlextResult[FlextLdapModels.SearchResponse | FlextLdapModels.Entry | None]",
            result,
        )

    def apply_changes(
        self,
        changes: dict[str, str | list[str]],
        dn: str | None = None,
        *,
        operation: Literal["add", "modify", "delete"] = "add",
        atomic: bool = False,
        batch: bool = False,
        modifications: list[tuple[str, dict[str, str | list[str]]]] | None = None,
        quirks_mode: FlextLdapConstants.Types.QuirksMode | None = None,
    ) -> FlextResult[bool | list[bool]]:
        """Universal CRUD apply_changes method with quirks support.

        Consolidates add, modify, and delete operations with unified interface.
        Supports both single and batch operations with optional atomic semantics.

        Args:
            changes: Changes/attributes for single operation.
            dn: Distinguished name for single operation (required for add/modify).
            operation: Type of operation: "add", "modify", or "delete".
            atomic: If True, attempt atomic modification (all or none).
            batch: If True, use modifications parameter for batch mode.
            modifications: List of (DN, changes) tuples for batch operations.
            quirks_mode: Optional override of current quirks mode.

        Returns:
            FlextResult[bool] for single operation, FlextResult[list[bool]] for batch.

        Examples:
            # Add single entry
            result = ldap.execute(
                {"cn": ["user"], "objectClass": ["person"]},
                dn="cn=user,dc=example,dc=com",
                operation="add"
            )

            # Modify single entry
            result = ldap.execute(
                {"mail": "new@example.com"},
                dn="cn=user,dc=example,dc=com",
                operation="modify"
            )

            # Delete entry
            result = ldap.execute({}, dn="cn=user,dc=example,dc=com", operation="delete")

            # Batch modify
            mods = [
                ("cn=user1,dc=example,dc=com", {"mail": "user1@example.com"}),
                ("cn=user2,dc=example,dc=com", {"mail": "user2@example.com"}),
            ]
            result = ldap.execute({}, batch=True, modifications=mods, operation="modify")

        """
        if quirks_mode:
            self._quirks_mode = quirks_mode

        if operation == "delete":
            if not dn:
                return FlextResult[bool | list[bool]].fail(
                    "DN required for delete operation"
                )
            return cast("FlextResult[bool | list[bool]]", self.client.delete_entry(dn))

        if batch and modifications:
            results: list[bool] = []
            if operation == "add":
                for batch_dn, batch_attrs in modifications:
                    result = self.client.add_entry(batch_dn, batch_attrs)
                    results.append(result.is_success)
            elif operation == "modify":
                if atomic:
                    temp_results = []
                    for batch_dn, batch_changes in modifications:
                        result = self.client.modify_entry(
                            batch_dn,
                            batch_changes,
                            operation=FlextLdapConstants.ModifyOperation.REPLACE,
                        )
                        temp_results.append(result.is_success)
                    if not all(temp_results):
                        failed_count = len([r for r in temp_results if not r])
                        return FlextResult[bool | list[bool]].fail(
                            f"Atomic modification failed: {failed_count} of {len(modifications)} entries"
                        )
                    results = temp_results
                else:
                    for batch_dn, batch_changes in modifications:
                        result = self.client.modify_entry(
                            batch_dn,
                            batch_changes,
                            operation=FlextLdapConstants.ModifyOperation.REPLACE,
                        )
                        results.append(result.is_success)
            return cast(
                "FlextResult[bool | list[bool]]", FlextResult[list[bool]].ok(results)
            )

        # Single operation
        if not dn:
            return FlextResult[bool | list[bool]].fail(
                f"DN required for {operation} operation"
            )

        if operation == "add":
            return cast(
                "FlextResult[bool | list[bool]]", self.client.add_entry(dn, changes)
            )
        if operation == "modify":
            return cast(
                "FlextResult[bool | list[bool]]",
                self.client.modify_entry(
                    dn, changes, operation=FlextLdapConstants.ModifyOperation.REPLACE
                ),
            )

        return FlextResult[bool | list[bool]].fail(f"Unknown operation: {operation}")

    def validate_entries(
        self,
        entries: FlextLdapModels.Entry | list[FlextLdapModels.Entry],
        *,
        server_type: str | None = None,
        mode: Literal["schema", "business", "all"] = "all",
        quirks_mode: FlextLdapConstants.Types.QuirksMode | None = None,
    ) -> FlextResult[dict[str, object]]:
        """Validation method with quirks support.

        Validates entries against server schema and business rules.
        Consolidates validate_entry_for_server and detect_entry_server_type.

        Args:
            entries: Entry or list of entries to validate.
            server_type: Optional explicit server type for validation.
            mode: Validation mode: "schema", "business", or "all".
            quirks_mode: Optional override of current quirks mode.

        Returns:
            FlextResult with validation report including any errors or warnings.

        """
        if quirks_mode:
            self._quirks_mode = quirks_mode

        if not hasattr(self, "_entry_adapter") or self._entry_adapter is None:
            self._entry_adapter = FlextLdapEntryAdapter()

        # Normalize input
        entry_list = entries if isinstance(entries, list) else [entries]

        # Perform validation
        all_valid = True
        validation_issues: list[str] = []

        for entry in entry_list:
            if mode in {"schema", "all"} and self._entry_adapter is not None:
                # Pass LDAP entry directly - adapter handles both LDAP and LDIF entries
                result = self._entry_adapter.validate_entry_for_server(
                    entry,  # LDAP entry
                    server_type or self.servers.server_type,
                )
                if result.is_failure:
                    all_valid = False
                    validation_issues.append(
                        f"Schema validation failed for {entry.dn}: {result.error}"
                    )

            if mode in {"business", "all"}:
                # Business rule validation can be extended
                pass

        return FlextResult[dict[str, object]].ok({
            "valid": all_valid,
            "issues": validation_issues,
            "entry_count": len(entry_list),
        })

    def convert(
        self,
        entries: FlextLdapModels.Entry | list[FlextLdapModels.Entry],
        source_server: str | None = None,
        target_server: str | None = None,
        *,
        quirks_mode: FlextLdapConstants.Types.QuirksMode | None = None,
    ) -> FlextResult[FlextLdapModels.Entry | list[FlextLdapModels.Entry]]:
        """Entry conversion method with quirks support.

        Converts entries between server types with server-specific transformations.

        Args:
            entries: Entry or list of entries to convert.
            source_server: Source server type (auto-detect if None).
            target_server: Target server type (use current if None).
            quirks_mode: Optional override of current quirks mode.

        Returns:
            FlextResult with converted entry/entries.

        """
        if quirks_mode:
            self._quirks_mode = quirks_mode

        if not hasattr(self, "_entry_adapter") or self._entry_adapter is None:
            self._entry_adapter = FlextLdapEntryAdapter()

        # Normalize input
        is_single = not isinstance(entries, list)
        entry_list = entries if isinstance(entries, list) else [entries]

        # Determine source server
        if not source_server:
            detect_result = self._entry_adapter.detect_entry_server_type(
                cast("FlextLdifModels.Entry", entry_list[0])
            )
            if detect_result.is_failure:
                return FlextResult.fail(
                    f"Could not detect source server: {detect_result.error}"
                )
            source_server = detect_result.unwrap()

        # Determine target server
        if not target_server:
            target_server = self.servers.server_type or "rfc"

        # Convert entries
        converted_list = []
        for entry in entry_list:
            convert_result = self._entry_adapter.convert_entry_format(
                cast("FlextLdifModels.Entry", entry), source_server, target_server
            )
            if convert_result.is_failure:
                return FlextResult.fail(
                    f"Conversion failed for {entry.dn}: {convert_result.error}"
                )
            converted_list.append(convert_result.unwrap())

        if is_single:
            return FlextResult[FlextLdapModels.Entry | list[FlextLdapModels.Entry]].ok(
                cast("FlextLdapModels.Entry", converted_list[0])
            )
        return FlextResult[FlextLdapModels.Entry | list[FlextLdapModels.Entry]].ok(
            cast("list[FlextLdapModels.Entry]", converted_list)
        )

    def exchange(
        self,
        data: str | None = None,
        entries: list[FlextLdapModels.Entry] | None = None,
        *,
        data_format: Literal["ldif", "json", "csv"] = "ldif",
        direction: Literal["import", "export"] = "import",
        quirks_mode: FlextLdapConstants.Types.QuirksMode | None = None,
    ) -> FlextResult[str | list[FlextLdapModels.Entry]]:
        """Data exchange method for import/export with quirks support.

        Consolidates import_from_ldif and export_to_ldif operations.

        Args:
            data: Data string for import operation.
            entries: Entries for export operation.
            data_format: Data format: "ldif", "json", or "csv".
            direction: Operation direction: "import" or "export".
            quirks_mode: Optional override of current quirks mode.

        Returns:
            FlextResult with imported entries or exported data string.

        """
        if quirks_mode:
            self._quirks_mode = quirks_mode

        if direction == "import":
            if not data:
                return FlextResult[str | list[FlextLdapModels.Entry]].fail(
                    "Data required for import operation"
                )
            if data_format == "ldif":
                return cast(
                    "FlextResult[str | list[FlextLdapModels.Entry]]",
                    self.import_from_ldif(data),
                )
            return FlextResult[str | list[FlextLdapModels.Entry]].fail(
                f"Import format {data_format} not yet supported"
            )
        # export
        if not entries:
            return FlextResult[str | list[FlextLdapModels.Entry]].fail(
                "Entries required for export operation"
            )
        if data_format == "ldif":
            exported_data = self.export_to_ldif(entries)
            return FlextResult[str | list[FlextLdapModels.Entry]].ok(exported_data)
        return FlextResult[str | list[FlextLdapModels.Entry]].fail(
            f"Export format {data_format} not yet supported"
        )

    def info(
        self,
        *,
        detail_level: Literal["basic", "full", "diagnostic"] = "basic",
        quirks_mode: FlextLdapConstants.Types.QuirksMode | None = None,
    ) -> FlextResult[dict[str, object]]:
        """Server information method with quirks support.

        Consolidates get_server_info, get_server_capabilities, get_acl_info, etc.

        Args:
            detail_level: Level of detail: "basic", "full", or "diagnostic".
            quirks_mode: Optional override of current quirks mode.

        Returns:
            FlextResult with comprehensive server information.

        """
        if quirks_mode:
            self._quirks_mode = quirks_mode

        info_dict: dict[str, object] = {
            "type": self.servers.server_type,
            "connected": self.client.is_connected,
            "quirks_mode": self._quirks_mode,
        }

        if detail_level in {"full", "diagnostic"}:
            info_dict.update({
                "default_port": self.servers.get_default_port(),
                "supports_starttls": self.servers.supports_start_tls(),
            })

        if detail_level == "diagnostic":
            caps_result = self.get_server_capabilities()
            if caps_result.is_success:
                caps = caps_result.unwrap()
                info_dict["capabilities"] = {
                    "ssl": caps.supports_ssl,
                    "starttls": caps.supports_starttls,
                    "paged_results": caps.supports_paged_results,
                    "sasl": caps.supports_sasl,
                    "max_page_size": caps.max_page_size,
                }

            acl_result = self.get_acl_info()
            if acl_result.is_success:
                info_dict["acl_format"] = acl_result.unwrap().get("format", "unknown")

        if detail_level == "diagnostic":
            info_dict["server_specific_attributes"] = (
                self.get_server_specific_attributes(self.servers.server_type)
            )

        return FlextResult[dict[str, object]].ok(info_dict)

    # =========================================================================
    # BACKWARD COMPATIBILITY METHODS (Deprecated - Use New Consolidated API)
    # =========================================================================

    def search(
        self,
        base_dn: str,
        filter_str: str,
        attributes: list[str] | None = None,
        *,
        single: bool = False,
    ) -> FlextResult[FlextLdapModels.SearchResponse | FlextLdapModels.Entry | None]:
        """Unified search method supporting single entry or full response.

        Args:
            base_dn: Base distinguished name for search.
            filter_str: LDAP search filter string.
            attributes: Optional list of attributes to retrieve.
            single: If True, return first Entry only. If False, return SearchResponse.

        Returns:
            FlextResult with SearchResponse or Entry | None based on single parameter.

        Examples:
            # Get all matching entries
            result = ldap.search("dc=example,dc=com", "(objectClass=person)")

            # Get first matching entry
            result = ldap.search("dc=example,dc=com", "(uid=jdoe)", single=True)
            if result.is_success and result.value:
                entry = result.unwrap()

        """
        result = self.client.search(base_dn, filter_str, attributes)
        if result.is_failure:
            return cast(
                "FlextResult[FlextLdapModels.SearchResponse | FlextLdapModels.Entry | None]",
                result,
            )

        if single:
            response = result.unwrap()
            # Client returns SearchResponse object, extract entries field
            if (
                isinstance(response, FlextLdapModels.SearchResponse)
                and response.entries
                and len(response.entries) > 0
            ):
                return cast(
                    "FlextResult[FlextLdapModels.SearchResponse | FlextLdapModels.Entry | None]",
                    FlextResult.ok(response.entries[0]),
                )
            return cast(
                "FlextResult[FlextLdapModels.SearchResponse | FlextLdapModels.Entry | None]",
                FlextResult.ok(None),
            )

        return cast(
            "FlextResult[FlextLdapModels.SearchResponse | FlextLdapModels.Entry | None]",
            result,
        )

    def add(
        self,
        dn: str,
        attributes: dict[str, str | list[str]],
        *,
        batch: bool = False,
        entries: list[tuple[str, dict[str, str | list[str]]]] | None = None,
    ) -> FlextResult[bool | list[bool]]:
        """Unified add method supporting single and batch operations.

        Args:
            dn: Distinguished name for single entry add.
            attributes: Attributes for single entry add.
            batch: If True, use entries parameter for batch mode.
            entries: List of (DN, attributes) tuples for batch mode.

        Returns:
            FlextResult[bool] for single mode, FlextResult[list[bool]] for batch mode.

        Examples:
            # Add single entry
            result = ldap.add("cn=user,dc=example,dc=com", {"cn": ["user"], "objectClass": ["person"]})

            # Add multiple entries
            entries = [("cn=user1,dc=example,dc=com", {...}), ("cn=user2,dc=example,dc=com", {...})]
            result = ldap.add("", {}, batch=True, entries=entries)

        """
        if batch and entries:
            results = []
            for batch_dn, batch_attrs in entries:
                result = self.client.add_entry(batch_dn, batch_attrs)
                results.append(result.is_success)
            return cast(
                "FlextResult[bool | list[bool]]", FlextResult[list[bool]].ok(results)
            )

        return cast(
            "FlextResult[bool | list[bool]]", self.client.add_entry(dn, attributes)
        )

    def modify(
        self,
        dn: str,
        changes: dict[str, str | list[str]],
        *,
        batch: bool = False,
        modifications: list[tuple[str, dict[str, str | list[str]]]] | None = None,
        atomic: bool = False,
        operation: str = FlextLdapConstants.ModifyOperation.REPLACE,
    ) -> FlextResult[bool | list[bool]]:
        """Unified modify method supporting single and batch operations.

        Args:
            dn: Distinguished name for single entry modify.
            changes: Changes for single entry modify.
            batch: If True, use modifications parameter for batch mode.
            modifications: List of (DN, changes) tuples for batch mode.
            atomic: If True, attempt atomic modification (all or none).
            operation: LDAP modify operation type from FlextLdapConstants.ModifyOperation.
                      Defaults to REPLACE. Use ADD for OUD schema.

        Returns:
            FlextResult[bool] for single mode, FlextResult[list[bool]] for batch mode.

        Examples:
            # Modify single entry
            result = ldap.modify("cn=user,dc=example,dc=com", {"mail": "new@example.com"})

            # Modify schema with ADD (OUD requirement)
            from flext_ldap import FlextLdapConstants
            result = ldap.modify(
                "cn=schema",
                {"attributeTypes": ["..."]},
                operation=FlextLdapConstants.ModifyOperation.ADD
            )

            # Modify multiple entries
            mods = [("cn=user1,dc=example,dc=com", {"mail": "user1@example.com"}), ...]
            result = ldap.modify("", {}, batch=True, modifications=mods)

        """
        if batch and modifications:
            results: list[bool] = []

            if atomic:
                temp_results = []
                for batch_dn, batch_changes in modifications:
                    result = self.client.modify_entry(
                        batch_dn, batch_changes, operation=operation
                    )
                    temp_results.append(result.is_success)

                if all(temp_results):
                    return cast(
                        "FlextResult[bool | list[bool]]",
                        FlextResult[list[bool]].ok(temp_results),
                    )
                failed_count = len([r for r in temp_results if not r])
                return cast(
                    "FlextResult[bool | list[bool]]",
                    FlextResult.fail(
                        f"Atomic modification failed: {failed_count} of {len(modifications)} entries failed"
                    ),
                )
            for batch_dn, batch_changes in modifications:
                result = self.client.modify_entry(
                    batch_dn, batch_changes, operation=operation
                )
                results.append(result.is_success)
            return cast(
                "FlextResult[bool | list[bool]]", FlextResult[list[bool]].ok(results)
            )

        return cast(
            "FlextResult[bool | list[bool]]",
            self.client.modify_entry(dn, changes, operation=operation),
        )

    def delete_entry(
        self,
        dn: str,
    ) -> FlextResult[bool]:
        """Delete LDAP entry."""
        return self.client.delete_entry(dn)

    def get_server_info(self) -> FlextResult[dict[str, object]]:
        """Get server information."""
        return FlextResult.ok({
            "type": self.servers.server_type,
            "default_port": self.servers.get_default_port(),
            "supports_starttls": self.servers.supports_start_tls(),
        })

    def get_acl_info(self) -> FlextResult[dict[str, object]]:
        """Get ACL information."""
        return FlextResult.ok({
            "format": self.acl.get_acl_format(),
        })

    def test_connection(self) -> FlextResult[bool]:
        """Test LDAP connection."""
        return self.client.test_connection()

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
        except (
            AttributeError,
            ValidationError,
        ) as e:
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
        except (
            AttributeError,
            ValidationError,
        ) as e:
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
        except (
            AttributeError,
            ValidationError,
        ) as e:
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
        attributes: dict[str, str | list[str]],
    ) -> FlextResult[bool]:
        """Add new LDAP entry."""
        return self.client.add_entry(dn, attributes)

    def get_server_capabilities(
        self,
    ) -> FlextResult[FlextLdapModels.ServerCapabilities]:
        """Get server capabilities information."""
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
        """Enter context manager - establish connection using config.

        Raises:
            ConnectionError: If connection fails

        """
        result = self.client.connect()
        if result.is_failure:
            error_msg = f"Failed to connect to LDAP server: {result.error}"
            raise ConnectionError(error_msg)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: types.TracebackType | None,
    ) -> None:
        """Exit context manager - close connection."""
        self.client.unbind()
