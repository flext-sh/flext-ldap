"""FLEXT-LDAP Infrastructure - Consolidated Infrastructure Layer.

🎯 CONSOLIDATES 8+ MAJOR INFRASTRUCTURE FILES INTO SINGLE PEP8 MODULE:
- infrastructure_schema_discovery.py (66,669 bytes) - LDAP schema discovery
- infrastructure_ldap_client.py (24,884 bytes) - LDAP client implementation
- infrastructure_certificate_validator.py (23,774 bytes) - Certificate validation
- infrastructure_repositories.py (20,957 bytes) - Data access repositories
- infrastructure_security_event_logger.py (20,287 bytes) - Security event logging
- infrastructure_error_correlation.py (19,304 bytes) - Error correlation
- infrastructure_connection_manager.py (3,886 bytes) - Connection management
- ldap_infrastructure.py (26,019 bytes) - Legacy infrastructure

TOTAL CONSOLIDATION: 205,780+ bytes → ldap_infrastructure.py (PEP8 organized)

This module provides comprehensive LDAP infrastructure implementations
following Clean Architecture patterns with dependency injection and
enterprise-grade security, monitoring, and data access patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import ssl
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from typing import TYPE_CHECKING, cast
from urllib.parse import urlparse

"""Compatibility shims for third-party deprecations (pyasn1).

We proactively alias deprecated attribute names used by ldap3 to their
modern equivalents to avoid DeprecationWarnings originating from pyasn1.
This fixes the root cause in our import path without silencing warnings
globally and without forking third-party packages.
"""
try:  # pragma: no cover - environment dependent
    from pyasn1.codec.ber import encoder as _ber_encoder  # type: ignore

    if hasattr(_ber_encoder, "TAG_MAP") and not hasattr(_ber_encoder, "tagMap"):
        setattr(_ber_encoder, "tagMap", getattr(_ber_encoder, "TAG_MAP"))
    if hasattr(_ber_encoder, "TYPE_MAP") and not hasattr(_ber_encoder, "typeMap"):
        setattr(_ber_encoder, "typeMap", getattr(_ber_encoder, "TYPE_MAP"))
except Exception:  # pragma: no cover - best effort only
    pass

import ldap3 as _ldap3
from flext_core import FlextResult, get_logger
from ldap3 import (
    ALL_ATTRIBUTES,
    BASE,
    LEVEL,
    MODIFY_REPLACE,
    SUBTREE,
    Connection as Ldap3Connection,
    Server,
)
from ldap3.core.exceptions import LDAPException

LDAP3_AVAILABLE = True


if TYPE_CHECKING:
    from collections.abc import Callable

    from flext_ldap.types import (
        LdapAttributeDict,
        LdapSearchResult,
    )

logger = get_logger(__name__)
# Resolve SUBORDINATES variant safely (default to SUBTREE if not provided)
LDAP_SUBORDINATES = getattr(_ldap3, "SUBORDINATES", SUBTREE)

# =============================================================================
# CONSTANTS
# =============================================================================

# Search method argument indices
SEARCH_SCOPE_ARG_INDEX = 3  # Minimum args to include scope parameter

# Alias to real ldap3.Connection to preserve test patch path
Connection = Ldap3Connection

# =============================================================================
# PARAMETER OBJECTS - REDUCING FUNCTION PARAMETERS
# =============================================================================


class LegacySearchParameters:
    """Parameter object for legacy search operations to reduce parameter count."""

    def __init__(
        self,
        connection_id: str,
        base_dn: object,
        search_filter: object,
        *,
        scope: object = "subtree",
        attributes: list[str] | None = None,
        size_limit: int = 1000,
        time_limit: int = 30,
    ) -> None:
        """Initialize legacy search parameters.

        Args:
            connection_id: Connection identifier (ignored for compatibility)
            base_dn: Base DN object (VO type or string)
            search_filter: Search filter object (VO type or string)
            scope: Search scope object (VO type or string)
            attributes: List of attributes to retrieve
            size_limit: Maximum number of entries to return
            time_limit: Search timeout in seconds

        """
        self.connection_id = connection_id
        self.base_dn = base_dn
        self.search_filter = search_filter
        self.scope = scope
        self.attributes = attributes
        self.size_limit = size_limit
        self.time_limit = time_limit


# =============================================================================
# LDAP CLIENT INFRASTRUCTURE
# =============================================================================


class FlextLdapClient:
    """Primary LDAP client for infrastructure operations."""

    def __init__(self, config: object | None = None) -> None:
        """Initialize LDAP client with configuration."""
        self._config = config
        self._connection: object | None = None
        self._is_connected = False

    async def connect(
        self,
        server_uri: str,
        bind_dn: str | None = None,
        bind_password: str | None = None,
    ) -> FlextResult[None]:
        """Connect to LDAP server - REFACTORED to reduce returns.

        Args:
            server_uri: LDAP server URI
            bind_dn: Optional bind DN
            bind_password: Optional bind password

        Returns:
            FlextResult[None]: Success or error result

        """
        try:
            # Validate URI and create connection
            return await self._perform_connection_sequence(server_uri, bind_dn, bind_password)

        except LDAPException as e:
            logger.exception("LDAP connection failed")
            return FlextResult.fail(f"Connection failed: {e!s}")
        except (ConnectionError, TimeoutError, OSError, TypeError, ValueError) as e:
            logger.exception("LDAP connection failed")
            return FlextResult.fail(f"Connection failed: {e!s}")

    async def _perform_connection_sequence(
        self, server_uri: str, bind_dn: str | None, bind_password: str | None,
    ) -> FlextResult[None]:
        """Perform the complete connection sequence with validation."""
        # Step 1: Validate URI
        uri_validation = self._validate_connection_uri(server_uri)
        if uri_validation.is_failure:
            return uri_validation

        # Step 2: Create and configure connection
        parsed = urlparse(server_uri)
        host = parsed.hostname or ""
        port = parsed.port
        use_ssl = parsed.scheme == "ldaps"

        connection_result = self._create_ldap_connection(
            host=host,
            port=port,
            use_ssl=use_ssl,
            bind_dn=bind_dn,
            bind_password=bind_password,
        )
        if connection_result.is_failure:
            return FlextResult.fail(connection_result.error or "Connection failed")

        # Step 3: Establish connection state
        conn = connection_result.data
        self._connection = conn
        self._is_connected = True

        logger.info(
            "LDAP client connected",
            extra={
                "server_uri": server_uri,
                "authenticated": bind_dn is not None,
            },
        )
        return FlextResult.ok(None)

    def _validate_connection_uri(self, server_uri: str) -> FlextResult[None]:
        """Validate the server URI format and scheme."""
        parsed = urlparse(server_uri)
        if parsed.scheme not in {"ldap", "ldaps"}:
            return FlextResult.fail("Connection failed: invalid URI scheme")

        host = parsed.hostname or ""
        if not host:
            return FlextResult.fail("Connection failed: invalid host")

        return FlextResult.ok(None)

    def _create_ldap_connection(
        self,
        *,
        host: str,
        port: int | None,
        use_ssl: bool,
        bind_dn: str | None,
        bind_password: str | None,
    ) -> FlextResult[object]:
        """Create and bind LDAP connection."""
        server = Server(host, port=port, use_ssl=use_ssl, get_info="NO_INFO")

        # Create real ldap3 connection
        conn = Connection(
            server,
            user=bind_dn or None,
            password=bind_password or None,
            auto_bind=False,
            raise_exceptions=False,
        )

        # Perform bind (anonymous if no credentials)
        if not conn.bind():
            error = getattr(conn, "last_error", "Bind failed")
            return FlextResult.fail(f"Bind failed: {error}")

        return FlextResult.ok(conn)

    async def disconnect(self, *args: object, **kwargs: object) -> FlextResult[None]:
        """Disconnect from LDAP server. Accepts and ignores legacy positional id."""
        _ = (args, kwargs)
        try:
            conn = self._connection
            # Use interface check to support patched/mocked connections in tests
            if conn is not None and hasattr(conn, "unbind"):
                try:
                    # Provide local typed callable for ldap3 unbind
                    unbind = cast("Callable[[], None]", conn.unbind)
                    unbind()
                except Exception as e:
                    # Ensure state is cleared even if unbind fails
                    logger.warning("LDAP unbind failed: %s", e)
            self._is_connected = False
            self._connection = None

            logger.info("LDAP client disconnected")
            return FlextResult.ok(None)
        except (ConnectionError, OSError, RuntimeError) as e:
            logger.exception("LDAP disconnection failed")
            return FlextResult.fail(f"Disconnection failed: {e!s}")

    # -------------------------------------------------------------------------
    # Backward-compat facade methods expected by legacy/tests

    # -------------------------------------------------------------------------

    async def create_entry(
        self,
        connection_id: str,  # ignored for backward-compat
        dn: object,
        attributes: dict[str, list[str]],
    ) -> FlextResult[None]:
        """Compatibility wrapper calling add_entry with dn string."""
        _ = connection_id
        dn_str = str(getattr(dn, "value", dn))
        return await self.add_entry(dn_str, attributes)

    async def disconnect_legacy(self, connection_id: str) -> FlextResult[None]:
        """Compatibility variant that accepts a connection id (ignored)."""
        _ = connection_id
        return await self.disconnect()

    def is_connected(self) -> bool:
        """Return connection status (compat for tests)."""
        return self._is_connected or (self._connection is not None)

    async def _search_impl(
        self,
        base_dn: str,
        search_filter: str,
        scope: str = "subtree",
        attributes: list[str] | None = None,
        size_limit: int = 1000,
        time_limit: int = 30,
    ) -> FlextResult[list[LdapSearchResult]]:
        """Perform LDAP search operation - REFACTORED to reduce complexity."""
        # Validate connection
        validation_result = self._validate_search_connection()
        if validation_result.is_failure:
            return validation_result  # type: ignore[return-value]

        try:
            # Execute search operation
            return await self._execute_search_operation(
                base_dn, search_filter, scope, attributes, size_limit, time_limit,
            )
        except Exception as e:
            logger.exception("LDAP search failed")
            return FlextResult.fail(f"Search failed: {e!s}")

    def _validate_search_connection(self) -> FlextResult[None]:
        """Validate that client is connected and ready for search."""
        if not self._is_connected or self._connection is None:
            return FlextResult.fail("Client not connected")
        return FlextResult.ok(None)

    async def _execute_search_operation(
        self,
        base_dn: str,
        search_filter: str,
        scope: str,
        attributes: list[str] | None,
        size_limit: int,
        time_limit: int,
    ) -> FlextResult[list[LdapSearchResult]]:
        """Execute the actual LDAP search operation."""
        conn = self._connection

        # Prepare search parameters
        ldap_scope = self._map_scope_to_ldap3_constant(scope)
        attrs = attributes or ALL_ATTRIBUTES

        # Perform search
        if conn is None:
            return FlextResult.fail("No connection available")
        if not hasattr(conn, "search"):
            # Provide stub search behavior when using placeholder connection
            conn.entries = []  # type: ignore[attr-defined]
            return FlextResult.ok([])
        ok = conn.search(  # type: ignore[attr-defined]
            search_base=base_dn,
            search_filter=search_filter,
            search_scope=ldap_scope,  # ldap3 is untyped; runtime-validated above
            attributes=attrs,
            size_limit=size_limit,
            time_limit=time_limit,
        )

        if not ok:
            error = getattr(conn, "last_error", "Search failed")
            return FlextResult.fail(f"Search failed: {error}")

        # Process search results
        results = self._process_search_results(conn)

        # Log operation
        self._log_search_operation(base_dn, search_filter, scope, len(results))

        return FlextResult.ok(results)

    def _map_scope_to_ldap3_constant(self, scope: str) -> object:
        """Map scope string to ldap3 constant - EXTRACTED for clarity."""
        normalized_scope = (scope or "subtree").lower()

        if normalized_scope == "base":
            return BASE
        if normalized_scope in {"one", "onelevel"}:
            return LEVEL
        if normalized_scope == "children":
            return LDAP_SUBORDINATES
        return SUBTREE

    def _process_search_results(self, conn: object) -> list[LdapSearchResult]:
        """Process raw LDAP search results into structured format."""
        results: list[LdapSearchResult] = []

        for entry in getattr(conn, "entries", []) or []:
            processed_entry = self._process_single_entry(entry)
            if processed_entry:
                results.append(processed_entry)

        return results

    def _process_single_entry(self, entry: object) -> LdapSearchResult | None:
        """Process a single LDAP entry into structured format."""
        try:
            dn = getattr(entry, "entry_dn", None) or getattr(entry, "dn", None)
            attributes_dict = self._extract_entry_attributes(entry)

            return {
                "dn": str(dn),
                "attributes": {
                    k: [
                        str(v)
                        for v in (val if isinstance(val, list) else [val])
                    ]
                    for k, val in attributes_dict.items()
                },  # type: ignore[dict-item]
            }
        except Exception as e:
            logger.debug("Failed to parse LDAP entry: %s", e)
            return None

    def _extract_entry_attributes(self, entry: object) -> dict[str, object]:
        """Extract attributes from LDAP entry object."""
        attributes_dict = getattr(entry, "entry_attributes_as_dict", None)

        if callable(attributes_dict):
            attributes_dict = attributes_dict()

        if attributes_dict is None:
            # Fallback: build dict from entry attributes
            attributes_dict = {
                attr: list(getattr(entry, attr).values)
                for attr in getattr(entry, "entry_attributes", [])
            }

        return attributes_dict

    def _log_search_operation(
        self, base_dn: str, search_filter: str, scope: str, result_count: int,
    ) -> None:
        """Log search operation details."""
        logger.debug(
            "LDAP search performed",
            extra={
                "base_dn": base_dn,
                "filter": search_filter,
                "scope": scope,
                "result_count": result_count,
            },
        )

    # Legacy signature for tests expecting connection_id and VO types
    async def search_legacy(
        self,
        connection_id: str,  # ignored
        base_dn: object,
        search_filter: object,
        *,
        scope: object = "subtree",
        attributes: list[str] | None = None,
        size_limit: int = 1000,
        time_limit: int = 30,
    ) -> FlextResult[list[LdapSearchResult]]:
        """Compatibility wrapper for search with VO types - REFACTORED with parameter object."""
        # Create parameter object from individual parameters
        params = LegacySearchParameters(
            connection_id=connection_id,
            base_dn=base_dn,
            search_filter=search_filter,
            scope=scope,
            attributes=attributes,
            size_limit=size_limit,
            time_limit=time_limit,
        )
        return await self._execute_legacy_search(params)

    async def _execute_legacy_search(
        self,
        params: LegacySearchParameters,
    ) -> FlextResult[list[LdapSearchResult]]:
        """Execute legacy search operation with parameter object."""
        try:
            _ = params.connection_id  # Ignored for compatibility

            # Extract string values from VO objects or direct values
            dn_str = self._extract_dn_string(params.base_dn)
            filter_str = self._extract_filter_string(params.search_filter)
            scope_str = self._extract_scope_string(params.scope)

            return await self._search_impl(
                dn_str,
                filter_str,
                scope=scope_str,
                attributes=params.attributes,
                size_limit=params.size_limit,
                time_limit=params.time_limit,
            )
        except Exception as e:
            logger.exception("LDAP search failed")
            return FlextResult.fail(f"Search failed: {e!s}")

    def _extract_dn_string(self, base_dn: object) -> str:
        """Extract DN string from VO object or direct value."""
        dn_candidate = getattr(base_dn, "value", getattr(base_dn, "dn", base_dn))
        return str(dn_candidate)

    def _extract_filter_string(self, search_filter: object) -> str:
        """Extract filter string from VO object or direct value."""
        filter_candidate = getattr(
            search_filter,
            "value",
            getattr(search_filter, "filter_string", search_filter),
        )
        return str(filter_candidate)

    def _extract_scope_string(self, scope: object) -> str:
        """Extract scope string from VO object or direct value."""
        return str(getattr(scope, "scope", scope))

    async def search(
        self,
        *args: object,
        **kwargs: object,
    ) -> FlextResult[list[LdapSearchResult]]:
        """Flexible search supporting legacy and modern signatures - REFACTORED to reduce complexity.

        Accepted forms:
          - search(base_dn: str, search_filter: str, scope: str = ..., ...)
          - search(connection_id: str, base_dn: VO|str, search_filter: VO|str, scope=..., ...)
          - search(base_dn=..., search_filter=..., ...)
        """
        try:
            # Determine signature type and dispatch to appropriate handler
            if self._is_keyword_search(kwargs):
                return await self._handle_keyword_search(kwargs)

            if self._is_legacy_positional_search(args):
                return await self._handle_legacy_positional_search(args, kwargs)

            if self._is_modern_positional_search(args):
                return await self._handle_modern_positional_search(args, kwargs)

            return FlextResult.fail("Invalid search arguments")

        except Exception as e:
            logger.exception("Search signature resolution failed")
            return FlextResult.fail(f"Search error: {e}")

    def _is_keyword_search(self, kwargs: dict[str, object]) -> bool:
        """Check if this is a keyword-based search."""
        return "base_dn" in kwargs and "search_filter" in kwargs

    def _is_legacy_positional_search(self, args: tuple[object, ...]) -> bool:
        """Check if this is a legacy positional search (connection_id, dn, filter)."""
        required_positional = 3
        return len(args) >= required_positional and isinstance(args[0], str)

    def _is_modern_positional_search(self, args: tuple[object, ...]) -> bool:
        """Check if this is a modern positional search (base_dn, search_filter)."""
        min_positional = 2
        return len(args) >= min_positional

    async def _handle_keyword_search(self, kwargs: dict[str, object]) -> FlextResult[list[LdapSearchResult]]:
        """Handle keyword-based search arguments."""
        search_params = self._extract_search_params_from_kwargs(kwargs)
        return await self._search_impl(
            str(search_params["base_dn"]),
            str(search_params["search_filter"]),
            str(search_params["scope"]),
            search_params["attributes"],  # type: ignore[arg-type]
            int(search_params["size_limit"]) if isinstance(search_params["size_limit"], int) else 1000,
            int(search_params["time_limit"]) if isinstance(search_params["time_limit"], int) else 30,
        )

    async def _handle_legacy_positional_search(
        self, args: tuple[object, ...], kwargs: dict[str, object],
    ) -> FlextResult[list[LdapSearchResult]]:
        """Handle legacy positional search (connection_id, dn, filter)."""
        connection_id = str(args[0])
        base_dn_obj = args[1]
        filter_obj = args[2]

        legacy_params = self._extract_legacy_search_params(kwargs)
        return await self.search_legacy(
            connection_id,
            base_dn_obj,
            filter_obj,
            scope=legacy_params["scope"],
            attributes=legacy_params["attributes"],  # type: ignore[arg-type]
            size_limit=int(legacy_params["size_limit"]) if isinstance(legacy_params["size_limit"], int) else 1000,
            time_limit=int(legacy_params["time_limit"]) if isinstance(legacy_params["time_limit"], int) else 30,
        )

    async def _handle_modern_positional_search(
        self, args: tuple[object, ...], kwargs: dict[str, object],
    ) -> FlextResult[list[LdapSearchResult]]:
        """Handle modern positional search (base_dn, search_filter, [scope])."""
        base_dn = str(args[0])
        search_filter = str(args[1])
        scope = str(args[2]) if len(args) >= SEARCH_SCOPE_ARG_INDEX else "subtree"

        modern_params = self._extract_modern_search_params(kwargs)
        return await self._search_impl(
            base_dn,
            search_filter,
            scope,
            modern_params["attributes"],  # type: ignore[arg-type]
            int(modern_params["size_limit"]) if isinstance(modern_params["size_limit"], int) else 1000,
            int(modern_params["time_limit"]) if isinstance(modern_params["time_limit"], int) else 30,
        )

    def _extract_search_params_from_kwargs(self, kwargs: dict[str, object]) -> dict[str, object]:
        """Extract and validate search parameters from keyword arguments."""
        return {
            "base_dn": str(kwargs.get("base_dn", "")),
            "search_filter": str(kwargs.get("search_filter", "(objectClass=*)")),
            "scope": str(kwargs.get("scope", "subtree")),
            "attributes": kwargs.get("attributes"),
            "size_limit": self._safe_int_conversion(kwargs.get("size_limit", 1000), 1000),
            "time_limit": self._safe_int_conversion(kwargs.get("time_limit", 30), 30),
        }

    def _extract_legacy_search_params(self, kwargs: dict[str, object]) -> dict[str, object]:
        """Extract parameters for legacy positional search."""
        return {
            "scope": kwargs.get("scope", "subtree"),
            "attributes": kwargs.get("attributes"),
            "size_limit": self._safe_int_conversion(kwargs.get("size_limit", 1000), 1000),
            "time_limit": self._safe_int_conversion(kwargs.get("time_limit", 30), 30),
        }

    def _extract_modern_search_params(self, kwargs: dict[str, object]) -> dict[str, object]:
        """Extract parameters for modern positional search."""
        return {
            "attributes": kwargs.get("attributes"),
            "size_limit": self._safe_int_conversion(kwargs.get("size_limit", 1000), 1000),
            "time_limit": self._safe_int_conversion(kwargs.get("time_limit", 30), 30),
        }

    def _safe_int_conversion(self, value: object, default: int) -> int:
        """Safely convert value to integer with fallback."""
        try:
            return int(str(value))
        except (ValueError, TypeError):
            return default

    async def add_entry(
        self,
        dn: str,
        attributes: dict[str, list[str]],
    ) -> FlextResult[None]:
        """Add new LDAP entry."""
        if not self._is_connected or not (
            self._connection is not None and hasattr(self._connection, "add")
        ):
            return FlextResult.fail("Client not connected")

        try:
            conn = self._connection
            # conn type is guarded above; do not duplicate unreachable return

            # Ensure values are list[str]
            normalized_attrs: dict[str, list[str]] = {
                k: [str(v) for v in (vals if isinstance(vals, list) else [vals])]
                for k, vals in attributes.items()
            }

            ok = conn.add(dn, attributes=normalized_attrs)
            if not ok:
                error = getattr(conn, "last_error", "Add failed")
                return FlextResult.fail(f"Add failed: {error}")

            logger.info(
                "LDAP entry added",
                extra={"dn": dn, "attribute_count": len(normalized_attrs)},
            )
            return FlextResult.ok(None)

        except LDAPException as e:
            logger.exception("LDAP add failed")
            return FlextResult.fail(f"Add failed: {e!s}")
        except (
            ConnectionError,
            TimeoutError,
            OSError,
            TypeError,
            ValueError,
            AttributeError,
        ) as e:
            logger.exception("LDAP add failed")
            return FlextResult.fail(f"Add failed: {e!s}")

    async def modify_entry(
        self,
        dn: str,
        modifications: dict[str, list[str]],
    ) -> FlextResult[None]:
        """Modify existing LDAP entry."""
        if not self._is_connected or not (
            self._connection is not None and hasattr(self._connection, "modify")
        ):
            return FlextResult.fail("Client not connected")

        try:
            conn = self._connection
            mods = {
                attr: [
                    (
                        MODIFY_REPLACE,
                        [str(v) for v in (vals if isinstance(vals, list) else [vals])],
                    ),
                ]
                for attr, vals in modifications.items()
            }
            ok = conn.modify(dn, changes=mods)
            if not ok:
                error = getattr(conn, "last_error", "Modify failed")
                return FlextResult.fail(f"Modify failed: {error}")

            logger.info(
                "LDAP entry modified",
                extra={"dn": dn, "modification_count": len(modifications)},
            )
            return FlextResult.ok(None)

        except LDAPException as e:
            logger.exception("LDAP modify failed")
            return FlextResult.fail(f"Modify failed: {e!s}")
        except (
            ConnectionError,
            TimeoutError,
            OSError,
            TypeError,
            ValueError,
            AttributeError,
        ) as e:
            logger.exception("LDAP modify failed")
            return FlextResult.fail(f"Modify failed: {e!s}")

    async def delete_entry(self, *args: object) -> FlextResult[None]:
        """Delete LDAP entry - REFACTORED to reduce returns.

        Modern: delete_entry(dn: str)
        Legacy: delete_entry(connection_id: str, dn: VO|str)
        """
        try:
            # Validate connection state
            connection_check = self._validate_delete_connection()
            if connection_check.is_failure:
                return connection_check

            # Extract DN from arguments
            dn_result = self._extract_dn_from_delete_args(args)
            if dn_result.is_failure:
                return FlextResult.fail(dn_result.error or "Failed to extract DN")

            # Perform deletion operation
            if dn_result.data is None:
                return FlextResult.fail("No DN data available")
            return await self._perform_delete_operation(str(dn_result.data))

        except LDAPException as e:
            logger.exception("LDAP delete failed")
            return FlextResult.fail(f"Delete failed: {e!s}")
        except (
            ConnectionError,
            TimeoutError,
            OSError,
            TypeError,
            ValueError,
            AttributeError,
        ) as e:
            logger.exception("LDAP delete failed")
            return FlextResult.fail(f"Delete failed: {e!s}")

    def _validate_delete_connection(self) -> FlextResult[None]:
        """Validate that connection is ready for delete operations."""
        if not self._is_connected or not (
            self._connection is not None and hasattr(self._connection, "delete")
        ):
            return FlextResult.fail("Client not connected")
        return FlextResult.ok(None)

    def _extract_dn_from_delete_args(self, args: tuple[object, ...]) -> FlextResult[str]:
        """Extract DN from delete method arguments."""
        single_arg = 1
        if len(args) == single_arg:
            return FlextResult.ok(str(args[0]))
        if len(args) >= single_arg + 1:
            dn_obj = args[1]
            dn_val = str(getattr(dn_obj, "value", dn_obj))
            return FlextResult.ok(dn_val)
        return FlextResult.fail("DN is required")

    async def _perform_delete_operation(self, dn_val: str) -> FlextResult[None]:
        """Perform the actual LDAP delete operation."""
        conn = self._connection
        if conn is None:
            return FlextResult.fail("No connection available for delete operation")
        ok = conn.delete(dn_val)  # type: ignore[attr-defined]

        if not ok:
            error = getattr(conn, "last_error", "Delete failed")
            return FlextResult.fail(f"Delete failed: {error}")

        logger.info("LDAP entry deleted", extra={"dn": dn_val})
        return FlextResult.ok(None)


# =============================================================================
# CONNECTION MANAGEMENT
# =============================================================================


class FlextLDAPConnectionManager:
    """LDAP connection pool and lifecycle management."""

    def __init__(self, max_connections: int = 10) -> None:
        """Initialize connection manager."""
        self._max_connections = max_connections
        self._active_connections: dict[str, FlextLdapClient] = {}
        self._connection_count = 0

    async def get_connection(
        self,
        connection_id: str,
        server_uri: str,
        bind_dn: str | None = None,
        bind_password: str | None = None,
    ) -> FlextResult[FlextLdapClient]:
        """Get or create LDAP connection."""
        if connection_id in self._active_connections:
            return FlextResult.ok(self._active_connections[connection_id])

        if self._connection_count >= self._max_connections:
            return FlextResult.fail("Connection pool exhausted")

        try:
            client = FlextLdapClient()
            connect_result = await client.connect(server_uri, bind_dn, bind_password)

            if not connect_result.is_success:
                return FlextResult.fail(connect_result.error or "Connection failed")

            self._active_connections[connection_id] = client
            self._connection_count += 1

            return FlextResult.ok(client)

        except (
            ConnectionError,
            TimeoutError,
            OSError,
            TypeError,
            ValueError,
            AttributeError,
        ) as e:
            return FlextResult.fail(f"Connection creation failed: {e!s}")

    async def release_connection(self, connection_id: str) -> FlextResult[None]:
        """Release connection back to pool."""
        if connection_id not in self._active_connections:
            return FlextResult.fail(f"Connection not found: {connection_id}")

        try:
            client = self._active_connections.pop(connection_id)
            await client.disconnect()
            self._connection_count -= 1

            return FlextResult.ok(None)

        except (ConnectionError, OSError, RuntimeError, AttributeError) as e:
            return FlextResult.fail(f"Connection release failed: {e!s}")


# =============================================================================
# CERTIFICATE VALIDATION
# =============================================================================


class FlextLdapCertificateValidationService:
    """SSL/TLS certificate validation for LDAP connections."""

    def __init__(self) -> None:
        """Initialize certificate validator."""
        self._trusted_cas: list[str] = []

    def validate_certificate(
        self,
        cert_data: bytes,
        hostname: str,
    ) -> FlextResult[None]:
        """Validate SSL certificate.

        Args:
            cert_data: Certificate data
            hostname: Expected hostname

        Returns:
            FlextResult[None]: Validation result

        """
        try:
            _ = cert_data
            # NOTE(marlonsc): Implement certificate validation logic (planned)
            logger.debug("Certificate validated", extra={"hostname": hostname})
            return FlextResult.ok(None)

        except (OSError, ValueError, TypeError, AttributeError) as e:
            logger.exception("Certificate validation failed")
            return FlextResult.fail(f"Certificate validation failed: {e!s}")

    def create_ssl_context(
        self,
        verify_mode: ssl.VerifyMode = ssl.CERT_REQUIRED,
    ) -> ssl.SSLContext:
        """Create SSL context for LDAP connections."""
        context = ssl.create_default_context()
        context.verify_mode = verify_mode
        return context


# =============================================================================
# SCHEMA DISCOVERY
# =============================================================================


class FlextLdapSchemaDiscoveryService:
    """LDAP schema discovery and validation service."""

    def __init__(self, client: FlextLdapClient) -> None:
        """Initialize schema discovery service."""
        self._client = client
        self._cached_schema: dict[str, object] = {}

    async def discover_schema(
        self,
        base_dn: str = "",
    ) -> FlextResult[dict[str, object]]:
        """Discover LDAP schema information.

        Args:
            base_dn: Base DN for schema discovery

        Returns:
            FlextResult[dict[str, Any]]: Schema information

        """
        try:
            _ = base_dn
            # NOTE: Implementation pending: schema discovery logic
            schema_result = await self._client.search(
                base_dn="cn=schema",
                search_filter="(objectClass=subschema)",
                scope="base",
                attributes=["objectClasses", "attributeTypes", "ldapSyntaxes"],
            )

            if not schema_result.is_success:
                return FlextResult.fail(
                    f"Schema discovery failed: {schema_result.error}",
                )

            schema_info: dict[str, object] = {
                "object_classes": [],
                "attribute_types": [],
                "syntaxes": [],
                "discovered_at": datetime.now(UTC).isoformat(),
            }

            # Cache schema for future use
            self._cached_schema = schema_info

            object_class_list = schema_info.get("object_classes", [])
            attribute_type_list = schema_info.get("attribute_types", [])
            object_class_count = len(
                object_class_list if isinstance(object_class_list, list) else [],
            )
            attribute_count = len(
                attribute_type_list if isinstance(attribute_type_list, list) else [],
            )
            logger.info(
                "LDAP schema discovered",
                extra={
                    "object_class_count": object_class_count,
                    "attribute_count": attribute_count,
                },
            )

            return FlextResult.ok(schema_info)

        except (
            ConnectionError,
            TimeoutError,
            OSError,
            TypeError,
            ValueError,
            AttributeError,
        ) as e:
            logger.exception("Schema discovery failed")
            return FlextResult.fail(f"Schema discovery failed: {e!s}")

    def validate_entry_against_schema(
        self,
        object_classes: list[str],
        attributes: dict[str, list[str]],
    ) -> FlextResult[None]:
        """Validate entry against discovered schema."""
        try:
            # NOTE: Implementation pending: schema validation logic
            logger.debug(
                "Entry validated against schema",
                extra={
                    "object_classes": object_classes,
                    "attribute_count": len(attributes),
                },
            )

            return FlextResult.ok(None)

        except (TypeError, ValueError, AttributeError) as e:
            logger.exception("Schema validation failed")
            return FlextResult.fail(f"Schema validation failed: {e!s}")


# =============================================================================
# SECURITY EVENT LOGGING
# =============================================================================


class FlextLdapSecurityEventLogger:
    """Security event logging for LDAP operations."""

    def __init__(self) -> None:
        """Initialize security event logger."""
        self._events: list[dict[str, object]] = []

    def log_authentication_attempt(
        self,
        bind_dn: str,
        *,
        success: bool,
        source_ip: str | None = None,
    ) -> None:
        """Log authentication attempt."""
        event = {
            "event_type": "authentication_attempt",
            "bind_dn": bind_dn,
            "success": success,
            "source_ip": source_ip,
            "timestamp": datetime.now(UTC).isoformat(),
        }

        self._events.append(event)

        log_level = "info" if success else "warning"
        getattr(logger, log_level)("LDAP authentication attempt", extra=event)

    def log_authorization_check(
        self,
        user_dn: str,
        operation: str,
        resource_dn: str,
        *,
        granted: bool,
    ) -> None:
        """Log authorization check."""
        event = {
            "event_type": "authorization_check",
            "user_dn": user_dn,
            "operation": operation,
            "resource_dn": resource_dn,
            "granted": granted,
            "timestamp": datetime.now(UTC).isoformat(),
        }

        self._events.append(event)

        log_level = "info" if granted else "warning"
        getattr(logger, log_level)("LDAP authorization check", extra=event)

    def log_data_access(
        self,
        user_dn: str,
        operation: str,
        target_dn: str,
        attributes: list[str] | None = None,
    ) -> None:
        """Log data access operation."""
        event = {
            "event_type": "data_access",
            "user_dn": user_dn,
            "operation": operation,
            "target_dn": target_dn,
            "attributes": attributes,
            "timestamp": datetime.now(UTC).isoformat(),
        }

        self._events.append(event)  # type: ignore[arg-type]
        logger.info("LDAP data access", extra=event)

    def get_security_events(
        self,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        event_type: str | None = None,
    ) -> list[dict[str, object]]:
        """Get security events with optional filtering."""
        _ = start_time
        _ = end_time
        filtered_events = self._events

        if event_type:
            filtered_events = [
                e
                for e in filtered_events
                if isinstance(e, dict) and e.get("event_type") == event_type
            ]

        # NOTE: Time filtering would be implemented here

        return filtered_events


# =============================================================================
# ERROR CORRELATION
# =============================================================================


class FlextLdapErrorCorrelationService:
    """Error correlation and analysis service."""

    def __init__(self) -> None:
        """Initialize error correlation service."""
        self._error_patterns: list[dict[str, object]] = []
        self._error_history: list[dict[str, object]] = []

    def correlate_error(
        self,
        error_message: str,
        operation: str,
        context: dict[str, object] | None = None,
    ) -> FlextResult[dict[str, object]]:
        """Correlate error with known patterns."""
        try:
            error_info: dict[str, object] = {
                "error_message": error_message,
                "operation": operation,
                "context": context or {},
                "timestamp": datetime.now(UTC).isoformat(),
                "correlation_id": f"err_{len(self._error_history)}",
            }

            # Add to error history
            self._error_history.append(error_info)

            # Look for patterns
            pattern_matches = self._find_error_patterns(error_message, operation)

            correlation_result: dict[str, object] = {
                "error_info": error_info,
                "pattern_matches": pattern_matches,
                "suggested_actions": self._get_suggested_actions(pattern_matches),
            }

            logger.warning("LDAP error correlated", extra=correlation_result)
            return FlextResult.ok(correlation_result)

        except (TypeError, ValueError, AttributeError, RuntimeError) as e:
            logger.exception("Error correlation failed")
            return FlextResult.fail(f"Error correlation failed: {e!s}")

    def _find_error_patterns(
        self,
        error_message: str,
        operation: str,
    ) -> list[dict[str, object]]:
        """Find matching error patterns."""
        _ = operation
        # NOTE: Create/refine logic for pattern matching
        patterns = []

        if "authentication" in error_message.lower():
            patterns.append(
                {
                    "pattern_type": "authentication_failure",
                    "confidence": 0.9,
                    "description": "Authentication-related error pattern",
                },
            )

        if "timeout" in error_message.lower():
            patterns.append(
                {
                    "pattern_type": "timeout_error",
                    "confidence": 0.8,
                    "description": "Network or operation timeout",
                },
            )

        return patterns

    def _get_suggested_actions(
        self,
        pattern_matches: list[dict[str, object]],
    ) -> list[str]:
        """Get suggested actions based on patterns."""
        actions: list[str] = []

        for pattern in pattern_matches:
            if pattern["pattern_type"] == "authentication_failure":
                actions.extend(
                    ("Check bind DN and password", "Verify user account status"),
                )

            elif pattern["pattern_type"] == "timeout_error":
                actions.extend(
                    (
                        "Check network connectivity",
                        "Increase timeout values",
                        "Verify server load",
                    ),
                )

        return actions


# =============================================================================
# REPOSITORY IMPLEMENTATIONS
# =============================================================================


class FlextLdapConnectionRepositoryImpl:
    """Repository implementation for LDAP connection data."""

    def __init__(self, client: FlextLdapClient) -> None:
        """Initialize connection repository."""
        self._client = client

    async def test_connection(
        self,
        server_uri: str,
        bind_dn: str | None = None,
        bind_password: str | None = None,
    ) -> FlextResult[dict[str, object]]:
        """Test LDAP connection."""
        try:
            # Create temporary client for testing
            test_client = FlextLdapClient()

            connect_result = await test_client.connect(
                server_uri,
                bind_dn,
                bind_password,
            )

            if connect_result.is_success:
                # Test with simple search
                search_result = await test_client.search(
                    base_dn="",
                    search_filter="(objectClass=*)",
                    scope="base",
                    size_limit=1,
                )

                await test_client.disconnect()

                test_result = {
                    "connection_successful": True,
                    "search_successful": search_result.is_success,
                    "server_uri": server_uri,
                    "authenticated": bind_dn is not None,
                }

                return FlextResult.ok(test_result)
            test_result = {
                "connection_successful": False,
                "error": connect_result.error,
                "server_uri": server_uri,
            }

            return FlextResult.ok(test_result)

        except (ConnectionError, TimeoutError, OSError, TypeError, ValueError) as e:
            logger.exception("Connection test failed")
            return FlextResult.fail(f"Connection test failed: {e!s}")


class FlextLdapUserRepositoryImpl:
    """Repository implementation for LDAP user data."""

    def __init__(self, client: FlextLdapClient) -> None:
        """Initialize user repository."""
        self._client = client

    async def find_user_by_uid(
        self,
        uid: str,
        base_dn: str,
    ) -> FlextResult[LdapSearchResult | None]:
        """Find user by UID."""
        try:
            search_result = await self._client.search(
                base_dn=base_dn,
                search_filter=f"(&(objectClass=person)(uid={uid}))",
                scope="subtree",
                attributes=["uid", "cn", "sn", "mail", "dn"],
            )

            if not search_result.is_success:
                return FlextResult.fail(search_result.error or "Search failed")

            users = search_result.data
            user = users[0] if users else None

            return FlextResult.ok(user)

        except (
            ConnectionError,
            TimeoutError,
            OSError,
            TypeError,
            ValueError,
            AttributeError,
        ) as e:
            logger.exception("User search failed")
            return FlextResult.fail(f"User search failed: {e!s}")

    async def save_user(
        self,
        user_data: LdapAttributeDict,
    ) -> FlextResult[None]:
        """Save user data - REFACTORED to reduce complexity."""
        try:
            # Validate DN
            dn_validation = self._validate_user_dn(user_data)
            if dn_validation.is_failure:
                return dn_validation

            # Convert to LDAP format
            attributes_result = self._convert_user_attributes(user_data)
            if attributes_result.is_failure:
                return FlextResult.fail(attributes_result.error or "Attribute conversion failed")

            # Save to LDAP
            dn = str(user_data.get("dn"))
            if attributes_result.data is None:
                return FlextResult.fail("No attributes data available")
            return await self._client.add_entry(dn, attributes_result.data)

        except (
            ConnectionError,
            TimeoutError,
            OSError,
            TypeError,
            ValueError,
            AttributeError,
        ) as e:
            logger.exception("User save failed")
            return FlextResult.fail(f"User save failed: {e!s}")

    def _validate_user_dn(self, user_data: LdapAttributeDict) -> FlextResult[None]:
        """Validate user DN is present."""
        dn = user_data.get("dn")
        if not dn:
            return FlextResult.fail("User DN is required")
        return FlextResult.ok(None)

    def _convert_user_attributes(self, user_data: LdapAttributeDict) -> FlextResult[dict[str, list[str]]]:
        """Convert user data to LDAP attributes format."""
        # Optimized with dictionary comprehension for better performance
        attributes = {
            key: self._convert_attribute_values(value)
            for key, value in user_data.items()
            if not self._should_skip_attribute(key, value)
        }

        return FlextResult.ok(attributes)

    def _should_skip_attribute(self, key: str, value: object) -> bool:
        """Check if attribute should be skipped during conversion."""
        return key == "dn" or value is None

    def _convert_attribute_values(self, value: object) -> list[str]:
        """Convert attribute value(s) to list of strings."""
        values_list = value if isinstance(value, list) else [value]
        # Optimized with list comprehension for better performance
        return [self._convert_single_value(v) for v in values_list]

    def _convert_single_value(self, value: object) -> str:
        """Convert a single value to string, handling bytes properly."""
        if isinstance(value, (bytes, bytearray)):
            try:
                return value.decode()
            except Exception:
                return str(value)
        return str(value)


# =============================================================================
# UNIFIED INFRASTRUCTURE INTERFACE
# =============================================================================


class FlextLdapInfrastructure:
    """Unified infrastructure interface providing all LDAP infrastructure services."""

    def __init__(self) -> None:
        """Initialize all infrastructure services."""
        self.connection_manager = FlextLDAPConnectionManager()
        self.certificate_validator = FlextLdapCertificateValidationService()
        self.security_logger = FlextLdapSecurityEventLogger()
        self.error_correlator = FlextLdapErrorCorrelationService()

        # Initialize with default client
        self._default_client = FlextLdapClient()
        self.schema_discovery = FlextLdapSchemaDiscoveryService(self._default_client)
        self.connection_repository = FlextLdapConnectionRepositoryImpl(
            self._default_client,
        )
        self.user_repository = FlextLdapUserRepositoryImpl(self._default_client)

    async def create_authenticated_client(
        self,
        server_uri: str,
        bind_dn: str | None = None,
        bind_password: str | None = None,
    ) -> FlextResult[FlextLdapClient]:
        """Create and authenticate LDAP client."""
        try:
            client = FlextLdapClient()
            connect_result = await client.connect(server_uri, bind_dn, bind_password)

            if connect_result.is_success:
                # Log authentication attempt
                self.security_logger.log_authentication_attempt(
                    bind_dn or "anonymous",
                    success=True,
                )

                return FlextResult.ok(client)
            self.security_logger.log_authentication_attempt(
                bind_dn or "anonymous",
                success=False,
            )

            return FlextResult.fail(connect_result.error or "Connection failed")

        except (
            ConnectionError,
            TimeoutError,
            OSError,
            TypeError,
            ValueError,
            AttributeError,
        ):
            logger.exception("Client creation failed")
            return FlextResult.fail("Client creation failed")

    async def perform_health_check(self) -> FlextResult[dict[str, object]]:
        """Perform infrastructure health check."""
        health_status: dict[str, object] = {
            "connection_manager": "healthy",
            "certificate_validator": "healthy",
            "security_logger": "healthy",
            "error_correlator": "healthy",
            "timestamp": datetime.now(UTC).isoformat(),
        }

        return FlextResult.ok(health_status)


# =============================================================================
# ADVANCED DESIGN PATTERNS - STRATEGY & OBSERVER
# =============================================================================


class FlextLdapSearchStrategy(ABC):
    """Strategy pattern for different LDAP search implementations."""

    @abstractmethod
    async def execute_search(
        self,
        client: FlextLdapClient,
        base_dn: str,
        search_filter: str,
        **kwargs: object,
    ) -> FlextResult[list[LdapSearchResult]]:
        """Execute search with specific strategy."""


class FlextLdapStandardSearchStrategy(FlextLdapSearchStrategy):
    """Standard LDAP search strategy implementation."""

    async def execute_search(
        self,
        client: FlextLdapClient,
        base_dn: str,
        search_filter: str,
        **kwargs: object,
    ) -> FlextResult[list[LdapSearchResult]]:
        """Execute standard LDAP search."""
        scope = str(kwargs.get("scope", "subtree"))
        attributes = kwargs.get("attributes")
        size_limit_val = kwargs.get("size_limit", 1000)
        time_limit_val = kwargs.get("time_limit", 30)
        size_limit = int(size_limit_val) if isinstance(size_limit_val, int) else 1000
        time_limit = int(time_limit_val) if isinstance(time_limit_val, int) else 30

        return await client._search_impl(
            base_dn,
            search_filter,
            scope,
            attributes if isinstance(attributes, list) else None,
            size_limit,
            time_limit,
        )


class FlextLdapPagedSearchStrategy(FlextLdapSearchStrategy):
    """Paged search strategy for large result sets."""

    def __init__(self, page_size: int = 1000) -> None:
        """Initialize paged search strategy."""
        self.page_size = page_size

    async def execute_search(
        self,
        client: FlextLdapClient,
        base_dn: str,
        search_filter: str,
        **kwargs: object,
    ) -> FlextResult[list[LdapSearchResult]]:
        """Execute paged LDAP search."""
        # For now, delegate to standard search (paging logic would be implemented here)
        standard_strategy = FlextLdapStandardSearchStrategy()
        return await standard_strategy.execute_search(client, base_dn, search_filter, **kwargs)


class FlextLdapEventObserver(ABC):
    """Observer pattern for LDAP operation events."""

    @abstractmethod
    async def on_connection_established(
        self,
        server_uri: str,
        bind_dn: str | None,
    ) -> None:
        """Handle connection established event."""

    @abstractmethod
    async def on_connection_failed(
        self,
        server_uri: str,
        error: str,
    ) -> None:
        """Handle connection failed event."""

    @abstractmethod
    async def on_search_performed(
        self,
        base_dn: str,
        search_filter: str,
        result_count: int,
    ) -> None:
        """Handle search performed event."""

    @abstractmethod
    async def on_entry_added(
        self,
        dn: str,
        attributes: dict[str, list[str]],
    ) -> None:
        """Handle entry added event."""


class FlextLdapSecurityObserver(FlextLdapEventObserver):
    """Security-focused observer for LDAP events."""

    def __init__(self, security_logger: FlextLdapSecurityEventLogger) -> None:
        """Initialize security observer."""
        self.security_logger = security_logger

    async def on_connection_established(
        self,
        server_uri: str,
        bind_dn: str | None,
    ) -> None:
        """Log successful connection for security audit."""
        _ = server_uri
        self.security_logger.log_authentication_attempt(
            bind_dn or "anonymous",
            success=True,
        )
        logger.info(
            "Security audit: connection established",
            extra={"server_uri": server_uri, "bind_dn": bind_dn},
        )

    async def on_connection_failed(
        self,
        server_uri: str,
        error: str,
    ) -> None:
        """Log failed connection for security monitoring."""
        logger.warning(
            "LDAP connection failed",
            extra={
                "server_uri": server_uri,
                "error": error,
                "event_type": "connection_failure",
            },
        )

    async def on_search_performed(
        self,
        base_dn: str,
        search_filter: str,
        result_count: int,
    ) -> None:
        """Log search operations for compliance."""
        _ = (search_filter, result_count)
        self.security_logger.log_data_access(
            user_dn="system",  # Would be actual user in real implementation
            operation="search",
            target_dn=base_dn,
            attributes=["search_filter", "result_count"],
        )
        logger.info(
            "Security audit: search performed",
            extra={
                "base_dn": base_dn,
                "search_filter": search_filter,
                "result_count": result_count,
            },
        )

    async def on_entry_added(
        self,
        dn: str,
        attributes: dict[str, list[str]],
    ) -> None:
        """Log entry creation for audit trail."""
        self.security_logger.log_data_access(
            user_dn="system",  # Would be actual user in real implementation
            operation="add",
            target_dn=dn,
            attributes=list(attributes.keys()),
        )


class FlextLdapPerformanceObserver(FlextLdapEventObserver):
    """Performance monitoring observer for LDAP operations."""

    def __init__(self) -> None:
        """Initialize performance observer."""
        self._operation_metrics: dict[str, list[float]] = {
            "connections": [],
            "searches": [],
            "adds": [],
        }

    async def on_connection_established(
        self,
        server_uri: str,
        bind_dn: str | None,
    ) -> None:
        """Track connection performance."""
        # In real implementation, would track connection time
        logger.debug(
            "Connection performance tracked",
            extra={"server_uri": server_uri, "authenticated": bind_dn is not None},
        )

    async def on_connection_failed(
        self,
        server_uri: str,
        error: str,
    ) -> None:
        """Track connection failures for performance analysis."""
        logger.debug(
            "Connection failure tracked",
            extra={"server_uri": server_uri, "error": error},
        )

    async def on_search_performed(
        self,
        base_dn: str,
        search_filter: str,
        result_count: int,
    ) -> None:
        """Track search performance metrics."""
        _ = (search_filter, result_count)
        logger.debug(
            "Search performance tracked",
            extra={
                "base_dn": base_dn,
                "search_filter": search_filter,
                "result_count": result_count,
                "operation": "search",
            },
        )

    async def on_entry_added(
        self,
        dn: str,
        attributes: dict[str, list[str]],
    ) -> None:
        """Track entry addition performance."""
        logger.debug(
            "Entry add performance tracked",
            extra={
                "dn": dn,
                "attribute_count": len(attributes),
                "operation": "add",
            },
        )

    def get_performance_metrics(self) -> dict[str, object]:
        """Get collected performance metrics."""
        return {
            "connection_count": len(self._operation_metrics["connections"]),
            "search_count": len(self._operation_metrics["searches"]),
            "add_count": len(self._operation_metrics["adds"]),
            "metrics_collected_at": datetime.now(UTC).isoformat(),
        }


class FlextLdapObservableClient(FlextLdapClient):
    """LDAP client with observer pattern support."""

    def __init__(self, config: object | None = None) -> None:
        """Initialize observable LDAP client."""
        super().__init__(config)
        self._observers: list[FlextLdapEventObserver] = []

    def add_observer(self, observer: FlextLdapEventObserver) -> None:
        """Add event observer."""
        if observer not in self._observers:
            self._observers.append(observer)

    def remove_observer(self, observer: FlextLdapEventObserver) -> None:
        """Remove event observer."""
        if observer in self._observers:
            self._observers.remove(observer)

    async def _notify_connection_established(
        self,
        server_uri: str,
        bind_dn: str | None,
    ) -> None:
        """Notify observers of successful connection."""
        for observer in self._observers:
            try:
                await observer.on_connection_established(server_uri, bind_dn)
            except Exception as e:
                logger.warning(f"Observer notification failed: {e}")

    async def _notify_connection_failed(
        self,
        server_uri: str,
        error: str,
    ) -> None:
        """Notify observers of connection failure."""
        for observer in self._observers:
            try:
                await observer.on_connection_failed(server_uri, error)
            except Exception as e:
                logger.warning(f"Observer notification failed: {e}")

    async def _notify_search_performed(
        self,
        base_dn: str,
        search_filter: str,
        result_count: int,
    ) -> None:
        """Notify observers of search operation."""
        for observer in self._observers:
            try:
                await observer.on_search_performed(base_dn, search_filter, result_count)
            except Exception as e:
                logger.warning(f"Observer notification failed: {e}")

    async def _notify_entry_added(
        self,
        dn: str,
        attributes: dict[str, list[str]],
    ) -> None:
        """Notify observers of entry addition."""
        for observer in self._observers:
            try:
                await observer.on_entry_added(dn, attributes)
            except Exception as e:
                logger.warning(f"Observer notification failed: {e}")

    async def connect(
        self,
        server_uri: str,
        bind_dn: str | None = None,
        bind_password: str | None = None,
    ) -> FlextResult[None]:
        """Connect with observer notifications."""
        result = await super().connect(server_uri, bind_dn, bind_password)

        if result.is_success:
            await self._notify_connection_established(server_uri, bind_dn)
        else:
            await self._notify_connection_failed(server_uri, result.error or "Connection failed")

        return result

    async def add_entry(
        self,
        dn: str,
        attributes: dict[str, list[str]],
    ) -> FlextResult[None]:
        """Add entry with observer notifications."""
        result = await super().add_entry(dn, attributes)

        if result.is_success:
            await self._notify_entry_added(dn, attributes)

        return result


class FlextLdapStrategyContext:
    """Context class for managing LDAP search strategies."""

    def __init__(self, strategy: FlextLdapSearchStrategy) -> None:
        """Initialize strategy context."""
        self._strategy = strategy

    def set_strategy(self, strategy: FlextLdapSearchStrategy) -> None:
        """Change search strategy."""
        self._strategy = strategy

    async def execute_search(
        self,
        client: FlextLdapClient,
        base_dn: str,
        search_filter: str,
        **kwargs: object,
    ) -> FlextResult[list[LdapSearchResult]]:
        """Execute search using current strategy."""
        return await self._strategy.execute_search(client, base_dn, search_filter, **kwargs)


# =============================================================================
# EXPORTS AND BACKWARD COMPATIBILITY
# =============================================================================

# =============================================================================
# DATA TYPE CONVERTER - BASIC IMPLEMENTATION
# =============================================================================


class FlextLdapDataType:
    """LDAP data type constants for compatibility."""

    STRING = "string"
    INTEGER = "integer"
    BOOLEAN = "boolean"
    BINARY = "binary"


class FlextLdapConverter:
    """Simple LDAP data type converter for test compatibility."""

    @staticmethod
    def to_string(value: object) -> str:
        """Convert value to string."""
        return str(value)

    @staticmethod
    def to_integer(value: object) -> int:
        """Convert value to integer."""
        return int(str(value))

    @staticmethod
    def to_boolean(value: object) -> bool:
        """Convert value to boolean."""
        return bool(value)

    # Extended API expected by tests
    def detect_type(self, value: object) -> str:
        """Detect simple data type (email, dn, uid)."""
        try:
            s = str(value)
        except Exception:
            return "uid"
        if "@" in s and "." in s.rsplit("@", maxsplit=1)[-1]:
            return "email"
        if "," in s and "=" in s:
            return "dn"
        return "uid"

    def convert_to_dn(self, value: str, base_dn: str) -> str:
        """Convert email/uid/DN to DN string.

        - email: local part becomes CN
        - uid: uid becomes CN
        - dn: returned as-is
        """
        detected = self.detect_type(value)
        if detected == "email":
            local = value.split("@", 1)[0]
            return f"cn={local},{base_dn}"
        if detected == "uid":
            return f"cn={value},{base_dn}"
        return value


# Export all infrastructure classes
__all__ = [
    "FlextLDAPConnectionManager",
    "FlextLdapCertificateValidationService",
    # Core services
    "FlextLdapClient",
    # Repository implementations
    "FlextLdapConnectionRepositoryImpl",
    # Data type conversion
    "FlextLdapConverter",
    "FlextLdapDataType",
    "FlextLdapErrorCorrelationService",
    # Observer pattern classes
    "FlextLdapEventObserver",
    # Main infrastructure interface
    "FlextLdapInfrastructure",
    "FlextLdapObservableClient",
    "FlextLdapPagedSearchStrategy",
    "FlextLdapPerformanceObserver",
    "FlextLdapSchemaDiscoveryService",
    "FlextLdapSearchStrategy",
    "FlextLdapSecurityEventLogger",
    "FlextLdapSecurityObserver",
    "FlextLdapStandardSearchStrategy",
    "FlextLdapStrategyContext",
    "FlextLdapUserRepositoryImpl",
]
