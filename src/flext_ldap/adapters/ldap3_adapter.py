"""LDAP3 adapter service - Service wrapper for ldap3 library.

This module provides a service adapter around ldap3 following flext-ldif patterns.
Reuses FlextLdifParser for parsing LDAP results to Entry models.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import Any

from flext_core import FlextLogger, FlextResult, FlextService
from flext_ldif.models import FlextLdifModels
from flext_ldif.services.parser import FlextLdifParser
from ldap3 import BASE, LEVEL, SUBTREE, Connection, Server

from flext_ldap.models import FlextLdapModels

logger = FlextLogger(__name__)


class Ldap3Adapter(FlextService[FlextLdifModels.Entry]):
    """Service adapter for ldap3 library following flext-ldif patterns.

    Wraps ldap3 Connection and Server objects to provide a simplified
    interface for LDAP operations. Reuses FlextLdifParser for automatic
    conversion of LDAP results to Entry models.

    This is a SERVICE adapter, not just a wrapper, following the same
    patterns as flext-ldif services.
    """

    _connection: Connection | None
    _server: Server | None
    _parser: FlextLdifParser
    _BASE: int
    _LEVEL: int
    _SUBTREE: int

    def __init__(
        self,
        parser: FlextLdifParser | None = None,
    ) -> None:
        """Initialize adapter service with parser.

        Args:
            parser: Optional FlextLdifParser instance. If None, creates new instance.

        """
        super().__init__()
        self._connection = None
        self._server = None
        self._parser = parser if parser is not None else FlextLdifParser()
        # Initialize scope constants (ldap3 constants are integers)
        # Type ignore needed because ldap3 stubs may not match runtime types
        self._BASE: int = BASE  # type: ignore[assignment]
        self._LEVEL: int = LEVEL  # type: ignore[assignment]
        self._SUBTREE: int = SUBTREE  # type: ignore[assignment]

    def connect(
        self,
        config: FlextLdapModels.ConnectionConfig,
    ) -> FlextResult[None]:
        """Establish LDAP connection using ldap3.

        Args:
            config: Connection configuration

        Returns:
            FlextResult[None] indicating success or failure

        """
        try:
            # Create server object
            server_kwargs: dict[str, Any] = {
                "host": config.host,
                "port": config.port,
            }

            if config.use_ssl:
                server_kwargs["use_ssl"] = True
            elif config.use_tls:
                server_kwargs["use_tls"] = True

            self._server = Server(**server_kwargs)

            # Create connection
            connection_kwargs: dict[str, Any] = {
                "server": self._server,
                "auto_bind": config.auto_bind,
                "auto_range": config.auto_range,
                "receive_timeout": config.timeout,
            }

            if config.bind_dn:
                connection_kwargs["user"] = config.bind_dn
            if config.bind_password:
                connection_kwargs["password"] = config.bind_password

            self._connection = Connection(**connection_kwargs)

            if not self._connection.bound:
                return FlextResult[None].fail("Failed to bind to LDAP server")

            # Scope constants already initialized in __init__

            logger.info(f"Connected to LDAP server {config.host}:{config.port}")
            return FlextResult[None].ok(None)

        except ImportError:
            return FlextResult[None].fail("ldap3 library not installed")
        except Exception as e:
            logger.exception("Failed to connect to LDAP server")
            return FlextResult[None].fail(f"Connection failed: {e!s}")

    def disconnect(self) -> None:
        """Close LDAP connection."""
        if self._connection:
            try:
                self._connection.unbind()
            except Exception as e:
                logger.debug(f"Error during disconnect: {e}")
            finally:
                self._connection = None
                self._server = None

    @property
    def connection(self) -> Connection | None:
        """Get underlying ldap3 Connection object.

        Returns:
            Connection object or None if not connected

        """
        return self._connection

    @property
    def is_connected(self) -> bool:
        """Check if adapter has an active connection.

        Returns:
            True if connected and bound, False otherwise

        """
        return self._connection is not None and self._connection.bound

    def search(
        self,
        base_dn: str,
        filter_str: str,
        scope: str = "SUBTREE",
        attributes: list[str] | None = None,
        size_limit: int = 0,
        time_limit: int = 0,
        server_type: str = "rfc",
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Perform LDAP search operation and convert to Entry models.

        Uses FlextLdifParser.parse_ldap3_results() to automatically convert
        LDAP results to Entry models, reusing flext-ldif parsing logic.

        Args:
            base_dn: Base DN for search
            filter_str: LDAP filter string
            scope: Search scope (BASE, ONELEVEL, SUBTREE)
            attributes: Attributes to retrieve (None = all)
            size_limit: Maximum number of entries (0 = no limit)
            time_limit: Maximum time in seconds (0 = no limit)
            server_type: LDAP server type for parsing (default: "rfc")

        Returns:
            FlextResult containing list of Entry models (reusing FlextLdifModels.Entry)

        """
        if not self.is_connected or self._connection is None:
            return FlextResult[list[FlextLdifModels.Entry]].fail("Not connected to LDAP server")

        try:
            # Map scope string to ldap3 constant
            scope_map: dict[str, int] = {
                "BASE": self._BASE,
                "ONELEVEL": self._LEVEL,
                "SUBTREE": self._SUBTREE,
            }
            ldap_scope = scope_map.get(scope.upper(), self._SUBTREE)

            # Perform search
            search_attributes = attributes or ["*"]
            self._connection.search(
                search_base=base_dn,
                search_filter=filter_str,
                search_scope=ldap_scope,  # type: ignore[arg-type]
                attributes=search_attributes,
                size_limit=size_limit,
                time_limit=time_limit,
            )

            # Convert ldap3 results to format expected by FlextLdifParser
            ldap3_results: list[tuple[str, dict[str, list[str]]]] = []
            for entry in self._connection.entries:
                entry_attrs: dict[str, list[str]] = {}
                for attr in entry.entry_attributes:
                    attr_values = entry[attr].values
                    entry_attrs[attr] = list(attr_values) if isinstance(attr_values, (list, tuple)) else [str(attr_values)]
                ldap3_results.append((str(entry.entry_dn), entry_attrs))

            # Use FlextLdifParser to parse LDAP3 results to Entry models
            # Reusing FlextLdifParser.parse_ldap3_results() method
            parse_result = self._parser.parse_ldap3_results(ldap3_results, server_type)
            if parse_result.is_success:
                parse_response = parse_result.unwrap()
                # Return entries directly (reusing FlextLdifModels.Entry)
                # ParseResponse.entries is a Sequence, convert to list
                # Type ignore needed because flext-ldif may return domain.Entry but we expect models.Entry
                entries_list = list(parse_response.entries)  # type: ignore[arg-type]
                return FlextResult[list[FlextLdifModels.Entry]].ok(entries_list)  # type: ignore[arg-type]
            error_msg = parse_result.error or "Failed to parse LDAP results"
            logger.warning(f"Failed to parse LDAP results: {error_msg}")
            return FlextResult[list[FlextLdifModels.Entry]].fail(error_msg)

        except Exception as e:
            logger.exception("LDAP search failed")
            return FlextResult[list[FlextLdifModels.Entry]].fail(f"Search failed: {e!s}")

    def add(
        self,
        entry: FlextLdifModels.Entry,
    ) -> FlextResult[None]:
        """Add LDAP entry using Entry model.

        Reuses FlextLdifModels.Entry for type safety and consistency.

        Args:
            entry: Entry model to add (reusing FlextLdifModels.Entry)

        Returns:
            FlextResult[None] indicating success or failure

        """
        if not self.is_connected or self._connection is None:
            return FlextResult[list[FlextLdifModels.Entry]].fail("Not connected to LDAP server")

        try:
            # Convert Entry model attributes to ldap3 format
            ldap_attrs: dict[str, list[str]] = {}
            if entry.attributes:
                for attr_name, attr_value in entry.attributes.items():
                    if isinstance(attr_value, list):
                        ldap_attrs[attr_name] = [str(v) for v in attr_value]
                    else:
                        ldap_attrs[attr_name] = [str(attr_value)] if attr_value else []

            # Use DN from Entry model (reusing FlextLdifModels.DistinguishedName)
            dn_str = str(entry.dn)

            success = self._connection.add(dn_str, attributes=ldap_attrs)
            if success:
                return FlextResult[None].ok(None)
            result_dict = self._connection.result
            error = result_dict.get("description", "Unknown error") if isinstance(result_dict, dict) else "Unknown error"
            return FlextResult[None].fail(f"Add failed: {error}")

        except Exception as e:
            logger.exception("LDAP add failed")
            return FlextResult[None].fail(f"Add failed: {e!s}")

    def modify(
        self,
        dn: str | FlextLdifModels.DistinguishedName,
        changes: dict[str, list[tuple[str, list[str]]]],
    ) -> FlextResult[None]:
        """Modify LDAP entry.

        Accepts DN as string or DistinguishedName model (reusing FlextLdifModels.DistinguishedName).

        Args:
            dn: Distinguished name of entry to modify (string or DistinguishedName model)
            changes: Modification changes in ldap3 format

        Returns:
            FlextResult[None] indicating success or failure

        """
        if not self.is_connected or self._connection is None:
            return FlextResult[list[FlextLdifModels.Entry]].fail("Not connected to LDAP server")

        try:
            # Convert DN to string (reusing FlextLdifModels.DistinguishedName)
            dn_str = str(dn) if isinstance(dn, FlextLdifModels.DistinguishedName) else dn

            success = self._connection.modify(dn_str, changes)
            if success:
                return FlextResult[None].ok(None)
            result_dict = self._connection.result
            error = result_dict.get("description", "Unknown error") if isinstance(result_dict, dict) else "Unknown error"
            return FlextResult[None].fail(f"Modify failed: {error}")

        except Exception as e:
            logger.exception("LDAP modify failed")
            return FlextResult[None].fail(f"Modify failed: {e!s}")

    def delete(
        self,
        dn: str | FlextLdifModels.DistinguishedName,
    ) -> FlextResult[None]:
        """Delete LDAP entry.

        Accepts DN as string or DistinguishedName model (reusing FlextLdifModels.DistinguishedName).

        Args:
            dn: Distinguished name of entry to delete (string or DistinguishedName model)

        Returns:
            FlextResult[None] indicating success or failure

        """
        if not self.is_connected or self._connection is None:
            return FlextResult[list[FlextLdifModels.Entry]].fail("Not connected to LDAP server")

        try:
            # Convert DN to string (reusing FlextLdifModels.DistinguishedName)
            dn_str = str(dn) if isinstance(dn, FlextLdifModels.DistinguishedName) else dn

            success = self._connection.delete(dn_str)
            if success:
                return FlextResult[None].ok(None)
            result_dict = self._connection.result
            error = result_dict.get("description", "Unknown error") if isinstance(result_dict, dict) else "Unknown error"
            return FlextResult[None].fail(f"Delete failed: {error}")

        except Exception as e:
            logger.exception("LDAP delete failed")
            return FlextResult[None].fail(f"Delete failed: {e!s}")

    def execute(self) -> FlextResult[FlextLdifModels.Entry]:
        """Execute service health check.

        Returns:
            FlextResult containing service status

        """
        if not self.is_connected:
            return FlextResult[FlextLdifModels.Entry].fail("Not connected to LDAP server")

        # Return success with empty entry as health check
        # This follows the FlextService pattern
        empty_entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value=""),
            attributes=FlextLdifModels.LdifAttributes(),
        )
        return FlextResult[FlextLdifModels.Entry].ok(empty_entry)
