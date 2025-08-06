"""Unified LDAP Infrastructure - Client + Converters + FlextCore Integration.

Consolidates client.py and converters.py into intelligent infrastructure layer.
Uses flext-core patterns for connection management, type conversion, and caching.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import re
import urllib.parse
from datetime import UTC, datetime
from uuid import UUID

import ldap3
from flext_core import (
    FlextContainer,
    FlextResult,
    get_logger,
)
from ldap3 import ALL, AUTO_BIND_NONE, BASE, LEVEL, SUBTREE, Connection, Server
from ldap3.core.exceptions import LDAPException
from pydantic import SecretStr

from flext_ldap.base import FlextLdapRepository
from flext_ldap.config import (
    FlextLdapAuthConfig,
    FlextLdapConnectionConfig,
)
from flext_ldap.constants import FlextLdapConstants, LDAPOperationResult

# Import specific error classes to avoid namespace issues
from flext_ldap.errors import (
    FlextLdapConnection,
    FlextLdapConnectionError,
    FlextLdapData,
)
from flext_ldap.types import FlextLdapDataType

logger = get_logger(__name__)


# Constants and types now imported from centralized modules


class FlextLdapConverter:
    """INTELLIGENT converter using flext-core patterns and caching."""

    @staticmethod
    def _is_trace_enabled() -> bool:
        """Check if TRACE logging is enabled - DRY helper method."""
        return (
            hasattr(logger, "_level_value")
            and logger._level_value <= FlextLdapConstants.TRACE_LEVEL_VALUE
        )

    def __init__(self) -> None:
        """Initialize with flext-core caching."""
        logger.debug("Initializing FlextLdapConverter with caching")
        self._type_cache: dict[str, FlextLdapDataType] = {}
        self._conversion_cache: dict[tuple[object, str], object] = {}
        # Efficient TRACE logging - respects centralized flext-core config
        if FlextLdapConverter._is_trace_enabled():
            logger.trace(
                "FlextLdapConverter initialized",
                extra={
                    "type_cache_size": len(self._type_cache),
                    "conversion_cache_size": len(self._conversion_cache),
                },
            )

    def detect_type(self, value: object) -> FlextLdapDataType:
        """Detect data type with intelligent caching."""
        if value is None:
            logger.trace("Detecting type for None value, returning STRING")
            return FlextLdapDataType.STRING

        value_key = str(type(value)) + str(value)[:50]  # Truncate for cache key
        if value_key in self._type_cache:
            cached_type = self._type_cache[value_key]
            # Performance-optimized TRACE logging
            if FlextLdapConverter._is_trace_enabled():
                logger.trace(
                    "Type detection cache hit",
                    extra={
                        "value_type": type(value).__name__,
                        "detected_type": cached_type.value,
                    },
                )
            return cached_type

        logger.trace(
            "Performing type detection",
            extra={
                "value_type": type(value).__name__,
                "value_preview": str(value)[:100],
            },
        )
        detected_type = self._detect_type_impl(value)
        self._type_cache[value_key] = detected_type

        logger.trace(
            "Type detected and cached",
            extra={
                "value_type": type(value).__name__,
                "detected_type": detected_type.value,
                "cache_size": len(self._type_cache),
            },
        )
        return detected_type

    def _detect_type_impl(self, value: object) -> FlextLdapDataType:
        """Implementation of type detection using Railway-Oriented Programming."""
        # Type detection pipeline - consolidated mapping approach
        type_detectors = [
            (bool, FlextLdapDataType.BOOLEAN),
            (int, FlextLdapDataType.INTEGER),
            (bytes, FlextLdapDataType.BINARY),
            (datetime, FlextLdapDataType.DATETIME),
            (UUID, FlextLdapDataType.UUID),
        ]

        # Execute type detection pipeline
        for type_class, ldap_type in type_detectors:
            if isinstance(value, type_class):
                return ldap_type

        # Handle string types with specialized detection
        if isinstance(value, str):
            return self._detect_string_type(value)

        # Default fallback
        return FlextLdapDataType.STRING

    def _detect_string_type(self, value: str) -> FlextLdapDataType:
        """Detect specific string types."""
        if re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", value):
            return FlextLdapDataType.EMAIL
        if re.match(r"^\+?[1-9][\d\-\(\)\s]{1,14}$", value):
            return FlextLdapDataType.PHONE
        if "=" in value and "," in value:
            return FlextLdapDataType.DN
        if value.lower() in {"true", "false", "yes", "no"}:
            return FlextLdapDataType.BOOLEAN
        return FlextLdapDataType.STRING

    def to_ldap(self, value: object) -> object:
        """Convert Python value to LDAP format with caching."""
        if value is None:
            return None

        cache_key = (id(value), "to_ldap")
        if cache_key in self._conversion_cache:
            return self._conversion_cache[cache_key]

        converted = self._to_ldap_impl(value)
        self._conversion_cache[cache_key] = converted
        return converted

    def _to_ldap_impl(self, value: object) -> object:
        """Implementation of Python to LDAP conversion."""
        if isinstance(value, bool):
            return "TRUE" if value else "FALSE"
        if isinstance(value, datetime):
            return value.strftime("%Y%m%d%H%M%SZ")
        if isinstance(value, (UUID, int, float)):
            return str(value)
        if isinstance(value, list):
            return [self.to_ldap(item) for item in value]
        return str(value)

    def from_ldap(
        self,
        value: object,
        target_type: FlextLdapDataType | None = None,
    ) -> object:
        """Convert LDAP value to Python format with intelligent type detection."""
        if value is None:
            return None

        cache_key = (id(value), f"from_ldap_{target_type}")
        if cache_key in self._conversion_cache:
            return self._conversion_cache[cache_key]

        converted = self._from_ldap_impl(value, target_type)
        self._conversion_cache[cache_key] = converted
        return converted

    def _from_ldap_impl(
        self,
        value: object,
        target_type: FlextLdapDataType | None = None,
    ) -> object:
        """Implementation of LDAP to Python conversion - SOLID refactored."""
        # Handle bytes conversion first
        if isinstance(value, bytes):
            value = value.decode("utf-8")

        # Handle list conversion recursively
        if isinstance(value, list):
            return [self.from_ldap(item, target_type) for item in value]

        # Detect type if not provided
        if target_type is None:
            target_type = self.detect_type(value)

        # Use strategy pattern for type-specific conversions
        return self._convert_by_type(value, target_type)

    def _convert_by_type(self, value: object, target_type: FlextLdapDataType) -> object:
        """Convert value based on target type - Single Responsibility."""
        conversion_strategies = {
            FlextLdapDataType.BOOLEAN: self._convert_to_boolean,
            FlextLdapDataType.INTEGER: self._convert_to_integer,
            FlextLdapDataType.DATETIME: self._convert_to_datetime,
            FlextLdapDataType.UUID: self._convert_to_uuid,
        }

        converter = conversion_strategies.get(target_type)
        if converter:
            return converter(value)
        return str(value)

    def _convert_to_boolean(self, value: object) -> bool:
        """Convert to boolean following Single Responsibility."""
        return str(value).lower() in {"true", "yes", "1"}

    def _convert_to_integer(self, value: object) -> int:
        """Convert to integer with error handling."""
        try:
            return (
                int(value) if isinstance(value, (str, int, float)) else int(str(value))
            )
        except (ValueError, TypeError):
            return 0

    def _convert_to_datetime(self, value: object) -> datetime | str:
        """Convert to datetime with proper error handling."""
        try:
            return datetime.strptime(str(value), "%Y%m%d%H%M%SZ").replace(tzinfo=UTC)
        except ValueError:
            return str(value)

    def _convert_to_uuid(self, value: object) -> UUID | str:
        """Convert to UUID with proper error handling."""
        try:
            return UUID(str(value))
        except ValueError:
            return str(value)


class FlextLdapConnectionManager:
    """INTELLIGENT connection manager using flext-core repository pattern."""

    def __init__(self, container: FlextContainer | None = None) -> None:
        """Initialize with connection repository and dependency injection."""
        self._container = container or FlextContainer()
        self._connections: FlextLdapRepository = FlextLdapRepository()
        self._pool_configs: dict[str, FlextLdapConnectionConfig] = {}

    def get_connection(
        self,
        config: FlextLdapConnectionConfig,
    ) -> FlextResult[Connection]:
        """Get connection with intelligent pooling and caching."""
        try:
            config_key = f"{config.server}:{config.port}"

            # Try to get existing connection
            existing = self._connections.find_by_attribute(
                "server",
                config.server,
            )
            if (
                existing
                and existing[0]
                and hasattr(existing[0], "closed")
                and not existing[0].closed
            ):
                # Type-safe connection verification
                connection_obj = existing[0]
                if isinstance(connection_obj, Connection):
                    return FlextResult.ok(connection_obj)
                # Invalid object type in repository, remove it
                # Note: Using available method instead of delete_by_criteria
                logger.warning("Invalid connection object type in repository, skipping")

            # Create new connection
            connection = self._create_connection(config)
            if connection.is_success:
                save_result = self._connections.save(connection.data)
                if not save_result.is_success:
                    logger.error("Failed to save connection: %s", save_result.error)
                self._pool_configs[config_key] = config

            return connection
        except (RuntimeError, ValueError, TypeError) as e:
            return FlextResult.fail(f"Failed to get connection: {e}")

    def _create_connection(
        self,
        config: FlextLdapConnectionConfig,
        user: str | None = None,
        password: str | None = None,
    ) -> FlextResult[Connection]:
        """Create new LDAP connection with optional authentication."""
        try:
            # Create server with intelligent configuration
            server = Server(
                config.server,
                port=config.port,
                use_ssl=config.use_ssl,
                get_info=ALL,
                connect_timeout=config.timeout_seconds,
            )

            # Create connection with or without credentials
            connection = Connection(
                server,
                user=user,
                password=password,
                auto_bind=AUTO_BIND_NONE,
                raise_exceptions=True,
            )

            # Test connection
            if not connection.bind():
                return FlextResult.fail(f"Bind failed: {connection.result}")

            return FlextResult.ok(connection)
        except LDAPException as e:
            error = FlextLdapConnectionError(
                f"LDAP protocol error: {e}",
                server=config.server,
                port=config.port,
                cause=e,
            )
            return error.to_typed_result(Connection)
        except (RuntimeError, ValueError, TypeError) as e:
            error = FlextLdapConnectionError(
                f"Connection setup error: {e}",
                server=config.server,
                port=config.port,
                cause=e,
            )
            return error.to_typed_result(Connection)

    def close_connection(self, connection: Connection) -> FlextResult[bool]:
        """Close connection and remove from pool."""
        try:
            if hasattr(connection, "server"):
                delete_result = self._connections.delete(
                    getattr(connection, "server", ""),
                )
                if not delete_result.is_success:
                    logger.error("Failed to delete connection: %s", delete_result.error)
            if hasattr(connection, "unbind") and callable(connection.unbind):
                try:
                    # Type-safe unbind with error handling
                    connection.unbind()  # type: ignore[no-untyped-call] # ldap3 typing limitation
                except Exception as e:
                    logger.warning("Failed to unbind connection: %s", e)
            return FlextResult.ok(data=True)
        except (RuntimeError, ValueError, TypeError) as e:
            error = FlextLdapConnectionError(
                f"Failed to close connection: {e}",
                cause=e,
            )
            return error.to_bool_result()


class FlextLdapSimpleClient:
    """UNIFIED LDAP client with intelligent infrastructure."""

    def __init__(
        self,
        config: FlextLdapConnectionConfig | None = None,
        container: FlextContainer | None = None,
    ) -> None:
        """Initialize unified client with dependency injection support."""
        logger.debug(
            "Initializing FlextLdapSimpleClient",
            extra={
                "has_config": config is not None,
                "has_container": container is not None,
                "config": config.__dict__ if config else None,
            },
        )
        self._container = container or FlextContainer()
        self._config = config
        self._connection_manager = FlextLdapConnectionManager(self._container)
        self._converter = FlextLdapConverter()
        self._current_connection: Connection | None = None
        self._auth_config: FlextLdapAuthConfig | None = None
        logger.trace(
            "FlextLdapClient initialized with components",
            extra={
                "connection_manager": type(self._connection_manager).__name__,
                "converter": type(self._converter).__name__,
            },
        )

    def connect(
        self,
        config: FlextLdapConnectionConfig | None = None,
    ) -> FlextResult[bool]:
        """Connect with intelligent connection management."""
        logger.debug(
            "Attempting LDAP connection",
            extra={
                "config_provided": config is not None,
                "has_stored_config": self._config is not None,
            },
        )
        try:
            use_config = config or self._config
            if not use_config:
                logger.error("No connection configuration available")
                return FlextResult.fail("No connection configuration provided")

            logger.trace(
                "Using connection config",
                extra={
                    "server": use_config.server,
                    "port": use_config.port,
                    "use_ssl": use_config.use_ssl,
                    "timeout": use_config.timeout_seconds,
                },
            )

            connection_result = self._connection_manager.get_connection(
                use_config,
            )
            if not connection_result.is_success:
                logger.error(
                    "Connection manager failed",
                    extra={
                        "error": connection_result.error,
                        "server": use_config.server,
                    },
                )
                return FlextResult.fail(connection_result.error or "Connection failed")

            self._current_connection = connection_result.data
            logger.info(
                "LDAP connection established",
                extra={
                    "server": use_config.server,
                    "port": use_config.port,
                    "ssl": use_config.use_ssl,
                },
            )
            return FlextResult.ok(LDAPOperationResult.SUCCESS)
        except (RuntimeError, ValueError, TypeError) as e:
            logger.exception(
                "Connection exception",
                extra={"error": str(e), "type": type(e).__name__},
            )
            return FlextResult.fail(f"Connection failed: {e}")

    async def connect_with_auth(
        self,
        auth_config: FlextLdapAuthConfig,
    ) -> FlextResult[bool]:
        """Connect with authentication using provided credentials."""
        logger.debug(
            "Attempting LDAP authentication",
            extra={
                "bind_dn": auth_config.bind_dn,
                "has_password": bool(auth_config.bind_password),
            },
        )
        try:
            # Create a new authenticated connection instead of modifying existing one
            if not self._config:
                logger.error("No connection configuration available")
                return FlextResult.fail("Connection configuration required")

            logger.trace("Creating authenticated connection")
            password = auth_config.bind_password
            if password is not None and hasattr(password, "get_secret_value"):
                password_str = password.get_secret_value()
            else:
                password_str = None

            connection_result = self._connection_manager._create_connection(
                self._config,
                user=auth_config.bind_dn,
                password=password_str,
            )

            if not connection_result.is_success:
                logger.error(
                    "Failed to create authenticated connection",
                    extra={
                        "bind_dn": auth_config.bind_dn,
                        "error": connection_result.error,
                    },
                )
                return FlextResult.fail(
                    f"Authentication failed: {connection_result.error}",
                )

            # Replace current connection with authenticated one
            if self._current_connection and hasattr(self._current_connection, "unbind"):
                try:
                    if callable(self._current_connection.unbind):
                        # Type-safe unbind with error handling
                        self._current_connection.unbind()  # type: ignore[no-untyped-call] # ldap3 typing limitation
                except Exception as e:
                    logger.warning("Failed to unbind previous connection: %s", e)

            self._current_connection = connection_result.data

            logger.info(
                "LDAP authentication successful",
                extra={"bind_dn": auth_config.bind_dn},
            )
            return FlextResult.ok(LDAPOperationResult.SUCCESS)
        except LDAPException as e:
            error = FlextLdapConnection.AuthenticationError(
                f"LDAP authentication failed: {e}",
                bind_dn=auth_config.bind_dn,
                cause=e,
            )
            return error.to_bool_result()
        except (RuntimeError, ValueError, TypeError) as e:
            error = FlextLdapConnection.AuthenticationError(
                f"Authentication setup failed: {e}",
                bind_dn=auth_config.bind_dn,
                cause=e,
            )
            return error.to_bool_result()

    async def search(
        self,
        base_dn: str,
        search_filter: str,
        attributes: list[str] | None = None,
        scope: str = "subtree",
    ) -> FlextResult[list[dict[str, object]]]:
        """Search with intelligent result conversion."""
        # Use flext-core context binding for operation tracking
        operation_logger = logger.bind(
            operation="ldap_search",
            base_dn=base_dn,
            filter=search_filter,
        )

        operation_logger.debug(
            "Performing LDAP search",
            extra={
                "attributes": attributes,
                "connection_active": self._current_connection is not None,
            },
        )

        if not self._current_connection:
            operation_logger.error("Search attempted without active connection")
            return FlextResult.fail("Not connected")

        try:
            search_attributes = attributes or ["*"]

            # Map scope string to ldap3 constants - REALLY USE scope parameter

            scope_mapping = {
                "base": BASE,
                "onelevel": LEVEL,
                "one": LEVEL,
                "subtree": SUBTREE,
                "sub": SUBTREE,
            }
            ldap_scope = scope_mapping.get(scope.lower(), SUBTREE)

            operation_logger.trace(
                "Executing LDAP search operation",
                extra={
                    "attrs": search_attributes,
                    "scope": scope,
                    "ldap_scope": ldap_scope,
                },
            )

            # Use ldap3 constants with type annotation fix
            # ldap3 constants (BASE, LEVEL, SUBTREE) are int values but typing expects literals
            success: bool = self._current_connection.search(
                search_base=base_dn,
                search_filter=search_filter,
                search_scope=ldap_scope,  # type: ignore[arg-type] # ldap3 typing limitation
                attributes=search_attributes,
            ) or False

            if not success:
                operation_logger.error(
                    "LDAP search operation failed",
                    extra={"result": str(self._current_connection.result)},
                )
                return FlextResult.fail(
                    f"Search failed: {self._current_connection.result}",
                )

            operation_logger.debug(
                "LDAP search completed",
                extra={"entries_found": len(self._current_connection.entries)},
            )

            # Convert results using intelligent converter
            operation_logger.trace(
                "Converting search results with intelligent converter",
            )
            results: list[dict[str, object]] = []
            for entry in self._current_connection.entries:
                converted_entry: dict[str, object] = {
                    "dn": str(entry.entry_dn),
                    "attributes": {},
                }

                for attr_name, attr_values in entry.entry_attributes_as_dict.items():
                    # Use intelligent type conversion
                    converted_values = []
                    for value in attr_values:
                        converted = self._converter.from_ldap(value)
                        converted_values.append(converted)

                    # Cast to dict to make MyPy happy about the assignment
                    attributes_dict = converted_entry["attributes"]
                    if isinstance(attributes_dict, dict):
                        attributes_dict[attr_name] = converted_values

                results.append(converted_entry)
                operation_logger.trace(
                    "Converted entry",
                    extra={
                        "dn": str(entry.entry_dn),
                        "attribute_count": len(entry.entry_attributes_as_dict),
                    },
                )

            operation_logger.info(
                "LDAP search successful",
                extra={
                    "result_count": len(results),
                    "attributes_requested": search_attributes,
                },
            )
            return FlextResult.ok(results)
        except (RuntimeError, ValueError, TypeError) as e:
            error = FlextLdapConnectionError(
                f"Search operation failed: {e}",
                cause=e,
            )
            operation_logger.exception(
                "Search exception converted to FlextLdapError",
                extra={
                    "error_code": error.error_code,
                    "correlation_id": error.correlation_id,
                },
            )
            return error.to_typed_result(list[dict[str, object]])

    async def add(
        self,
        dn: str,
        object_classes: list[str],
        attributes: dict[str, object],
    ) -> FlextResult[bool]:
        """Add entry with intelligent attribute conversion."""
        # Use flext-core context binding for operation tracking
        operation_logger = logger.bind(
            operation="ldap_add",
            dn=dn,
            object_classes=object_classes,
        )

        operation_logger.debug(
            "Adding LDAP entry",
            extra={
                "attribute_count": len(attributes),
                "connection_active": self._current_connection is not None,
            },
        )

        if not self._current_connection:
            operation_logger.error("Add attempted without active connection")
            return FlextResult.fail("Not connected")

        try:
            operation_logger.trace("Converting attributes for LDAP add operation")
            # Convert attributes using intelligent converter
            ldap_attributes = {}
            for attr_name, attr_value in attributes.items():
                converted_value = self._converter.to_ldap(attr_value)
                ldap_attributes[attr_name] = converted_value
                operation_logger.trace(
                    "Converted attribute",
                    extra={
                        "attr_name": attr_name,
                        "original_type": type(attr_value).__name__,
                        "converted_type": type(converted_value).__name__,
                    },
                )

            # Add objectClass
            ldap_attributes["objectClass"] = object_classes
            operation_logger.trace(
                "Prepared LDAP attributes",
                extra={"total_attributes": len(ldap_attributes)},
            )

            operation_logger.trace("Executing LDAP add operation")
            # LDAP add operation - ldap3 Connection.add method
            success: bool = self._current_connection.add(dn, attributes=ldap_attributes) or False  # type: ignore[no-untyped-call] # ldap3 typing limitation

            if not success:
                operation_logger.error(
                    "LDAP add operation failed",
                    extra={"result": str(self._current_connection.result)},
                )
                return FlextResult.fail(
                    f"Add failed: {self._current_connection.result}",
                )

            operation_logger.info(
                "LDAP entry added successfully",
                extra={"attribute_count": len(attributes)},
            )
            return FlextResult.ok(LDAPOperationResult.SUCCESS)
        except (RuntimeError, ValueError, TypeError) as e:
            error = FlextLdapData.ValidationError(
                f"Add operation failed: {e}",
                field_name="attributes",
                cause=e,
            )
            operation_logger.exception(
                "Add exception converted to FlextLdapError",
                extra={
                    "error_code": error.error_code,
                    "correlation_id": error.correlation_id,
                },
            )
            return error.to_bool_result()

    async def modify(self, dn: str, changes: dict[str, object]) -> FlextResult[bool]:
        """Modify entry with intelligent change conversion."""
        logger.debug(
            "Modifying LDAP entry",
            extra={
                "dn": dn,
                "changes_count": len(changes),
                "connection_active": self._current_connection is not None,
            },
        )

        if not self._current_connection:
            logger.error("Modify attempted without active connection")
            return FlextResult.fail("Not connected")

        try:
            logger.trace("Converting changes for LDAP modify operation")
            # Convert changes using intelligent converter
            ldap_changes = {}
            for attr_name, attr_value in changes.items():
                converted_value = self._converter.to_ldap(attr_value)
                ldap_changes[attr_name] = [(ldap3.MODIFY_REPLACE, converted_value)]
                logger.trace(
                    "Prepared modification",
                    extra={
                        "attr_name": attr_name,
                        "original_type": type(attr_value).__name__,
                        "converted_type": type(converted_value).__name__,
                    },
                )

            logger.trace(
                "Executing LDAP modify operation",
                extra={"dn": dn, "modifications": list(ldap_changes.keys())},
            )
            # LDAP modify operation - ldap3 Connection.modify method
            success: bool = self._current_connection.modify(dn, ldap_changes) or False  # type: ignore[no-untyped-call] # ldap3 typing limitation

            if not success:
                logger.error(
                    "LDAP modify operation failed",
                    extra={"dn": dn, "result": str(self._current_connection.result)},
                )
                return FlextResult.fail(
                    f"Modify failed: {self._current_connection.result}",
                )

            logger.info(
                "LDAP entry modified successfully",
                extra={"dn": dn, "changes_applied": list(changes.keys())},
            )
            return FlextResult.ok(LDAPOperationResult.SUCCESS)
        except (RuntimeError, ValueError, TypeError) as e:
            error = FlextLdapData.ValidationError(
                f"Modify operation failed: {e}",
                field_name="changes",
                cause=e,
            )
            logger.exception(
                "Modify exception converted to FlextLdapError",
                extra={
                    "error_code": error.error_code,
                    "correlation_id": error.correlation_id,
                    "dn": dn,
                },
            )
            return error.to_bool_result()

    async def delete(self, dn: str) -> FlextResult[bool]:
        """Delete entry."""
        logger.debug(
            "Deleting LDAP entry",
            extra={"dn": dn, "connection_active": self._current_connection is not None},
        )

        if not self._current_connection:
            logger.error("Delete attempted without active connection")
            return FlextResult.fail("Not connected")

        try:
            logger.trace("Executing LDAP delete operation", extra={"dn": dn})
            # LDAP delete operation - ldap3 Connection.delete method
            success: bool = self._current_connection.delete(dn) or False  # type: ignore[no-untyped-call] # ldap3 typing limitation

            if not success:
                logger.error(
                    "LDAP delete operation failed",
                    extra={"dn": dn, "result": str(self._current_connection.result)},
                )
                return FlextResult.fail(
                    f"Delete failed: {self._current_connection.result}",
                )

            logger.info("LDAP entry deleted successfully", extra={"dn": dn})
            return FlextResult.ok(LDAPOperationResult.SUCCESS)
        except (RuntimeError, ValueError, TypeError) as e:
            error = FlextLdapConnectionError(
                f"Delete operation failed: {e}",
                cause=e,
            )
            logger.exception(
                "Delete exception converted to FlextLdapError",
                extra={
                    "error_code": error.error_code,
                    "correlation_id": error.correlation_id,
                    "dn": dn,
                },
            )
            return error.to_bool_result()

    def disconnect(self) -> FlextResult[bool]:
        """Disconnect with proper cleanup."""
        logger.debug(
            "Disconnecting from LDAP server",
            extra={"has_active_connection": self._current_connection is not None},
        )

        if self._current_connection:
            logger.trace("Closing active LDAP connection")
            result = self._connection_manager.close_connection(
                self._current_connection,
            )
            self._current_connection = None

            if result.is_success:
                logger.info("LDAP disconnection successful")
            else:
                logger.error("LDAP disconnection failed", extra={"error": result.error})
            return result

        logger.debug("No active connection to disconnect")
        return FlextResult.ok(LDAPOperationResult.SUCCESS)

    def is_connected(self) -> bool:
        """Check connection status."""
        return (
            self._current_connection is not None and not self._current_connection.closed
        )

    def get_server_info(self) -> dict[str, str]:
        """Get server connection information."""
        if not self.is_connected() or not self._current_connection:
            return {"status": "disconnected"}

        try:
            return {
                "status": "connected",
                "server": str(self._current_connection.server),
                "bound": str(self._current_connection.bound),
                "user": str(getattr(self._current_connection, "user", "anonymous")),
            }
        except Exception as e:
            logger.exception("Error getting server info", exc_info=e)
            return {"status": "error", "error": str(e)}

    async def get_entry(self, dn: str) -> FlextResult[dict[str, object]]:
        """Get single LDAP entry by DN."""
        logger.debug("Getting LDAP entry", extra={"dn": dn})

        # Use search with BASE scope to get single entry
        search_result = await self.search(dn, "(objectClass=*)", scope="base")

        if not search_result.is_success:
            return FlextResult.fail(f"Failed to get entry: {search_result.error}")

        entries = search_result.data or []
        if not entries:
            return FlextResult.fail(f"Entry not found: {dn}")

        return FlextResult.ok(entries[0])

    async def delete_entry(self, dn: str) -> FlextResult[bool]:
        """Delete LDAP entry by DN."""
        logger.debug("Deleting LDAP entry", extra={"dn": dn})

        # Use the existing delete method
        return await self.delete(dn)


# COMPATIBILITY ALIASES
FlextSimpleConverter = FlextLdapConverter  # From old converters.py


# FACTORY FUNCTIONS for easy instantiation
def create_ldap_client(
    server_url: str,
    bind_dn: str | None = None,
    password: str | None = None,
    **kwargs: object,
) -> FlextLdapSimpleClient:
    """Factory for creating configured LDAP client.

    Args:
        server_url: LDAP server URL (REALLY USED)
        bind_dn: Bind DN for authentication (REALLY USED)
        password: Password for authentication (REALLY USED)
        **kwargs: Additional configuration parameters (REALLY USED)

    """
    logger.debug(
        "Creating LDAP client via factory",
        extra={
            "server_url": server_url,
            "bind_dn": bind_dn,
            "has_password": bool(password),
            "kwargs_count": len(kwargs),
        },
    )

    # Parse server_url to get host and port
    parsed = urllib.parse.urlparse(server_url)
    host = parsed.hostname or "localhost"
    port = parsed.port or (636 if parsed.scheme == "ldaps" else 389)
    use_ssl = parsed.scheme == "ldaps"

    logger.trace(
        "Parsed server URL",
        extra={
            "original_url": server_url,
            "parsed_host": host,
            "parsed_port": port,
            "use_ssl": use_ssl,
            "scheme": parsed.scheme,
        },
    )

    # Extract timeout from kwargs with default value
    timeout_seconds = 30
    if "timeout" in kwargs:
        timeout_value = kwargs.get("timeout")
        if isinstance(timeout_value, (int, float)) and timeout_value > 0:
            timeout_seconds = int(timeout_value)
    elif "timeout_seconds" in kwargs:
        timeout_value = kwargs.get("timeout_seconds")
        if isinstance(timeout_value, (int, float)) and timeout_value > 0:
            timeout_seconds = int(timeout_value)

    # Extract pool_size from kwargs with default value
    pool_size = 10
    if "pool_size" in kwargs:
        pool_value = kwargs.get("pool_size")
        if isinstance(pool_value, (int, float)) and pool_value > 0:
            pool_size = int(pool_value)

    # Create config with REAL parameters from server_url and kwargs
    config = FlextLdapConnectionConfig(
        host=host,
        port=port,
        use_ssl=use_ssl,
        timeout=timeout_seconds,
        pool_size=pool_size,
    )

    # Create client with REAL config
    logger.trace(
        "Creating FlextLdapSimpleClient with config",
        extra={"host": host, "port": port, "ssl": use_ssl, "timeout": timeout_seconds},
    )
    client = FlextLdapSimpleClient(config)

    # If authentication credentials provided, store them for later use
    if bind_dn and password:
        logger.debug(
            "Configuring authentication for client",
            extra={"bind_dn": bind_dn},
        )
        # Store auth config in client for future authentication
        auth_config = FlextLdapAuthConfig(
            bind_dn=bind_dn,
            bind_password=SecretStr(password),
        )
        # REALLY use the auth_config by storing it in the client
        client._auth_config = auth_config
        logger.info(
            "Created LDAP client with authentication credentials for %s",
            bind_dn,
        )
    else:
        logger.debug("Created LDAP client without authentication")

    logger.info(
        "LDAP client factory completed",
        extra={
            "server": host,
            "port": port,
            "ssl": use_ssl,
            "authenticated": bool(bind_dn and password),
        },
    )
    return client


def create_ldap_converter() -> FlextLdapConverter:
    """Factory for creating LDAP converter."""
    logger.debug("Creating LDAP converter via factory")
    converter = FlextLdapConverter()
    logger.trace("LDAP converter factory completed")
    return converter
