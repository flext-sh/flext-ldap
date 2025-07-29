"""Unified LDAP Infrastructure - Client + Converters + FlextCore Integration.

Consolidates client.py and converters.py into intelligent infrastructure layer.
Uses flext-core patterns for connection management, type conversion, and caching.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from typing import Any, TypeVar, Generic
from uuid import UUID

import ldap3
from flext_core import FlextResult, get_logger
from ldap3 import (
    ALL, AUTO_BIND_NONE, ROUND_ROBIN,
    Connection, Server, ServerPool, Tls
)
from ldap3.core.exceptions import LDAPException

from flext_ldap.base import FlextLdapRepository

logger = get_logger(__name__)

# Generic types for infrastructure
TValue = TypeVar("TValue")


class FlextLdapDataType(Enum):
    """LDAP data types with intelligent detection."""
    STRING = "string"
    INTEGER = "integer"
    BOOLEAN = "boolean"
    BINARY = "binary"
    DATETIME = "datetime"
    DN = "dn"
    EMAIL = "email"
    PHONE = "phone"
    UUID = "uuid"


@dataclass
class FlextLdapConnectionConfig:
    """Unified connection configuration."""
    server_url: str
    bind_dn: str | None = None
    password: str | None = None
    use_ssl: bool = False
    tls_config: Tls | None = None
    connection_timeout: int = 10
    pool_size: int = 5


class FlextLdapConverter:
    """INTELLIGENT converter using flext-core patterns and caching."""

    def __init__(self) -> None:
        """Initialize with flext-core caching."""
        self._type_cache: dict[str, FlextLdapDataType] = {}
        self._conversion_cache: dict[tuple[Any, str], Any] = {}

    def detect_type(self, value: Any) -> FlextLdapDataType:
        """Detect data type with intelligent caching."""
        if value is None:
            return FlextLdapDataType.STRING

        value_key = str(type(value)) + str(value)[:50]  # Truncate for cache key
        if value_key in self._type_cache:
            return self._type_cache[value_key]

        detected_type = self._detect_type_impl(value)
        self._type_cache[value_key] = detected_type
        return detected_type

    def _detect_type_impl(self, value: Any) -> FlextLdapDataType:
        """Implementation of type detection."""
        if isinstance(value, bool):
            return FlextLdapDataType.BOOLEAN
        elif isinstance(value, int):
            return FlextLdapDataType.INTEGER
        elif isinstance(value, bytes):
            return FlextLdapDataType.BINARY
        elif isinstance(value, datetime):
            return FlextLdapDataType.DATETIME
        elif isinstance(value, UUID):
            return FlextLdapDataType.UUID
        elif isinstance(value, str):
            return self._detect_string_type(value)
        else:
            return FlextLdapDataType.STRING

    def _detect_string_type(self, value: str) -> FlextLdapDataType:
        """Detect specific string types."""
        if re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", value):
            return FlextLdapDataType.EMAIL
        elif re.match(r"^\+?[1-9]\d{1,14}$", value):
            return FlextLdapDataType.PHONE
        elif "=" in value and "," in value:
            return FlextLdapDataType.DN
        elif value.lower() in ["true", "false", "yes", "no"]:
            return FlextLdapDataType.BOOLEAN
        else:
            return FlextLdapDataType.STRING

    def to_ldap(self, value: Any) -> Any:
        """Convert Python value to LDAP format with caching."""
        if value is None:
            return None

        cache_key = (id(value), "to_ldap")
        if cache_key in self._conversion_cache:
            return self._conversion_cache[cache_key]

        converted = self._to_ldap_impl(value)
        self._conversion_cache[cache_key] = converted
        return converted

    def _to_ldap_impl(self, value: Any) -> Any:
        """Implementation of Python to LDAP conversion."""
        if isinstance(value, bool):
            return "TRUE" if value else "FALSE"
        elif isinstance(value, datetime):
            return value.strftime("%Y%m%d%H%M%SZ")
        elif isinstance(value, UUID):
            return str(value)
        elif isinstance(value, (int, float)):
            return str(value)
        elif isinstance(value, list):
            return [self.to_ldap(item) for item in value]
        else:
            return str(value)

    def from_ldap(self, value: Any, target_type: FlextLdapDataType | None = None) -> Any:
        """Convert LDAP value to Python format with intelligent type detection."""
        if value is None:
            return None

        cache_key = (id(value), f"from_ldap_{target_type}")
        if cache_key in self._conversion_cache:
            return self._conversion_cache[cache_key]

        converted = self._from_ldap_impl(value, target_type)
        self._conversion_cache[cache_key] = converted
        return converted

    def _from_ldap_impl(self, value: Any, target_type: FlextLdapDataType | None = None) -> Any:
        """Implementation of LDAP to Python conversion."""
        if isinstance(value, bytes):
            value = value.decode('utf-8')

        if isinstance(value, list):
            return [self.from_ldap(item, target_type) for item in value]

        if target_type is None:
            target_type = self.detect_type(value)

        if target_type == FlextLdapDataType.BOOLEAN:
            return str(value).lower() in ["true", "yes", "1"]
        elif target_type == FlextLdapDataType.INTEGER:
            return int(value)
        elif target_type == FlextLdapDataType.DATETIME:
            return datetime.strptime(str(value), "%Y%m%d%H%M%SZ").replace(tzinfo=UTC)
        elif target_type == FlextLdapDataType.UUID:
            return UUID(str(value))
        else:
            return str(value)


class FlextLdapConnectionManager:
    """INTELLIGENT connection manager using flext-core repository pattern."""

    def __init__(self) -> None:
        """Initialize with connection repository."""
        self._connections: FlextLdapRepository[Connection] = FlextLdapRepository()
        self._pool_configs: dict[str, FlextLdapConnectionConfig] = {}

    async def get_connection(self, config: FlextLdapConnectionConfig) -> FlextResult[Connection]:
        """Get connection with intelligent pooling and caching."""
        try:
            config_key = f"{config.server_url}:{config.bind_dn}"
            
            # Try to get existing connection
            existing = await self._connections.find_by_attribute("server_url", config.server_url)
            if existing and existing[0] and not existing[0].closed:
                return FlextResult.ok(existing[0])

            # Create new connection
            connection = await self._create_connection(config)
            if connection.is_success:
                await self._connections.save(connection.data)
                self._pool_configs[config_key] = config
                
            return connection
        except Exception as e:
            return FlextResult.fail(f"Failed to get connection: {e}")

    async def _create_connection(self, config: FlextLdapConnectionConfig) -> FlextResult[Connection]:
        """Create new LDAP connection."""
        try:
            # Create server with intelligent configuration
            server = Server(
                config.server_url,
                use_ssl=config.use_ssl,
                tls=config.tls_config,
                get_info=ALL,
                connect_timeout=config.connection_timeout
            )

            # Create connection
            connection = Connection(
                server,
                user=config.bind_dn,
                password=config.password,
                auto_bind=AUTO_BIND_NONE,
                raise_exceptions=True
            )

            # Test connection
            if not connection.bind():
                return FlextResult.fail(f"Bind failed: {connection.result}")

            return FlextResult.ok(connection)
        except LDAPException as e:
            return FlextResult.fail(f"LDAP error: {e}")
        except Exception as e:
            return FlextResult.fail(f"Connection error: {e}")

    async def close_connection(self, connection: Connection) -> FlextResult[bool]:
        """Close connection and remove from pool."""
        try:
            if hasattr(connection, 'server_url'):
                await self._connections.delete(getattr(connection, 'server_url', ''))
            connection.unbind()
            return FlextResult.ok(True)
        except Exception as e:
            return FlextResult.fail(f"Failed to close connection: {e}")


class FlextLdapClient:
    """UNIFIED LDAP client with intelligent infrastructure."""

    def __init__(self, config: FlextLdapConnectionConfig | None = None) -> None:
        """Initialize unified client."""
        self._config = config
        self._connection_manager = FlextLdapConnectionManager()
        self._converter = FlextLdapConverter()
        self._current_connection: Connection | None = None

    async def connect(self, config: FlextLdapConnectionConfig | None = None) -> FlextResult[bool]:
        """Connect with intelligent connection management."""
        try:
            use_config = config or self._config
            if not use_config:
                return FlextResult.fail("No connection configuration provided")

            connection_result = await self._connection_manager.get_connection(use_config)
            if not connection_result.is_success:
                return FlextResult.fail(connection_result.error)

            self._current_connection = connection_result.data
            return FlextResult.ok(True)
        except Exception as e:
            return FlextResult.fail(f"Connection failed: {e}")

    async def search(self, base_dn: str, search_filter: str, attributes: list[str] | None = None) -> FlextResult[list[dict[str, Any]]]:
        """Search with intelligent result conversion."""
        if not self._current_connection:
            return FlextResult.fail("Not connected")

        try:
            success = self._current_connection.search(
                search_base=base_dn,
                search_filter=search_filter,
                attributes=attributes or ['*']
            )

            if not success:
                return FlextResult.fail(f"Search failed: {self._current_connection.result}")

            # Convert results using intelligent converter
            results = []
            for entry in self._current_connection.entries:
                converted_entry = {
                    'dn': str(entry.entry_dn),
                    'attributes': {}
                }
                
                for attr_name, attr_values in entry.entry_attributes_as_dict.items():
                    # Use intelligent type conversion
                    converted_values = []
                    for value in attr_values:
                        converted = self._converter.from_ldap(value)
                        converted_values.append(converted)
                    
                    converted_entry['attributes'][attr_name] = converted_values

                results.append(converted_entry)

            return FlextResult.ok(results)
        except Exception as e:
            return FlextResult.fail(f"Search error: {e}")

    async def add(self, dn: str, object_classes: list[str], attributes: dict[str, Any]) -> FlextResult[bool]:
        """Add entry with intelligent attribute conversion."""
        if not self._current_connection:
            return FlextResult.fail("Not connected")

        try:
            # Convert attributes using intelligent converter
            ldap_attributes = {}
            for attr_name, attr_value in attributes.items():
                ldap_attributes[attr_name] = self._converter.to_ldap(attr_value)

            # Add objectClass
            ldap_attributes['objectClass'] = object_classes

            success = self._current_connection.add(dn, attributes=ldap_attributes)
            
            if not success:
                return FlextResult.fail(f"Add failed: {self._current_connection.result}")

            return FlextResult.ok(True)
        except Exception as e:
            return FlextResult.fail(f"Add error: {e}")

    async def modify(self, dn: str, changes: dict[str, Any]) -> FlextResult[bool]:
        """Modify entry with intelligent change conversion."""
        if not self._current_connection:
            return FlextResult.fail("Not connected")

        try:
            # Convert changes using intelligent converter
            ldap_changes = {}
            for attr_name, attr_value in changes.items():
                converted_value = self._converter.to_ldap(attr_value)
                ldap_changes[attr_name] = [(ldap3.MODIFY_REPLACE, converted_value)]

            success = self._current_connection.modify(dn, ldap_changes)
            
            if not success:
                return FlextResult.fail(f"Modify failed: {self._current_connection.result}")

            return FlextResult.ok(True)
        except Exception as e:
            return FlextResult.fail(f"Modify error: {e}")

    async def delete(self, dn: str) -> FlextResult[bool]:
        """Delete entry."""
        if not self._current_connection:
            return FlextResult.fail("Not connected")

        try:
            success = self._current_connection.delete(dn)
            
            if not success:
                return FlextResult.fail(f"Delete failed: {self._current_connection.result}")

            return FlextResult.ok(True)
        except Exception as e:
            return FlextResult.fail(f"Delete error: {e}")

    async def disconnect(self) -> FlextResult[bool]:
        """Disconnect with proper cleanup."""
        if self._current_connection:
            result = await self._connection_manager.close_connection(self._current_connection)
            self._current_connection = None
            return result
        return FlextResult.ok(True)

    def is_connected(self) -> bool:
        """Check connection status."""
        return self._current_connection is not None and not self._current_connection.closed


# COMPATIBILITY ALIASES
FlextLdapSimpleClient = FlextLdapClient  # From old client.py
FlextSimpleConverter = FlextLdapConverter  # From old converters.py

# FACTORY FUNCTIONS for easy instantiation
def create_ldap_client(server_url: str, bind_dn: str | None = None, password: str | None = None, **kwargs: Any) -> FlextLdapClient:
    """Factory for creating configured LDAP client."""
    config = FlextLdapConnectionConfig(
        server_url=server_url,
        bind_dn=bind_dn,
        password=password,
        **kwargs
    )
    return FlextLdapClient(config)


def create_ldap_converter() -> FlextLdapConverter:
    """Factory for creating LDAP converter."""
    return FlextLdapConverter()