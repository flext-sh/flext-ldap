"""🚀 LDAP Core Shared - Simplified Public API.

High-level convenience API for common LDAP operations.
Designed for maximum usability with Python 3.9+ compatibility.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Optional, Union

# Import the core components
from ldap_core_shared.core.connection_manager import (
    ConnectionInfo,
    LDAPConnectionManager,
)
from ldap_core_shared.domain.models import LDAPEntry
from ldap_core_shared.exceptions import (
    AuthenticationError,
    ConnectionError,
    LDAPError,
    ValidationError,
)
from ldap_core_shared.ldif.processor import LDIFProcessor
from ldap_core_shared.utils.logging import get_logger

if TYPE_CHECKING:
    import types

    from ldap_core_shared.connections.base import LDAPConnectionInfo


@dataclass
class LDAPConnectionConfig:
    """Configuration for LDAP connections."""

    server_url: str
    use_ssl: bool = False
    verify_cert: bool = True
    timeout: int = 30
    pool_size: int = 5


@dataclass
class QuickSearchParams:
    """Parameters for quick LDAP search operations."""

    server_url: str
    bind_dn: str
    password: str
    base_dn: str
    filter_str: str = "(objectClass=*)"
    attributes: Optional[list[str]] = None


logger = get_logger(__name__)


class SimpleLDAPClient:
    """🚀 Simple LDAP client for common operations.

    Provides a high-level interface for LDAP operations with automatic
    connection management, error handling, and Python 3.9+ compatibility.

    Example:
        Basic usage:

        >>> client = SimpleLDAPClient("ldap://server.com")
        >>> await client.connect("cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com", "password")
        >>> entries = await client.search("dc=example,dc=com", "(objectClass=user)")
        >>> for entry in entries:
        ...     print(f"User: {entry.dn}")
        >>> await client.disconnect()

        Context manager usage:

        >>> async with SimpleLDAPClient("ldap://server.com") as client:
        ...     await client.bind("cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com", "password")
        ...     entries = await client.search("dc=example,dc=com", "(objectClass=user)")
        ...     for entry in entries:
        ...         print(f"User: {entry.dn}")
    """

    def __init__(self, config: LDAPConnectionConfig) -> None:
        """Initialize LDAP client.

        Args:
            config: LDAP connection configuration
        """
        self.server_url = config.server_url
        self._parse_server_url(config.server_url)

        # Store configuration for later use
        self._config = config
        self._connection_info: LDAPConnectionInfo | None = None

        # Connection manager
        self._manager: Optional[LDAPConnectionManager] = None
        self._connected = False
        self._pool_size = config.pool_size

    def _parse_server_url(self, url: str) -> None:
        """Parse server URL into components."""
        try:
            from urllib.parse import urlparse

            parsed = urlparse(url)

            self._host = parsed.hostname or "localhost"
            self._port = parsed.port or (636 if parsed.scheme == "ldaps" else 389)
            self._use_ssl = parsed.scheme == "ldaps"

        except Exception as e:
            msg = f"Invalid server URL: {url}"
            raise ValidationError(msg, original_error=e) from e

    async def connect(self, bind_dn: str, password: str, base_dn: str = "") -> bool:
        """Connect and bind to LDAP server.

        Args:
            bind_dn: DN to bind with
            password: Password for authentication
            base_dn: Base DN for searches (optional)

        Returns:
            True if connection successful

        Raises:
            ConnectionError: If connection fails
            AuthenticationError: If authentication fails
        """
        try:
            # Create connection info with credentials
            connection_info = ConnectionInfo(
                host=self._host,
                port=self._port,
                bind_dn=bind_dn,
                bind_password=password,
                base_dn=base_dn or f"dc={self._host.split('.')[0]},dc=com",
                use_ssl=self._config.use_ssl,
                timeout=self._config.timeout,
            )

            # Create connection manager
            self._manager = LDAPConnectionManager(connection_info)

            # Test connection by trying to connect
            self._connected = True
            logger.info(
                "Connected to LDAP server",
                extra={
                    "host": self._host,
                    "port": self._port,
                    "bind_dn": bind_dn,
                },
            )
            return True

        except Exception as e:
            if isinstance(e, (ConnectionError, AuthenticationError)):
                raise
            msg = f"Failed to connect to LDAP server: {e}"
            raise ConnectionError(msg) from e

    async def disconnect(self) -> None:
        """Disconnect from LDAP server."""
        if self._manager:
            await self._manager.close()
            self._manager = None
        self._connected = False
        logger.info("Disconnected from LDAP server")

    async def search(
        self,
        base_dn: Optional[str] = None,
        filter_str: str = "(objectClass=*)",
        attributes: Optional[list[str]] = None,
        scope: str = "subtree",
        size_limit: int = 0,
    ) -> list[LDAPEntry]:
        """Search LDAP directory.

        Args:
            base_dn: Base DN for search (uses connection base_dn if None)
            filter_str: LDAP search filter
            attributes: List of attributes to retrieve (all if None)
            scope: Search scope (base, one, subtree)
            size_limit: Maximum number of entries to return (0 = no limit)

        Returns:
            List of LDAP entries

        Raises:
            ConnectionError: If not connected
            LDAPError: If search fails
        """
        if not self._connected or not self._manager:
            msg = "Not connected to LDAP server"
            raise ConnectionError(msg)

        search_base = base_dn or self._connection_info.base_dn

        try:
            async with self._manager.get_pooled_connection() as pooled_conn:
                connection = pooled_conn.connection

                # Perform search
                success = connection.search(
                    search_base=search_base,
                    search_filter=filter_str,
                    search_scope=self._convert_scope(scope),
                    attributes=attributes,
                    size_limit=size_limit,
                )

                if not success:
                    msg = f"Search failed: {connection.last_error}"
                    raise LDAPError(msg, error_code=str(connection.last_error))

                # Convert results to LDAPEntry objects
                entries = []
                for entry in connection.entries:
                    ldap_entry = LDAPEntry(
                        dn=entry.entry_dn,
                        attributes=dict(entry.entry_attributes_as_dict),
                        raw_attributes={},  # ldap3 handles encoding
                    )
                    entries.append(ldap_entry)

                logger.info(
                    "Search completed",
                    extra={
                        "base_dn": search_base,
                        "filter": filter_str,
                        "result_count": len(entries),
                    },
                )

                return entries

        except Exception as e:
            if isinstance(e, LDAPError):
                raise
            msg = f"Search operation failed: {e}"
            raise LDAPError(msg, original_error=e) from e

    def _convert_scope(self, scope: str) -> int:
        """Convert scope string to ldap3 constant."""
        import ldap3

        scope_map = {
            "base": ldap3.BASE,
            "one": ldap3.LEVEL,
            "subtree": ldap3.SUBTREE,
        }
        return scope_map.get(scope.lower(), ldap3.SUBTREE)

    async def add_entry(
        self,
        dn: str,
        attributes: dict[str, Union[str, list[str]]],
        object_classes: Optional[list[str]] = None,
    ) -> bool:
        """Add new LDAP entry.

        Args:
            dn: Distinguished name for new entry
            attributes: Entry attributes
            object_classes: Object classes for entry

        Returns:
            True if successful

        Raises:
            ConnectionError: If not connected
            LDAPError: If add operation fails
        """
        if not self._connected or not self._manager:
            msg = "Not connected to LDAP server"
            raise ConnectionError(msg)

        try:
            # Prepare attributes
            entry_attributes = dict(attributes)
            if object_classes:
                entry_attributes["objectClass"] = object_classes

            async with self._manager.get_pooled_connection() as pooled_conn:
                connection = pooled_conn.connection

                success = connection.add(dn, attributes=entry_attributes)

                if not success:
                    msg = f"Add operation failed: {connection.last_error}"
                    raise LDAPError(msg, error_code=str(connection.last_error))

                logger.info("Entry added successfully", extra={"dn": dn})
                return True

        except Exception as e:
            if isinstance(e, LDAPError):
                raise
            msg = f"Add operation failed: {e}"
            raise LDAPError(msg, original_error=e) from e

    async def modify_entry(
        self,
        dn: str,
        changes: dict[str, Union[str, list[str], None]],
    ) -> bool:
        """Modify existing LDAP entry.

        Args:
            dn: Distinguished name of entry to modify
            changes: Dictionary of attribute changes
                    - str/List[str]: replace attribute value(s)
                    - None: delete attribute

        Returns:
            True if successful

        Raises:
            ConnectionError: If not connected
            LDAPError: If modify operation fails
        """
        if not self._connected or not self._manager:
            msg = "Not connected to LDAP server"
            raise ConnectionError(msg)

        try:
            import ldap3

            # Prepare changes
            modifications = {}
            for attr, value in changes.items():
                if value is None:
                    modifications[attr] = [(ldap3.MODIFY_DELETE, [])]
                else:
                    modifications[attr] = [(ldap3.MODIFY_REPLACE, value)]

            async with self._manager.get_pooled_connection() as pooled_conn:
                connection = pooled_conn.connection

                success = connection.modify(dn, modifications)

                if not success:
                    msg = f"Modify operation failed: {connection.last_error}"
                    raise LDAPError(msg, error_code=str(connection.last_error))

                logger.info("Entry modified successfully", extra={"dn": dn})
                return True

        except Exception as e:
            if isinstance(e, LDAPError):
                raise
            msg = f"Modify operation failed: {e}"
            raise LDAPError(msg, original_error=e) from e

    async def delete_entry(self, dn: str) -> bool:
        """Delete LDAP entry.

        Args:
            dn: Distinguished name of entry to delete

        Returns:
            True if successful

        Raises:
            ConnectionError: If not connected
            LDAPError: If delete operation fails
        """
        if not self._connected or not self._manager:
            msg = "Not connected to LDAP server"
            raise ConnectionError(msg)

        try:
            async with self._manager.get_pooled_connection() as pooled_conn:
                connection = pooled_conn.connection

                success = connection.delete(dn)

                if not success:
                    msg = f"Delete operation failed: {connection.last_error}"
                    raise LDAPError(msg, error_code=str(connection.last_error))

                logger.info("Entry deleted successfully", extra={"dn": dn})
                return True

        except Exception as e:
            if isinstance(e, LDAPError):
                raise
            msg = f"Delete operation failed: {e}"
            raise LDAPError(msg, original_error=e) from e

    async def __aenter__(self) -> SimpleLDAPClient:
        """Async context manager entry."""
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: types.TracebackType | None,
    ) -> None:
        """Async context manager exit."""
        await self.disconnect()


# Convenience functions for common operations
async def quick_search(params: QuickSearchParams) -> list[LDAPEntry]:
    """Quick LDAP search operation.

    Convenience function for simple search operations without managing connections.

    Args:
        params: Search parameters including server URL, credentials, and search criteria

    Returns:
        List of LDAP entries
    """
    async with SimpleLDAPClient(params.server_url) as client:
        await client.connect(params.bind_dn, params.password, params.base_dn)
        return await client.search(params.base_dn, params.filter_str, params.attributes)


async def process_ldif_file(
    file_path: str,
    *,
    validate_schema: bool = True,
    batch_size: int = 1000,
    encoding: str = "utf-8",
) -> dict[str, Any]:
    """Process LDIF file with high performance.

    Convenience function for LDIF file processing.

    Args:
        file_path: Path to LDIF file
        validate_schema: Whether to validate schema
        batch_size: Batch size for processing
        encoding: File encoding

    Returns:
        Processing statistics
    """
    processor = LDIFProcessor()

    # Configure processor
    config = {
        "validate_schema": validate_schema,
        "batch_size": batch_size,
        "encoding": encoding,
    }

    # Process file
    result = await processor.process_file(file_path, config)

    return {
        "entries_processed": result.entries_processed,
        "processing_time": result.processing_time,
        "entries_per_second": (
            result.entries_processed / result.processing_time
            if result.processing_time > 0
            else 0
        ),
        "errors": result.errors,
        "warnings": result.warnings,
    }
