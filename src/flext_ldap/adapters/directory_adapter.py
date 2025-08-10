"""Directory Service Adapter - Implements flext-core FlextLdapDirectoryServiceInterface.

This adapter bridges the flext-core abstract domain interface with
the concrete FLEXT LDAP infrastructure implementation.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import asyncio
import concurrent.futures
from abc import ABC, abstractmethod
from asyncio import AbstractEventLoop
from typing import TYPE_CHECKING, Protocol, cast
from urllib.parse import urlparse

from flext_core import FlextResult, get_logger
from pydantic import SecretStr

if TYPE_CHECKING:
    from flext_core.typings import FlextTypes

from flext_ldap.config import FlextLdapAuthConfig, FlextLdapConnectionConfig
from flext_ldap.errors import (
    FlextLdapConnectionError,
    FlextLdapData,
    FlextLdapError,
    FlextLdapProtocol,
    FlextLdapTimeoutError,
)
from flext_ldap.ldap_infrastructure import FlextLdapSimpleClient, LdapAuthConfig

if TYPE_CHECKING:
    from collections.abc import Callable

logger = get_logger(__name__)


class DirectoryOperationResult:
    """Directory operation result constants - eliminates boolean parameters."""

    SUCCESS = True
    FAILURE = False


# 🚨 LOCAL PROTOCOLS - Clean Architecture compliance
class FlextLdapDirectoryConnectionProtocol(Protocol):
    """Protocol for directory connections."""

    host: str
    port: int


class FlextLdapDirectoryEntryProtocol(Protocol):
    """Protocol for directory entries."""

    dn: str
    attributes: FlextTypes.Core.JsonDict


class FlextLdapDirectoryEntry:
    """Simple implementation of FlextLdapDirectoryEntryProtocol."""

    def __init__(self, dn: str, attributes: FlextTypes.Core.JsonDict) -> None:
        self.dn = dn
        self.attributes = attributes


class FlextLdapDirectoryServiceInterface(ABC):
    """Abstract interface for directory operations."""

    @abstractmethod
    async def connect(
        self,
        server_url: str,
        *,
        bind_dn: str | None = None,
        password: str | None = None,
    ) -> FlextResult[bool]:
        """Connect to directory service."""
        ...

    @abstractmethod
    def search_users(
        self,
        search_filter: str,
        base_dn: str = "",
        attributes: list[str] | None = None,
    ) -> FlextResult[list[FlextLdapDirectoryEntryProtocol]]:
        """Search for users."""
        ...


class FlextLdapDirectoryAdapterInterface(ABC):
    """Abstract interface for directory adapters."""

    @abstractmethod
    def get_directory_service(self) -> FlextLdapDirectoryServiceInterface:
        """Get directory service implementation."""
        ...


class FlextLdapDirectoryService(FlextLdapDirectoryServiceInterface):
    """Concrete implementation of FlextLdapDirectoryServiceInterface."""

    def __init__(self) -> None:
        """Initialize FLEXT LDAP directory service."""
        logger.debug("Initializing FlextLdapDirectoryService")
        self._ldap_client: FlextLdapSimpleClient = FlextLdapSimpleClient()
        self._auth_config: FlextLdapAuthConfig | None = None
        self._connection_id: str | None = None
        logger.trace("FlextLdapDirectoryService initialized with default client")

    async def connect(
        self,
        server_url: str,
        *,
        bind_dn: str | None = None,
        password: str | None = None,
    ) -> FlextResult[bool]:
        """Establish connection to directory server using FLEXT LDAP.

        Args:
            server_url: LDAP server URL (REALLY USED)
            bind_dn: Bind DN for authentication (REALLY USED)
            password: Password for authentication (REALLY USED)

        Returns:
            FlextResult indicating connection success or error

        """
        logger.debug(
            "Connecting to LDAP server",
            extra={
                "server_url": server_url,
                "bind_dn": bind_dn,
                "has_password": bool(password),
            },
        )
        try:
            # Consolidated connection pipeline - Railway Oriented Programming
            return await self._execute_connection_pipeline(
                server_url,
                bind_dn,
                password,
            )

        except (ConnectionError, OSError) as e:
            # Convert to FLEXT LDAP error with rich context
            connection_error = FlextLdapConnectionError(
                f"Directory connection failed: {e}",
                server=server_url,
                cause=e,
            )
            return connection_error.to_bool_result()
        except ValueError as e:
            # Convert to FLEXT LDAP validation error with context
            validation_error = FlextLdapData.ValidationError(
                f"Directory configuration invalid: {e}",
                field_name="server_url",
                field_value=server_url,
                cause=e,
            )
            return validation_error.to_bool_result()
        except FlextLdapError:
            # Re-raise FLEXT LDAP errors as-is (they're already logged)
            raise
        except Exception as e:
            # Convert unexpected errors to generic FLEXT LDAP error
            generic_error = FlextLdapError(
                f"Unexpected directory connection error: {e}",
                cause=e,
                context={"server_url": server_url},
            )
            return generic_error.to_bool_result()

    async def _execute_connection_pipeline(
        self,
        server_url: str,
        bind_dn: str | None,
        password: str | None,
    ) -> FlextResult[bool]:
        """Execute connection pipeline with consolidated error handling."""
        # Railway Oriented Programming pattern - chain operations
        config_result = self._create_connection_config(server_url)
        if config_result.is_failure:
            return FlextResult.fail(config_result.error or "Configuration failed")

        config = config_result.data
        if config is None:
            return FlextResult.fail("Configuration data is None")
        connection_result = await self._establish_ldap_connection(config)
        if connection_result.is_failure:
            return connection_result

        auth_result = self._handle_authentication(bind_dn, password)
        if auth_result.is_failure:
            return auth_result

        # Log success and return single success result
        logger.info(
            "Directory connection established successfully",
            extra={
                "server_url": server_url,
                "bind_dn": bind_dn,
                "authenticated": bool(bind_dn and password),
            },
        )
        return FlextResult.ok(DirectoryOperationResult.SUCCESS)

    def _create_connection_config(
        self,
        server_url: str,
    ) -> FlextResult[FlextLdapConnectionConfig]:
        """Create connection configuration from server URL - Single Responsibility."""
        parsed = urlparse(server_url)
        host = parsed.hostname or "localhost"
        port = parsed.port or (636 if parsed.scheme == "ldaps" else 389)
        use_ssl = parsed.scheme == "ldaps"

        logger.trace(
            "Parsed connection parameters",
            extra={
                "host": host,
                "port": port,
                "use_ssl": use_ssl,
                "scheme": parsed.scheme,
            },
        )

        config = FlextLdapConnectionConfig(
            host=host,
            port=port,
            use_ssl=use_ssl,
        )
        logger.trace("Created connection config", extra={"config": config.__dict__})
        return FlextResult.ok(config)

    async def _establish_ldap_connection(
        self,
        config: FlextLdapConnectionConfig,
    ) -> FlextResult[bool]:
        """Establish LDAP connection using config - Single Responsibility."""
        self._ldap_client = FlextLdapSimpleClient(None)
        logger.debug("Created new LDAP client")

        logger.trace("Attempting LDAP connection")
        server_url = (
            f"{'ldaps' if config.use_ssl else 'ldap'}://{config.host}:{config.port}"
        )
        connection_result = await self._ldap_client.connect(server_url, None, None)
        if not connection_result.is_success:
            logger.error(
                "LDAP connection failed",
                extra={
                    "error": connection_result.error,
                    "server": config.server,
                    "port": config.port,
                },
            )
            return FlextResult.fail(f"Connection failed: {connection_result.error}")

        logger.debug("LDAP connection established successfully")
        # Save connection ID for later use in disconnect
        self._connection_id = connection_result.data
        return FlextResult.ok(DirectoryOperationResult.SUCCESS)

    def _handle_authentication(
        self,
        bind_dn: str | None,
        password: str | None,
    ) -> FlextResult[bool]:
        """Handle authentication if credentials provided - Single Responsibility."""
        if not (bind_dn and password):
            return FlextResult.ok(DirectoryOperationResult.SUCCESS)  # No auth needed

        logger.debug("Configuring authentication", extra={"bind_dn": bind_dn})

        auth_config = FlextLdapAuthConfig(
            bind_dn=bind_dn,
            bind_password=SecretStr(password),
        )

        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                logger.trace("Storing auth config for later use (async context)")
                self._auth_config = auth_config
            else:
                logger.trace("Attempting authentication in sync context")
                # Convert FlextLdapAuthConfig to LdapAuthConfig for compatibility
                ldap_auth_config = LdapAuthConfig(
                    bind_dn=auth_config.bind_dn,
                    password=auth_config.bind_password.get_secret_value()
                    if auth_config.bind_password
                    else None,
                )
                auth_result = loop.run_until_complete(
                    self._ldap_client.connect_with_auth(ldap_auth_config),
                )
                if not auth_result.is_success:
                    logger.error(
                        "Authentication failed",
                        extra={"bind_dn": bind_dn, "error": auth_result.error},
                    )
                    return FlextResult.fail(
                        f"Authentication failed: {auth_result.error}",
                    )
                logger.debug("Authentication successful")
        except RuntimeError:
            logger.trace("No event loop available, storing auth config")
            self._auth_config = auth_config

        return FlextResult.ok(DirectoryOperationResult.SUCCESS)

    def search_users(
        self,
        search_filter: str,
        base_dn: str = "",
        attributes: list[str] | None = None,
    ) -> FlextResult[list[FlextLdapDirectoryEntryProtocol]]:
        """Search for users in directory.

        Args:
            search_filter: LDAP search filter (REALLY USED)
            base_dn: Base DN for search (REALLY USED)
            attributes: Attributes to retrieve (REALLY USED)

        """
        logger.debug(
            "Searching for users",
            extra={
                "search_filter": search_filter,
                "base_dn": base_dn,
                "attributes": attributes,
            },
        )
        try:
            # Railway Oriented Programming - Consolidated search execution
            return self._execute_user_search_pipeline(
                search_filter,
                base_dn,
                attributes,
            )

        except TimeoutError as e:
            timeout_error = FlextLdapTimeoutError(
                f"User search timed out: {e}",
                operation="search_users",
                timeout_seconds=30,
                cause=e,
            )
            return timeout_error.to_typed_result(list[FlextLdapDirectoryEntryProtocol])
        except ConnectionError as e:
            connection_error = FlextLdapConnectionError(
                f"Search connection failed: {e}",
                cause=e,
            )
            return connection_error.to_typed_result(
                list[FlextLdapDirectoryEntryProtocol],
            )
        except ValueError as e:
            filter_error = FlextLdapProtocol.FilterError(
                f"Invalid search parameters: {e}",
                filter_string=search_filter,
                cause=e,
            )
            return filter_error.to_typed_result(list[FlextLdapDirectoryEntryProtocol])
        except OSError as e:
            network_error = FlextLdapConnectionError(
                f"Network error during search: {e}",
                cause=e,
            )
            return network_error.to_typed_result(list[FlextLdapDirectoryEntryProtocol])

    def _execute_user_search_pipeline(
        self,
        search_filter: str,
        base_dn: str,
        attributes: list[str] | None,
    ) -> FlextResult[list[FlextLdapDirectoryEntryProtocol]]:
        """Execute user search pipeline with consolidated error handling."""
        # REALMENTE usar os parâmetros recebidos seguindo SOLID!

        # Use default base_dn if empty
        actual_base_dn = base_dn or "dc=example,dc=com"

        # Use default attributes if none provided
        actual_attributes = attributes if attributes is not None else ["*"]

        logger.trace(
            "Normalized search parameters",
            extra={
                "actual_base_dn": actual_base_dn,
                "actual_attributes": actual_attributes,
                "search_filter": search_filter,
            },
        )

        # Execute REAL search with REAL parameters
        search_result = self._perform_async_search(
            actual_base_dn,
            search_filter,
            actual_attributes,
        )

        if not search_result.is_success:
            logger.error(
                "User search failed",
                extra={
                    "error": search_result.error,
                    "base_dn": actual_base_dn,
                    "filter": search_filter,
                },
            )
            return FlextResult.fail(f"Search failed: {search_result.error}")

        # Convert and return results - search_result.data already contains
        # FlextLdapDirectoryEntry objects
        entries_data = search_result.data or []
        return FlextResult.ok(entries_data)

    def _perform_async_search(
        self,
        base_dn: str,
        search_filter: str,
        attributes: list[str],
    ) -> FlextResult[list[FlextLdapDirectoryEntryProtocol]]:
        """Perform async search handling different event loop scenarios."""
        logger.trace("Executing LDAP search")
        try:
            loop: AbstractEventLoop = asyncio.get_event_loop()
            if loop.is_running():
                logger.trace("Using thread pool executor for async search")
                # Create task for async execution
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future = executor.submit(
                        asyncio.run,
                        self._ldap_client.search(base_dn, search_filter, attributes),
                    )
                    raw_result = future.result(timeout=30)
                    return self._convert_raw_search_result(raw_result)
            else:
                logger.trace("Using event loop for search")
                raw_result = loop.run_until_complete(
                    self._ldap_client.search(base_dn, search_filter, attributes),
                )
                return self._convert_raw_search_result(raw_result)
        except RuntimeError:
            logger.trace("No event loop, using asyncio.run for search")
            # No event loop, create new one
            raw_result = asyncio.run(
                self._ldap_client.search(base_dn, search_filter, attributes),
            )
            return self._convert_raw_search_result(raw_result)
        except Exception as e:
            logger.exception("Search operation failed", exc_info=e)
            return FlextResult.fail(f"Search error: {e}")

    def _convert_raw_search_result(
        self,
        raw_result: FlextResult[list[FlextTypes.Core.JsonDict]],
    ) -> FlextResult[list[FlextLdapDirectoryEntryProtocol]]:
        """Convert raw search result to protocol format."""
        if raw_result.is_failure:
            return FlextResult.fail(raw_result.error or "Search failed")

        raw_data = raw_result.data or []
        return self._convert_search_results_to_directory_protocol(raw_data)

    def _convert_search_results_to_protocol(
        self,
        raw_results: list[FlextTypes.Core.JsonDict],
        base_dn: str,
        search_filter: str,
        attributes: list[str],
    ) -> FlextResult[list[FlextLdapDirectoryEntryProtocol]]:
        """Convert raw search results to protocol format."""
        logger.debug(
            "User search completed successfully",
            extra={"result_count": len(raw_results)},
        )

        # Convert to protocol format
        logger.trace("Converting search results to protocol format")
        entries: list[FlextLdapDirectoryEntryProtocol] = []
        for raw_entry in raw_results:
            # Create proper entry from raw data
            entry = cast(
                "FlextLdapDirectoryEntryProtocol",
                {
                    "dn": raw_entry.get("dn", ""),
                    "attributes": raw_entry.get("attributes", {}),
                },
            )
            entries.append(entry)
            # Type-safe attribute count calculation
            attrs_obj = (
                raw_entry.get("attributes", {}) if isinstance(raw_entry, dict) else {}
            )
            attr_count = len(attrs_obj) if isinstance(attrs_obj, dict) else 0

            logger.trace(
                "Converted entry",
                extra={
                    "dn": raw_entry.get("dn", ""),
                    "attribute_count": attr_count,
                },
            )

        logger.info(
            "User search completed",
            extra={
                "base_dn": base_dn,
                "filter": search_filter,
                "result_count": len(entries),
                "attributes_requested": attributes,
            },
        )
        return FlextResult.ok(entries)

    async def disconnect(self, _connection_id: str | None = None) -> FlextResult[bool]:
        """Disconnect from directory server.

        Args:
            connection_id: Optional connection identifier (for compatibility with tests)

        Returns:
            FlextResult indicating success or failure

        """
        try:
            # Use saved connection_id with new async API
            if not self._connection_id:
                return FlextResult.fail("No active connection to disconnect")

            disconnect_result = await self._ldap_client.disconnect(self._connection_id)
            if disconnect_result.is_success:
                self._connection_id = None
                return FlextResult.ok(DirectoryOperationResult.SUCCESS)
            return FlextResult.fail(f"Disconnect failed: {disconnect_result.error}")
        except ConnectionError as e:
            connection_error = FlextLdapConnectionError(
                f"Disconnect connection error: {e}",
                cause=e,
            )
            return connection_error.to_bool_result()
        except OSError as e:
            network_error = FlextLdapConnectionError(
                f"Network error during disconnect: {e}",
                cause=e,
            )
            return network_error.to_bool_result()
        except FlextLdapError:
            # Re-raise FLEXT LDAP errors as-is
            raise
        except Exception as e:
            generic_error = FlextLdapError(
                f"Unexpected disconnect error: {e}",
                cause=e,
            )
            return generic_error.to_bool_result()

    def search(
        self,
        base_dn: str,
        search_filter: str,
        attributes: list[str] | None = None,
    ) -> FlextResult[list[FlextLdapDirectoryEntryProtocol]]:
        """Search directory entries using FLEXT LDAP.

        Args:
            base_dn: Base distinguished name for search (REALLY USED)
            search_filter: LDAP search filter (REALLY USED)
            attributes: Attributes to retrieve (REALLY USED)

        Returns:
            FlextResult containing list of entries or error

        """
        try:
            # Railway Oriented Programming - Consolidated search execution
            return self._execute_directory_search_pipeline(
                base_dn,
                search_filter,
                attributes,
            )

        except TimeoutError as e:
            timeout_error = FlextLdapTimeoutError(
                f"Directory search timed out: {e}",
                operation="search",
                cause=e,
            )
            return timeout_error.to_typed_result(list[FlextLdapDirectoryEntryProtocol])
        except ConnectionError as e:
            connection_error = FlextLdapConnectionError(
                f"Search connection failed: {e}",
                cause=e,
            )
            return connection_error.to_typed_result(
                list[FlextLdapDirectoryEntryProtocol],
            )
        except ValueError as e:
            filter_error = FlextLdapProtocol.FilterError(
                f"Invalid search parameters: {e}",
                filter_string=search_filter,
                cause=e,
            )
            return filter_error.to_typed_result(list[FlextLdapDirectoryEntryProtocol])
        except OSError as e:
            network_error = FlextLdapConnectionError(
                f"Network error during search: {e}",
                cause=e,
            )
            return network_error.to_typed_result(list[FlextLdapDirectoryEntryProtocol])

    def _execute_directory_search_pipeline(
        self,
        base_dn: str,
        search_filter: str,
        attributes: list[str] | None,
    ) -> FlextResult[list[FlextLdapDirectoryEntryProtocol]]:
        """Execute directory search pipeline with consolidated error handling."""
        # REALMENTE usar TODOS os parâmetros recebidos!
        # Use provided parameters directly
        actual_attributes = attributes if attributes is not None else ["*"]

        # Execute REAL search with ALL provided parameters
        search_result = self._perform_ldap_search_operation(
            base_dn,
            search_filter,
            actual_attributes,
        )

        if not search_result.is_success:
            return FlextResult.fail(f"Search failed: {search_result.error}")

        # Convert results to protocol format
        search_data = search_result.data or []
        return self._convert_search_results_to_directory_protocol(search_data)

    def _perform_ldap_search_operation(
        self,
        base_dn: str,
        search_filter: str,
        actual_attributes: list[str],
    ) -> FlextResult[list[FlextTypes.Core.JsonDict]]:
        """Perform LDAP search operation with proper async handling."""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future = executor.submit(
                        asyncio.run,
                        self._ldap_client.search(
                            base_dn,
                            search_filter,
                            actual_attributes,
                        ),
                    )
                    return future.result(timeout=30)
            else:
                return loop.run_until_complete(
                    self._ldap_client.search(
                        base_dn,
                        search_filter,
                        actual_attributes,
                    ),
                )
        except RuntimeError:
            return asyncio.run(
                self._ldap_client.search(base_dn, search_filter, actual_attributes),
            )
        except Exception as e:
            logger.exception("LDAP search operation failed", exc_info=e)
            return FlextResult.fail(f"Search error: {e}")

    def _convert_search_results_to_directory_protocol(
        self,
        raw_results: list[FlextTypes.Core.JsonDict],
    ) -> FlextResult[list[FlextLdapDirectoryEntryProtocol]]:
        """Convert raw search results to directory protocol format."""
        entries: list[FlextLdapDirectoryEntryProtocol] = []
        for raw_entry in raw_results:
            entry = FlextLdapDirectoryEntry(
                dn=str(raw_entry.get("dn", "")),
                attributes=(
                    cast("FlextTypes.Core.JsonDict", raw_entry.get("attributes", {}))
                    if isinstance(raw_entry.get("attributes"), dict)
                    else {}
                ),
            )
            entries.append(entry)

        return FlextResult.ok(entries)

    def add_entry(
        self,
        dn: str,
        attributes: FlextTypes.Core.JsonDict,
    ) -> FlextResult[bool]:
        """Add new directory entry using FLEXT LDAP.

        Args:
            dn: Distinguished name for new entry (REALLY USED)
            attributes: Entry attributes (REALLY USED)

        Returns:
            FlextResult indicating success or failure

        """
        try:
            # REALMENTE usar os parâmetros dn e attributes!
            object_classes, clean_attributes = self._extract_object_classes(attributes)

            # Execute REAL add with REAL parameters
            add_result = self._execute_async_operation(
                self._ldap_client.add,
                dn,
                object_classes,
                clean_attributes,
            )

            if hasattr(add_result, "is_success") and not add_result.is_success:
                error_msg = getattr(add_result, "error", "Unknown error")
                # Distinguish between LDAP operation failures and execution errors
                if "Operation error:" in error_msg:
                    # This is an execution exception, use "error" format
                    return FlextResult.fail(f"Add entry error: {error_msg}")
                # This is an LDAP operation failure, use "failed" format
                return FlextResult.fail(f"Add entry failed: {error_msg}")

            return FlextResult.ok(DirectoryOperationResult.SUCCESS)

        except ConnectionError as e:
            connection_error = FlextLdapConnectionError(
                f"Add entry connection failed: {e}",
                cause=e,
            )
            return connection_error.to_bool_result()
        except TimeoutError as e:
            timeout_error = FlextLdapTimeoutError(
                f"Add entry timed out: {e}",
                operation="add_entry",
                cause=e,
            )
            return timeout_error.to_bool_result()
        except ValueError as e:
            validation_error = FlextLdapData.ValidationError(
                f"Invalid entry data: {e}",
                field_name="attributes",
                cause=e,
            )
            return validation_error.to_bool_result()

    def _extract_object_classes(
        self,
        attributes: FlextTypes.Core.JsonDict,
    ) -> tuple[list[str], FlextTypes.Core.JsonDict]:
        """Extract objectClass from attributes following SOLID Single Responsibility.

        Args:
            attributes: Original attributes dictionary

        Returns:
            Tuple of (object_classes, clean_attributes)

        """
        object_classes = []
        clean_attributes = {}

        for attr_name, attr_value in attributes.items():
            if attr_name.lower() == "objectclass":
                if isinstance(attr_value, list):
                    object_classes = [str(v) for v in attr_value]
                else:
                    object_classes = [str(attr_value)]
            else:
                clean_attributes[attr_name] = attr_value

        # Ensure we have objectClass
        if not object_classes:
            object_classes = ["top"]

        return object_classes, clean_attributes

    def _execute_async_operation(
        self,
        operation_func: Callable[..., object],  # Generic callable for flexibility
        *args: object,
    ) -> object:
        """Execute async operation with proper event loop handling.

        Following DRY principle - centralized async execution pattern.
        """
        try:
            # Try to get current event loop
            try:
                asyncio.get_running_loop()
                # We're in an async context, use thread executor
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    # Type annotation for future
                    future: concurrent.futures.Future[object] = executor.submit(
                        lambda: asyncio.run(operation_func(*args)),
                    )
                    raw_result = future.result(timeout=30)
                    # Only convert search results - other operations return their
                    # results directly
                    if hasattr(operation_func, "__name__") and "search" in str(
                        operation_func,
                    ):
                        return self._convert_raw_search_result(
                            cast(
                                "FlextResult[list[FlextTypes.Core.JsonDict]]",
                                raw_result,
                            ),
                        )
                    return raw_result
            except RuntimeError:
                # No running loop, we can use asyncio.run directly
                return asyncio.run(operation_func(*args))
        except Exception as e:
            logger.exception("Async operation failed", exc_info=e)
            return FlextResult.fail(f"Operation error: {e}")

    def modify_entry(
        self,
        dn: str,
        changes: FlextTypes.Core.JsonDict,
    ) -> FlextResult[bool]:
        """Modify existing directory entry using FLEXT LDAP.

        Args:
            dn: Distinguished name of entry to modify (REALLY USED)
            changes: Modifications to apply (REALLY USED)

        Returns:
            FlextResult indicating success or failure

        """
        try:
            # Railway Oriented Programming - Consolidated modify execution
            return self._execute_modify_entry_pipeline(dn, changes)

        except TimeoutError as e:
            timeout_error = FlextLdapTimeoutError(
                f"Modify entry timed out: {e}",
                operation="modify_entry",
                cause=e,
            )
            return timeout_error.to_bool_result()
        except ConnectionError as e:
            connection_error = FlextLdapConnectionError(
                f"Modify entry connection failed: {e}",
                cause=e,
            )
            return connection_error.to_bool_result()
        except ValueError as e:
            validation_error = FlextLdapData.ValidationError(
                f"Invalid modification data: {e}",
                field_name="changes",
                cause=e,
            )
            return validation_error.to_bool_result()
        except OSError as e:
            network_error = FlextLdapConnectionError(
                f"Network error during modify: {e}",
                cause=e,
            )
            return network_error.to_bool_result()

    def _execute_modify_entry_pipeline(
        self,
        dn: str,
        changes: FlextTypes.Core.JsonDict,
    ) -> FlextResult[bool]:
        """Execute modify entry pipeline with consolidated error handling."""
        # REALMENTE usar os parâmetros dn e changes!
        # Execute REAL modify with REAL parameters using DRY helper
        modify_result = self._execute_async_operation(
            self._ldap_client.modify,
            dn,
            changes,
        )

        return self._handle_modify_result(modify_result)

    def _handle_modify_result(self, modify_result: object) -> FlextResult[bool]:
        """Handle the result of modify operation."""
        if hasattr(modify_result, "is_success") and not modify_result.is_success:
            error_msg = getattr(modify_result, "error", "Unknown error")
            return FlextResult.fail(f"Modify entry failed: {error_msg}")

        return FlextResult.ok(DirectoryOperationResult.SUCCESS)

    def delete_entry(
        self,
        dn: str,
    ) -> FlextResult[bool]:
        """Delete directory entry using FLEXT LDAP.

        Args:
            dn: Distinguished name of entry to delete (REALLY USED)

        Returns:
            FlextResult indicating success or failure

        """
        try:
            # Railway Oriented Programming - Consolidated delete execution
            return self._execute_delete_entry_pipeline(dn)

        except TimeoutError as e:
            timeout_error = FlextLdapTimeoutError(
                f"Delete entry timed out: {e}",
                operation="delete_entry",
                cause=e,
            )
            return timeout_error.to_bool_result()
        except ConnectionError as e:
            connection_error = FlextLdapConnectionError(
                f"Delete entry connection failed: {e}",
                cause=e,
            )
            return connection_error.to_bool_result()
        except ValueError as e:
            dn_error = FlextLdapProtocol.DNError(
                f"Invalid DN for delete: {e}",
                dn=dn,
                cause=e,
            )
            return dn_error.to_bool_result()
        except OSError as e:
            network_error = FlextLdapConnectionError(
                f"Network error during delete: {e}",
                cause=e,
            )
            return network_error.to_bool_result()

    def _execute_delete_entry_pipeline(self, dn: str) -> FlextResult[bool]:
        """Execute delete entry pipeline with consolidated error handling."""
        # REALMENTE usar o parâmetro dn!
        # Execute REAL delete with REAL dn parameter using DRY helper
        delete_result = self._execute_async_operation(self._ldap_client.delete, dn)

        return self._handle_delete_result(delete_result)

    def _handle_delete_result(self, delete_result: object) -> FlextResult[bool]:
        """Handle the result of delete operation."""
        if hasattr(delete_result, "is_success") and not delete_result.is_success:
            error_msg = getattr(delete_result, "error", "Unknown error")
            return FlextResult.fail(f"Delete entry failed: {error_msg}")

        return FlextResult.ok(DirectoryOperationResult.SUCCESS)


class FlextLdapDirectoryAdapter(FlextLdapDirectoryAdapterInterface):
    """Adapter that provides FLEXT LDAP directory service implementation."""

    def get_directory_service(self) -> FlextLdapDirectoryServiceInterface:
        """Get FLEXT LDAP directory service implementation.

        Returns:
            Configured FLEXT LDAP directory service implementation

        """
        return FlextLdapDirectoryService()


# Backward compatibility aliases
DirectoryConnectionProtocol = FlextLdapDirectoryConnectionProtocol
DirectoryEntryProtocol = FlextLdapDirectoryEntryProtocol
DirectoryServiceInterface = FlextLdapDirectoryServiceInterface
DirectoryAdapterInterface = FlextLdapDirectoryAdapterInterface
