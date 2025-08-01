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
from typing import Protocol, cast
from urllib.parse import urlparse

from flext_core import FlextResult, get_logger

from flext_ldap.config import FlextLdapAuthConfig, FlextLdapConnectionConfig
from flext_ldap.ldap_infrastructure import FlextLdapClient as FlextLdapSimpleClient

logger = get_logger(__name__)


# Operation result constants to eliminate FBT smells - SOLID DRY Principle
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
    attributes: dict[str, object]


class FlextLdapDirectoryServiceInterface(ABC):
    """Abstract interface for directory operations."""

    @abstractmethod
    def connect(
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
        logger.trace("FlextLdapDirectoryService initialized with default client")

    def connect(
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
            return self._execute_connection_pipeline(server_url, bind_dn, password)

        except (ConnectionError, OSError) as e:
            logger.exception(
                "Directory connection error",
                extra={"server_url": server_url},
            )
            return FlextResult.fail(f"Connection error: {e}")
        except ValueError as e:
            logger.exception(
                "Directory configuration error",
                extra={"server_url": server_url},
            )
            return FlextResult.fail(f"Configuration error: {e}")
        except Exception as e:
            logger.exception(
                "Unexpected directory connection error",
                extra={"server_url": server_url},
            )
            return FlextResult.fail(f"Unexpected error: {e}")

    def _execute_connection_pipeline(
        self, server_url: str, bind_dn: str | None, password: str | None
    ) -> FlextResult[bool]:
        """Execute connection pipeline with consolidated error handling."""
        # Railway Oriented Programming pattern - chain operations
        config_result = self._create_connection_config(server_url)
        if config_result.is_failure:
            return config_result

        connection_result = self._establish_ldap_connection(config_result.data)
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
        self, server_url: str
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
            server=host,
            port=port,
            use_ssl=use_ssl,
        )
        logger.trace("Created connection config", extra={"config": config.__dict__})
        return FlextResult.ok(config)

    def _establish_ldap_connection(
        self, config: FlextLdapConnectionConfig
    ) -> FlextResult[bool]:
        """Establish LDAP connection using config - Single Responsibility."""
        self._ldap_client = FlextLdapSimpleClient(config)
        logger.debug("Created new LDAP client with config")

        logger.trace("Attempting LDAP connection")
        connection_result = self._ldap_client.connect(config)
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
        return FlextResult.ok(DirectoryOperationResult.SUCCESS)

    def _handle_authentication(
        self, bind_dn: str | None, password: str | None
    ) -> FlextResult[bool]:
        """Handle authentication if credentials provided - Single Responsibility."""
        if not (bind_dn and password):
            return FlextResult.ok(DirectoryOperationResult.SUCCESS)  # No auth needed

        logger.debug("Configuring authentication", extra={"bind_dn": bind_dn})
        auth_config = FlextLdapAuthConfig(
            bind_dn=bind_dn,
            bind_password=password,
        )

        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                logger.trace("Storing auth config for later use (async context)")
                self._auth_config = auth_config
            else:
                logger.trace("Attempting authentication in sync context")
                auth_result = loop.run_until_complete(
                    self._ldap_client.connect_with_auth(auth_config),
                )
                if not auth_result.is_success:
                    logger.error(
                        "Authentication failed",
                        extra={"bind_dn": bind_dn, "error": auth_result.error},
                    )
                    return FlextResult.fail(
                        f"Authentication failed: {auth_result.error}"
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
                search_filter, base_dn, attributes
            )

        except ConnectionError as e:
            logger.exception("Search connection error", extra={"filter": search_filter})
            return FlextResult.fail(f"Search connection error: {e}")
        except ValueError as e:
            logger.exception("Search parameter error", extra={"filter": search_filter})
            return FlextResult.fail(f"Search parameter error: {e}")
        except OSError as e:
            logger.exception("Search network error", extra={"filter": search_filter})
            return FlextResult.fail(f"Search network error: {e}")
        except TimeoutError as e:
            logger.exception("Search timeout error", extra={"filter": search_filter})
            return FlextResult.fail(f"Search timeout error: {e}")

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
            actual_base_dn, search_filter, actual_attributes
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

        # Convert and return results
        return self._convert_search_results_to_protocol(
            search_result.data or [], actual_base_dn, search_filter, actual_attributes
        )

    def _perform_async_search(
        self, base_dn: str, search_filter: str, attributes: list[str]
    ) -> FlextResult:
        """Perform async search handling different event loop scenarios."""
        logger.trace("Executing LDAP search")
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                logger.trace("Using thread pool executor for async search")
                # Create task for async execution
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future = executor.submit(
                        asyncio.run,
                        self._ldap_client.search(base_dn, search_filter, attributes),
                    )
                    return future.result(timeout=30)
            else:
                logger.trace("Using event loop for search")
                return loop.run_until_complete(
                    self._ldap_client.search(base_dn, search_filter, attributes)
                )
        except RuntimeError:
            logger.trace("No event loop, using asyncio.run for search")
            # No event loop, create new one
            return asyncio.run(
                self._ldap_client.search(base_dn, search_filter, attributes)
            )

    def _convert_search_results_to_protocol(
        self,
        raw_results: list,
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
                raw_entry.get("attributes", {})
                if isinstance(raw_entry, dict)
                else {}
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

    def disconnect(self) -> FlextResult[bool]:
        """Disconnect from directory server.

        Returns:
            FlextResult indicating success or failure

        """
        try:
            disconnect_result = self._ldap_client.disconnect()
            if disconnect_result.is_success:
                return FlextResult.ok(data=DirectoryOperationResult.SUCCESS)
            return FlextResult.fail(f"Disconnect failed: {disconnect_result.error}")
        except ConnectionError as e:
            return FlextResult.fail(f"Disconnect connection error: {e}")
        except OSError as e:
            return FlextResult.fail(f"Disconnect network error: {e}")

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
                base_dn, search_filter, attributes
            )

        except ConnectionError as e:
            return FlextResult.fail(f"Search connection error: {e}")
        except ValueError as e:
            return FlextResult.fail(f"Search parameter error: {e}")
        except OSError as e:
            return FlextResult.fail(f"Search network error: {e}")
        except TimeoutError as e:
            return FlextResult.fail(f"Search timeout error: {e}")

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
            base_dn, search_filter, actual_attributes
        )

        if not search_result.is_success:
            return FlextResult.fail(f"Search failed: {search_result.error}")

        # Convert results to protocol format
        search_data = search_result.data or []
        return self._convert_search_results_to_directory_protocol(search_data)

    def _perform_ldap_search_operation(
        self, base_dn: str, search_filter: str, actual_attributes: list[str]
    ) -> FlextResult:
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

    def _convert_search_results_to_directory_protocol(
        self, raw_results: list
    ) -> FlextResult[list[FlextLdapDirectoryEntryProtocol]]:
        """Convert raw search results to directory protocol format."""
        entries: list[FlextLdapDirectoryEntryProtocol] = []
        for raw_entry in raw_results:
            entry = cast(
                "FlextLdapDirectoryEntryProtocol",
                {
                    "dn": raw_entry.get("dn", ""),
                    "attributes": raw_entry.get("attributes", {}),
                },
            )
            entries.append(entry)

        return FlextResult.ok(entries)

    def add_entry(
        self,
        dn: str,
        attributes: dict[str, object],
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
                return FlextResult.fail(f"Add entry failed: {error_msg}")

            return FlextResult.ok(DirectoryOperationResult.SUCCESS)

        except ConnectionError as e:
            return FlextResult.fail(f"Add entry error: {e}")
        except TimeoutError as e:
            return FlextResult.fail(f"Add entry timeout: {e}")
        except ValueError as e:
            return FlextResult.fail(f"Add entry parameter error: {e}")

    def _extract_object_classes(
        self,
        attributes: dict[str, object],
    ) -> tuple[list[str], dict[str, object]]:
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

    def _execute_async_operation(self, operation_func: object, *args: object) -> object:
        """Execute async operation with proper event loop handling.

        Following DRY principle - centralized async execution pattern.
        """
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    # Type ignore for dynamic callable execution
                    future = executor.submit(lambda: asyncio.run(operation_func(*args)))  # type: ignore[operator]
                    return future.result(timeout=30)
            else:
                # Type ignore for dynamic callable execution
                return loop.run_until_complete(operation_func(*args))  # type: ignore[operator]
        except RuntimeError:
            # Type ignore for dynamic callable execution
            return asyncio.run(operation_func(*args))  # type: ignore[operator]

    def modify_entry(
        self,
        dn: str,
        changes: dict[str, object],
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

        except ConnectionError as e:
            return FlextResult.fail(f"Modify entry connection error: {e}")
        except ValueError as e:
            return FlextResult.fail(f"Modify entry parameter error: {e}")
        except OSError as e:
            return FlextResult.fail(f"Modify entry network error: {e}")
        except TimeoutError as e:
            return FlextResult.fail(f"Modify entry timeout: {e}")

    def _execute_modify_entry_pipeline(
        self, dn: str, changes: dict[str, object]
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

        except ConnectionError as e:
            return FlextResult.fail(f"Delete entry connection error: {e}")
        except ValueError as e:
            return FlextResult.fail(f"Delete entry parameter error: {e}")
        except OSError as e:
            return FlextResult.fail(f"Delete entry network error: {e}")
        except TimeoutError as e:
            return FlextResult.fail(f"Delete entry timeout: {e}")

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
