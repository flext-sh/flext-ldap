"""LDAP Connection Operations - Extracted from manager.py for complexity reduction."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

import ldap3
from ldap3.core.exceptions import LDAPException

if TYPE_CHECKING:
    from collections.abc import AsyncIterable, Callable
    from typing import AsyncContextManager

    from flext_ldap.connections.base import LDAPSearchConfig
    from flext_ldap.connections.state import LDAPSearchParams

logger = logging.getLogger(__name__)


class LDAPOperations:
    """LDAP operations implementation extracted from manager for complexity reduction.

    SOLID Compliance:
    - S: Single responsibility for LDAP operations only
    - O: Open for extension through inheritance
    - L: Follows LDAP operation contracts
    - I: Implements focused operation interfaces
    - D: Depends on connection abstraction
    """

    def __init__(
        self,
        get_connection_func: Callable[[], AsyncContextManager[Any]],
    ) -> None:
        """Initialize LDAP operations with connection provider.

        Args:
            get_connection_func: Function that provides LDAP connections
        """
        self._get_connection = get_connection_func

    async def search(self, params: LDAPSearchParams) -> AsyncIterable[dict[str, Any]]:
        """Perform LDAP search operation.

        Args:
            params: Search parameters

        Yields:
            Search results as dictionaries
        """
        search_config = LDAPSearchConfig(
            search_base=params.search_base,
            search_filter=params.search_filter,
            attributes=params.attributes,
            search_scope=params.search_scope,  # type: ignore
            size_limit=params.size_limit,
            time_limit=params.time_limit,
        )

        async for result in self.search_with_config(search_config):
            yield result

    async def search_with_config(
        self,
        search_config: LDAPSearchConfig,
    ) -> AsyncIterable[dict[str, Any]]:
        """Perform LDAP search with configuration object.

        Args:
            search_config: Search configuration

        Yields:
            Search results as dictionaries
        """
        async with self._get_connection() as connection:
            try:
                connection.search(
                    search_base=search_config.search_base,
                    search_filter=search_config.search_filter,
                    search_scope=search_config.get_ldap3_scope(),
                    attributes=search_config.attributes,
                    size_limit=search_config.size_limit,
                    time_limit=search_config.time_limit,
                )

                for entry in connection.entries:
                    yield {
                        "dn": entry.entry_dn,
                        "attributes": dict(entry.entry_attributes_as_dict),
                    }

            except LDAPException as e:
                logger.exception("LDAP search error: %s", e)
                raise

    async def modify_entry(self, dn: str, changes: dict[str, Any]) -> bool:
        """Modify LDAP entry.

        Args:
            dn: Distinguished name of entry to modify
            changes: Dictionary of changes to apply

        Returns:
            True if modification succeeded
        """
        async with self._get_connection() as connection:
            try:
                # Convert changes to ldap3 format
                ldap3_changes = []
                for attr, value in changes.items():
                    if isinstance(value, list):
                        ldap3_changes.append((attr, ldap3.MODIFY_REPLACE, value))
                    else:
                        ldap3_changes.append((attr, ldap3.MODIFY_REPLACE, [value]))

                result = connection.modify(dn, ldap3_changes)
                if result:
                    logger.info("Successfully modified entry: %s", dn)
                else:
                    logger.error("Failed to modify entry %s: %s", dn, connection.result)

                return result

            except LDAPException as e:
                logger.exception("LDAP modify error for %s: %s", dn, e)
                raise

    async def add_entry(self, dn: str, attributes: dict[str, Any]) -> bool:
        """Add new LDAP entry.

        Args:
            dn: Distinguished name for new entry
            attributes: Entry attributes

        Returns:
            True if addition succeeded
        """
        async with self._get_connection() as connection:
            try:
                result = connection.add(dn, attributes=attributes)
                if result:
                    logger.info("Successfully added entry: %s", dn)
                else:
                    logger.error("Failed to add entry %s: %s", dn, connection.result)

                return result

            except LDAPException as e:
                logger.exception("LDAP add error for %s: %s", dn, e)
                raise

    async def delete_entry(self, dn: str) -> bool:
        """Delete LDAP entry.

        Args:
            dn: Distinguished name of entry to delete

        Returns:
            True if deletion succeeded
        """
        async with self._get_connection() as connection:
            try:
                result = connection.delete(dn)
                if result:
                    logger.info("Successfully deleted entry: %s", dn)
                else:
                    logger.error("Failed to delete entry %s: %s", dn, connection.result)

                return result

            except LDAPException as e:
                logger.exception("LDAP delete error for %s: %s", dn, e)
                raise

    async def get_entry(
        self,
        dn: str,
        attributes: list[str] | None = None,
    ) -> dict[str, Any] | None:
        """Get single LDAP entry by DN.

        Args:
            dn: Distinguished name of entry
            attributes: Attributes to retrieve

        Returns:
            Entry data or None if not found
        """
        async with self._get_connection() as connection:
            try:
                connection.search(
                    search_base=dn,
                    search_filter="(objectClass=*)",
                    search_scope=ldap3.BASE,
                    attributes=attributes or ldap3.ALL_ATTRIBUTES,
                )

                if connection.entries:
                    entry = connection.entries[0]
                    return {
                        "dn": entry.entry_dn,
                        "attributes": dict(entry.entry_attributes_as_dict),
                    }

                return None

            except LDAPException as e:
                logger.exception("LDAP get entry error for %s: %s", dn, e)
                raise

    async def compare_attribute(self, dn: str, attribute: str, value: str) -> bool:
        """Compare attribute value in LDAP entry.

        Args:
            dn: Distinguished name of entry
            attribute: Attribute name to compare
            value: Value to compare against

        Returns:
            True if attribute matches value
        """
        async with self._get_connection() as connection:
            try:
                return connection.compare(dn, attribute, value)

            except LDAPException as e:
                logger.exception("LDAP compare error for %s.%s: %s", dn, attribute, e)
                raise

    async def get_schema_info(self) -> dict[str, Any]:
        """Retrieve LDAP schema information.

        Returns:
            Schema information dictionary
        """
        async with self._get_connection() as connection:
            try:
                if hasattr(connection.server, "schema"):
                    schema = connection.server.schema
                    return {
                        "object_classes": (
                            list(schema.object_classes.keys())
                            if schema.object_classes
                            else []
                        ),
                        "attributes": (
                            list(schema.attribute_types.keys())
                            if schema.attribute_types
                            else []
                        ),
                        "syntaxes": (
                            list(schema.syntaxes.keys()) if schema.syntaxes else []
                        ),
                    }
                logger.warning("Schema information not available")
                return {"object_classes": [], "attributes": [], "syntaxes": []}

            except LDAPException as e:
                logger.exception("LDAP schema error: %s", e)
                raise

    async def bulk_search(
        self,
        search_configs: list[LDAPSearchConfig],
    ) -> list[list[dict[str, Any]]]:
        """Perform multiple searches concurrently for high performance.

        Args:
            search_configs: List of search configurations

        Returns:
            List of search results, one per configuration
        """
        import asyncio

        async def single_search(config: LDAPSearchConfig) -> list[dict[str, Any]]:
            return [result async for result in self.search_with_config(config)]

        # Execute searches concurrently
        tasks = [single_search(config) for config in search_configs]
        return await asyncio.gather(*tasks)

    async def health_check(self) -> bool:
        """Perform health check on LDAP connection.

        Returns:
            True if connection is healthy
        """
        try:
            async with self._get_connection() as connection:
                # Simple search to verify connectivity
                connection.search(
                    search_base="",
                    search_filter="(objectClass=*)",
                    search_scope=ldap3.BASE,
                    attributes=["objectClass"],
                    size_limit=1,
                    time_limit=5,
                )
                return True

        except Exception as e:
            logger.warning("Health check failed: %s", e)
            return False
