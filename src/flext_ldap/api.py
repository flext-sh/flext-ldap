"""FLEXT-LDAP API - Consolidated Unified Enterprise LDAP Interface.

🎯 CONSOLIDATES 2 MAJOR FILES INTO SINGLE PEP8 MODULE:
- api.py (64,526 bytes) - Primary unified LDAP interface with Clean Architecture
- ldap_api.py (3,989 bytes) - Compatibility facade and deprecated module

TOTAL CONSOLIDATION: 68,515 bytes → ldap_api.py (PEP8 organized)

This module provides the primary interface for LDAP directory operations,
implementing Clean Architecture patterns with railway-oriented programming
for comprehensive error handling and type safety.

The FlextLdapApi class serves as the unified entry point for all LDAP operations,
consolidating connection management, domain object conversion, and error handling
into a single, consistent interface.

Key Features:
- Type-safe LDAP operations with FlextResult pattern
- Automatic session and connection lifecycle management
- Domain entity conversion (raw LDAP data → rich objects)
- Integration with flext-core dependency injection container
- Comprehensive error handling and logging

Architecture:
This module follows Clean Architecture principles by providing an interface
that abstracts LDAP protocol complexities while maintaining clean separation
between domain logic and infrastructure concerns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, cast
from urllib.parse import urlparse

from flext_core import (
    FlextResult,
    get_flext_container,
    get_logger,
)
from flext_ldif.api import FlextLdifAPI
from flext_ldif.models import (
    FlextLdifAttributes as _LdifAttributes,
    FlextLdifDistinguishedName as _LdifDN,
    FlextLdifEntry as _LdifEntry,
)

from flext_ldap.config import FlextLdapConnectionConfig, FlextLdapSettings
from flext_ldap.infrastructure import FlextLdapClient
from flext_ldap.models import (
    FlextLdapCreateUserRequest,
    FlextLdapDistinguishedName,
    FlextLdapEntry,
    FlextLdapFilter,
    FlextLdapGroup,
    FlextLdapUser,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator


logger = get_logger(__name__)

# =============================================================================
# LDAP API IMPLEMENTATION - Primary Interface
# =============================================================================


class FlextLdapApi:
    """Unified LDAP API implementing enterprise-grade directory operations.

    This class provides a comprehensive interface for LDAP directory services,
    implementing Clean Architecture patterns with domain-driven design and
    railway-oriented programming for robust error handling.

    The API abstracts LDAP protocol complexity while providing type-safe operations
    that return rich domain entities instead of raw protocol data structures.

    Key Capabilities:
    - Session-based connection management with automatic cleanup
    - Type-safe operations returning FlextResult[T] for error handling
    - Domain entity conversion (LDAP entries → business objects)
    - Integration with flext-core dependency injection container
    - Comprehensive logging and error correlation

    Architecture:
    Follows Clean Architecture with clear separation between:
    - API Interface (this class)
    - Domain Logic (entities and value objects)
    - Infrastructure (LDAP client and protocol handling)
    """

    def __init__(self, config: FlextLdapSettings | None = None) -> None:
        """Initialize LDAP API with optional configuration.

        Args:
            config: Optional LDAP configuration settings. If not provided,
                   will be resolved from flext-core dependency container.

        """
        self._container = get_flext_container()
        self._id_generator = self._container.get("FlextIdGenerator").unwrap_or(None)
        self._config = config
        self._client: FlextLdapClient | None = None

        logger.debug(
            "FlextLdapApi initialized",
            extra={"config_provided": config is not None},
        )

    def _generate_id(self) -> str:
        """Generate unique ID using container generator or fallback."""
        if self._id_generator and hasattr(self._id_generator, "generate"):
            return cast("str", self._id_generator.generate())
        return str(uuid.uuid4())

    def _get_client(self) -> FlextLdapClient:
        """Get LDAP client instance, creating if necessary."""
        if self._client is None:
            config = self._config or FlextLdapSettings()
            # Convert FlextLdapConnectionConfig to dict if available
            client_config = None
            if config.default_connection:
                client_config = config.default_connection.model_dump()
            self._client = FlextLdapClient(client_config)

        return self._client

    @asynccontextmanager
    async def connection(
        self,
        server_uri: str,
        bind_dn: str | None = None,
        bind_password: str | None = None,
    ) -> AsyncIterator[str]:
        """Async context manager for LDAP connections.

        Args:
            server_uri: LDAP server URI (ldap:// or ldaps://)
            bind_dn: Optional bind DN for authentication
            bind_password: Optional bind password

        Yields:
            TLdapSessionId: Session ID for use in other API operations

        Example:
            >>> api = FlextLdapApi()
            >>> async with api.connection(
            ...     "ldap://localhost", "cn=admin,dc=example,dc=com", "secret"
            ... ) as session:
            ...     result = await api.search(
            ...         session, "dc=example,dc=com", "(objectClass=person)"
            ...     )
            ...     if result.is_success:
            ...         print(f"Found {len(result.data)} entries")

        """
        client = self._get_client()
        session_id = self._generate_id()

        try:
            # Connect to LDAP server
            connection_result = await client.connect(server_uri, bind_dn, bind_password)
            if not connection_result.is_success:
                logger.error(
                    f"Failed to connect to LDAP server: {connection_result.error}",
                )
                msg = f"LDAP connection failed: {connection_result.error}"
                raise RuntimeError(msg)

            logger.debug(
                "LDAP connection established",
                extra={
                    "session_id": session_id,
                    "server_uri": server_uri,
                    "bind_dn": bind_dn,
                },
            )

            yield session_id

        finally:
            # Ensure connection is properly closed
            try:
                await client.disconnect()
                logger.debug("LDAP connection closed", extra={"session_id": session_id})
            except Exception as e:
                logger.warning(
                    f"Error closing LDAP connection: {e}",
                    extra={"session_id": session_id},
                )

    async def search(  # noqa: C901, PLR0913
        self,
        base_dn: str = "",
        search_filter: str = "(objectClass=*)",
        scope: str = "subtree",
        attributes: list[str] | None = None,
        size_limit: int = 1000,
        time_limit: int = 30,
        session: str | None = None,
        session_id: str | None = None,
    ) -> FlextResult[list[FlextLdapEntry]]:
        """Perform LDAP search operation.

        Args:
            session_id: Session ID from connection context
            base_dn: Base DN for search
            search_filter: LDAP search filter
            scope: Search scope (base, onelevel, subtree)
            attributes: List of attributes to retrieve (None for all)
            size_limit: Maximum number of entries to return
            time_limit: Search timeout in seconds
            session: Session ID from connection context
            session_id: Session ID from connection context

        Returns:
            FlextResult[list[FlextLdapEntry]]: Search results as domain entities

        """
        try:
            # Support both 'session' and 'session_id' for backward compatibility
            session_identifier: str | None = session_id or session
            # Validate inputs
            dn_validation = FlextLdapDistinguishedName(
                value=base_dn,
            ).validate_business_rules()
            if not dn_validation.is_success:
                return FlextResult.fail(f"Invalid base DN: {dn_validation.error}")

            filter_validation = FlextLdapFilter(
                value=search_filter,
            ).validate_business_rules()
            if not filter_validation.is_success:
                return FlextResult.fail(
                    f"Invalid search filter: {filter_validation.error}",
                )

            client = self._get_client()

            # Perform LDAP search
            search_result = await client.search(
                base_dn=base_dn,
                search_filter=search_filter,
                scope=scope,
                attributes=attributes,
                size_limit=size_limit,
                time_limit=time_limit,
            )

            if not search_result.is_success:
                return FlextResult.fail(f"LDAP search failed: {search_result.error}")

            # Convert raw LDAP entries to domain entities
            entries = []
            if search_result.data:  # Check if data is not None
                for raw_entry in search_result.data:
                    # Ensure dn is a string
                    dn = raw_entry.get("dn", "")
                    if isinstance(dn, (list, bytes)):
                        dn = str(dn[0] if isinstance(dn, list) and dn else dn)

                    # Ensure object_classes is a list of strings
                    object_classes = raw_entry.get("objectClass", [])
                    if not isinstance(object_classes, list):
                        object_classes = [str(object_classes)]

                    # Convert attributes to proper format
                    entry_attributes: dict[str, object] = {}
                    for k, v in raw_entry.items():
                        if k == "dn":
                            continue
                        if isinstance(v, list):
                            entry_attributes[k] = [str(item) for item in v]
                        else:
                            entry_attributes[k] = [str(v)]

                    entry = FlextLdapEntry(
                        id=self._generate_id(),
                        dn=str(dn),
                        object_classes=[str(oc) for oc in object_classes],
                        attributes=entry_attributes,
                    )
                    entries.append(entry)

            logger.debug(
                "LDAP search completed",
                extra={
                    "session_id": session_identifier,
                    "base_dn": base_dn,
                    "filter": search_filter,
                    "result_count": len(entries),
                },
            )

            return FlextResult.ok(entries)

        except Exception as e:
            logger.exception(
                "LDAP search error",
                extra={
                    "session_id": session_identifier,
                    "base_dn": base_dn,
                    "filter": search_filter,
                },
            )
            return FlextResult.fail(f"Search operation failed: {e!s}")

    async def connect(
        self,
        server_uri: str,
        bind_dn: str | None = None,
        bind_password: str | None = None,
    ) -> FlextResult[str]:
        """Establish a connection and return a session identifier.

        This method provides a simple imperative alternative to the
        async context manager exposed by `connection(...)`, matching
        expectations from integration tests and legacy usage.

        Args:
            server_uri: LDAP server URI (ldap:// or ldaps://)
            bind_dn: Optional bind DN
            bind_password: Optional bind password

        Returns:
            FlextResult[str]: Session ID when connected

        """
        client = self._get_client()
        session_id = self._generate_id()

        connect_result = await client.connect(server_uri, bind_dn, bind_password)
        if not connect_result.is_success:
            return FlextResult.fail(connect_result.error or "Connection failed")

        logger.debug(
            "LDAP connection established (imperative connect)",
            extra={
                "session_id": session_id,
                "server_uri": server_uri,
                "bind_dn": bind_dn,
            },
        )
        return FlextResult.ok(session_id)

    async def disconnect(self, session_id: str) -> FlextResult[None]:
        """Close the active LDAP connection for the given session.

        The current simplified implementation maintains a single client
        instance. This method forwards to the underlying client and
        logs the session identifier for traceability.

        Args:
            session_id: Session identifier previously returned by `connect`

        Returns:
            FlextResult[None]: Success or error result

        """
        _ = session_id
        client = self._get_client()
        result = await client.disconnect()
        if result.is_success:
            logger.debug("LDAP connection closed (imperative disconnect)")
        return result

    async def get_entry(
        self,
        session_id: str,
        dn: str,
        attributes: list[str] | None = None,
    ) -> FlextResult[FlextLdapEntry]:
        """Get a single LDAP entry by DN.

        Args:
            session_id: Session ID from connection context
            dn: Distinguished Name of the entry to retrieve
            attributes: List of attributes to retrieve (None for all)

        Returns:
            FlextResult[FlextLdapEntry]: The entry as a domain entity

        """
        search_result = await self.search(
            session_id=session_id,
            base_dn=dn,
            search_filter="(objectClass=*)",
            scope="base",
            attributes=attributes,
            size_limit=1,
        )

        if not search_result.is_success:
            return FlextResult.fail(search_result.error or "Search operation failed")

        if not search_result.data:
            return FlextResult.fail(f"Entry not found: {dn}")

        return FlextResult.ok(search_result.data[0])

    async def create_user(
        self,
        session_id: str,
        user_request: FlextLdapCreateUserRequest,
    ) -> FlextResult[FlextLdapUser]:
        """Create a new LDAP user.

        Args:
            session_id: Session ID from connection context
            user_request: User creation request with required attributes

        Returns:
            FlextResult[FlextLdapUser]: Created user entity

        """
        try:
            client = self._get_client()

            # Build LDAP attributes from request
            attributes: dict[str, list[str]] = {
                "objectClass": user_request.object_classes,
                "cn": [user_request.cn],
                "sn": [user_request.sn],
                "uid": [user_request.uid],
            }

            if user_request.given_name:
                attributes["givenName"] = [user_request.given_name]

            if user_request.mail:
                attributes["mail"] = [user_request.mail]

            if user_request.user_password:
                attributes["userPassword"] = [user_request.user_password]

            # Add additional attributes
            attributes.update(user_request.additional_attributes)

            # Create user in LDAP
            create_result = await client.add_entry(user_request.dn, attributes)
            if not create_result.is_success:
                return FlextResult.fail(f"Failed to create user: {create_result.error}")

            # Return created user as domain entity
            user = FlextLdapUser(
                id=self._generate_id(),
                dn=user_request.dn,
                object_classes=user_request.object_classes,
                attributes=attributes,  # type: ignore[arg-type]
                uid=user_request.uid,
                cn=user_request.cn,
                sn=user_request.sn,
                given_name=user_request.given_name,
                mail=user_request.mail,
            )

            logger.info(
                "User created successfully",
                extra={
                    "session_id": session_id,
                    "user_dn": user_request.dn,
                    "uid": user_request.uid,
                },
            )

            return FlextResult.ok(user)

        except Exception as e:
            logger.exception(
                "User creation error",
                extra={
                    "session_id": session_id,
                    "user_dn": user_request.dn,
                },
            )
            return FlextResult.fail(f"User creation failed: {e!s}")

    async def create_group(
        self,
        session_id: str,
        dn: str,
        cn: str,
        description: str | None = None,
        *,
        members: list[str] | None = None,
    ) -> FlextResult[FlextLdapGroup]:
        """Create a new LDAP group.

        Args:
            session_id: Session ID from connection context
            dn: Distinguished Name for the group
            cn: Common Name for the group
            description: Optional group description
            members: Optional list of member DNs

        Returns:
            FlextResult[FlextLdapGroup]: Created group entity

        """
        try:
            client = self._get_client()

            # Build LDAP attributes
            attributes: dict[str, list[str]] = {
                "objectClass": ["groupOfNames", "top"],
                "cn": [cn],
            }

            if description:
                attributes["description"] = [description]

            # Add members (groupOfNames requires at least one member)
            member_list = members or []
            if not member_list:
                # Add dummy member if none provided (required by groupOfNames)
                member_list = ["cn=dummy,ou=temp,dc=example,dc=com"]

            attributes["member"] = member_list

            # Create group in LDAP
            create_result = await client.add_entry(dn, attributes)
            if not create_result.is_success:
                return FlextResult.fail(
                    f"Failed to create group: {create_result.error}",
                )

            # Return created group as domain entity
            group = FlextLdapGroup(
                id=self._generate_id(),
                dn=dn,
                object_classes=["groupOfNames", "top"],
                attributes=attributes,  # type: ignore[arg-type]
                cn=cn,
                description=description,
                members=member_list,
            )

            logger.info(
                "Group created successfully",
                extra={
                    "session_id": session_id,
                    "group_dn": dn,
                    "cn": cn,
                    "member_count": len(member_list),
                },
            )

            return FlextResult.ok(group)

        except Exception as e:
            logger.exception(
                "Group creation error",
                extra={
                    "session_id": session_id,
                    "group_dn": dn,
                },
            )
            return FlextResult.fail(f"Group creation failed: {e!s}")

    async def modify_entry(
        self,
        session_id: str,
        dn: str,
        modifications: dict[str, list[str]],
    ) -> FlextResult[None]:
        """Modify an existing LDAP entry.

        Args:
            session_id: Session ID from connection context
            dn: Distinguished Name of the entry to modify
            modifications: Dictionary of attribute modifications

        Returns:
            FlextResult[None]: Success or error result

        """
        try:
            client = self._get_client()

            # Perform LDAP modification
            modify_result = await client.modify_entry(dn, modifications)
            if not modify_result.is_success:
                return FlextResult.fail(
                    f"Failed to modify entry: {modify_result.error}",
                )

            logger.info(
                "Entry modified successfully",
                extra={
                    "session_id": session_id,
                    "entry_dn": dn,
                    "modification_count": len(modifications),
                },
            )

            return FlextResult.ok(None)

        except Exception as e:
            logger.exception(
                "Entry modification error",
                extra={
                    "session_id": session_id,
                    "entry_dn": dn,
                },
            )
            return FlextResult.fail(f"Entry modification failed: {e!s}")

    async def delete_entry(
        self,
        session_id: str,
        dn: str,
    ) -> FlextResult[None]:
        """Delete an LDAP entry.

        Args:
            session_id: Session ID from connection context
            dn: Distinguished Name of the entry to delete

        Returns:
            FlextResult[None]: Success or error result

        """
        try:
            client = self._get_client()

            # Perform LDAP deletion
            delete_result = await client.delete_entry(dn)
            if not delete_result.is_success:
                return FlextResult.fail(
                    f"Failed to delete entry: {delete_result.error}",
                )

            logger.info(
                "Entry deleted successfully",
                extra={
                    "session_id": session_id,
                    "entry_dn": dn,
                },
            )

            return FlextResult.ok(None)

        except Exception as e:
            logger.exception(
                "Entry deletion error",
                extra={
                    "session_id": session_id,
                    "entry_dn": dn,
                },
            )
            return FlextResult.fail(f"Entry deletion failed: {e!s}")

    async def add_group_member(
        self,
        session_id: str,
        group_dn: str,
        member_dn: str,
    ) -> FlextResult[None]:
        """Add member to LDAP group.

        Args:
            session_id: Session ID from connection context
            group_dn: Distinguished Name of the group
            member_dn: Distinguished Name of the member to add

        Returns:
            FlextResult[None]: Success or error result

        """
        modifications = {
            "member": [member_dn],
        }

        modify_result = await self.modify_entry(session_id, group_dn, modifications)
        if modify_result.is_success:
            logger.info(
                "Member added to group",
                extra={
                    "session_id": session_id,
                    "group_dn": group_dn,
                    "member_dn": member_dn,
                },
            )

        return modify_result

    async def remove_group_member(
        self,
        session_id: str,
        group_dn: str,
        member_dn: str,
    ) -> FlextResult[None]:
        """Remove member from LDAP group.

        Args:
            session_id: Session ID from connection context
            group_dn: Distinguished Name of the group
            member_dn: Distinguished Name of the member to remove

        Returns:
            FlextResult[None]: Success or error result

        """
        try:
            client = self._get_client()

            # Get current group members
            group_result = await self.get_entry(session_id, group_dn, ["member"])
            if not group_result.is_success:
                return FlextResult.fail(f"Failed to get group: {group_result.error}")

            if not group_result.data:
                return FlextResult.fail("Group data not found")
            current_members = group_result.data.get_attribute_values("member")
            if member_dn not in current_members:
                return FlextResult.fail(f"Member not found in group: {member_dn}")

            # Remove member from list
            updated_members = [m for m in current_members if m != member_dn]

            # If no members left, add dummy member (required by groupOfNames)
            if not updated_members:
                updated_members = ["cn=dummy,ou=temp,dc=example,dc=com"]

            # Update group
            modifications = {"member": updated_members}
            modify_result = await client.modify_entry(group_dn, modifications)

            if modify_result.is_success:
                logger.info(
                    "Member removed from group",
                    extra={
                        "session_id": session_id,
                        "group_dn": group_dn,
                        "member_dn": member_dn,
                    },
                )

            return modify_result

        except Exception as e:
            logger.exception(
                "Group member removal error",
                extra={
                    "session_id": session_id,
                    "group_dn": group_dn,
                    "member_dn": member_dn,
                },
            )
            return FlextResult.fail(f"Member removal failed: {e!s}")

    def get_connection_info(self) -> dict[str, object]:
        """Get current connection information.

        Returns:
            dict[str, object]: Connection information including server, port, etc.

        """
        if self._config and self._config.default_connection:
            conn = self._config.default_connection
            return {
                "server": conn.server,
                "port": conn.port,
                "use_ssl": conn.use_ssl,
                "bind_dn": conn.bind_dn,
                "timeout": conn.timeout,
            }

        return {"status": "no_configuration"}

    # =============================================================================
    # flext-ldif INTEGRATION
    # =============================================================================

    async def import_ldif_string(
        self, session_id: str, ldif_content: str,
    ) -> FlextResult[int]:
        """Import LDIF content into the connected LDAP server.

        Parses entries using flext-ldif and creates them via real LDAP operations.

        Returns the number of successfully imported entries.
        """
        _ = session_id  # Current client instance is used directly
        ldif_api = FlextLdifAPI()
        parse_result = ldif_api.parse(ldif_content)
        if parse_result.is_failure:
            return FlextResult.fail(parse_result.error or "Failed to parse LDIF")

        entries = parse_result.data or []
        client = self._get_client()
        imported = 0
        for entry in entries:
            try:
                dn = str(entry.dn.value)
                attrs = entry.attributes.attributes
                add_result = await client.add_entry(dn, attrs)
                if add_result.is_success:
                    imported += 1
                else:
                    return FlextResult.fail(
                        f"Failed to add entry {dn}: {add_result.error}",
                    )
            except Exception as e:
                return FlextResult.fail(f"Failed to import entry: {e!s}")

        return FlextResult.ok(imported)

    async def import_ldif_file(
        self, session_id: str, file_path: str,
    ) -> FlextResult[int]:
        """Import LDIF entries from a file path using flext-ldif."""
        _ = session_id
        ldif_api = FlextLdifAPI()
        parse_result = ldif_api.parse_file(file_path)
        if parse_result.is_failure:
            return FlextResult.fail(parse_result.error or "Failed to parse LDIF file")

        entries = parse_result.data or []
        client = self._get_client()
        imported = 0
        for entry in entries:
            try:
                dn = str(entry.dn.value)
                attrs = entry.attributes.attributes
                add_result = await client.add_entry(dn, attrs)
                if add_result.is_success:
                    imported += 1
                else:
                    return FlextResult.fail(
                        f"Failed to add entry {dn}: {add_result.error}",
                    )
            except Exception as e:
                return FlextResult.fail(f"Failed to import entry: {e!s}")

        return FlextResult.ok(imported)

    async def export_search_to_ldif(
        self,
        session_id: str,
        base_dn: str,
        search_filter: str = "(objectClass=*)",
        *,
        scope: str = "subtree",
        attributes: list[str] | None = None,
    ) -> FlextResult[str]:
        """Run a search and serialize results to LDIF using flext-ldif."""
        _ = session_id
        search_result = await self.search(
            base_dn=base_dn,
            search_filter=search_filter,
            scope=scope,
            attributes=attributes,
        )
        if search_result.is_failure:
            return FlextResult.fail(search_result.error or "LDAP search failed")

        entries = search_result.data or []

        # Transform to flext-ldif entries
        ldif_entries: list[_LdifEntry] = []
        for e in entries:
            try:
                dn = _LdifDN(value=e.dn)
                attrs: dict[str, list[str]] = {
                    k: ([str(v) for v in v] if isinstance(v, list) else [str(v)])
                    for k, v in (e.attributes or {}).items()
                }
                ldif_entries.append(
                    _LdifEntry(
                        id=f"ldif_{len(ldif_entries)}",
                        dn=dn,
                        attributes=_LdifAttributes(attributes=attrs),
                    ),
                )
            except Exception as exc:
                return FlextResult.fail(f"Failed to transform entry to LDIF: {exc!s}")

        ldif_api = FlextLdifAPI()
        write_result = ldif_api.write(ldif_entries)
        if write_result.is_failure:
            return FlextResult.fail(write_result.error or "Failed to write LDIF")

        return FlextResult.ok(write_result.data or "")

    async def test_connection(
        self,
        server_uri: str,
        bind_dn: str | None = None,
        bind_password: str | None = None,
    ) -> FlextResult[dict[str, object]]:
        """Test LDAP connection without creating a session.

        Args:
            server_uri: LDAP server URI
            bind_dn: Optional bind DN
            bind_password: Optional bind password

        Returns:
            FlextResult[dict[str, object]]: Connection test result with details

        """
        try:
            async with self.connection(
                server_uri,
                bind_dn,
                bind_password,
            ) as session_id:
                # Test with a simple search
                test_result = await self.search(
                    session_id=session_id,
                    base_dn="",
                    search_filter="(objectClass=*)",
                    scope="base",
                    size_limit=1,
                    time_limit=5,
                )

                connection_info = {
                    "server_uri": server_uri,
                    "bind_dn": bind_dn,
                    "authenticated": bind_dn is not None,
                    "search_successful": test_result.is_success,
                    "status": "connected",
                }

                return FlextResult.ok(dict(connection_info))

        except Exception as e:
            return FlextResult.fail(f"Connection test failed: {e!s}")


# =============================================================================
# FACTORY FUNCTIONS
# =============================================================================


def get_ldap_api(config: FlextLdapSettings | None = None) -> FlextLdapApi:
    """Get LDAP API instance with optional configuration.

    Args:
        config: Optional LDAP configuration settings

    Returns:
        FlextLdapApi: Configured LDAP API instance

    Example:
        >>> from flext_ldap.api import get_ldap_api
        >>> from flext_ldap.config import create_development_config
        >>>
        >>> config = create_development_config(host="ldap.example.com")
        >>> api = get_ldap_api(config)
        >>> async with api.connection("ldap://ldap.example.com") as session:
        ...     result = await api.search(session, "dc=example,dc=com", "(uid=john)")

    """
    return FlextLdapApi(config)


def create_ldap_api(
    server_uri: str,
    bind_dn: str | None = None,
    bind_password: str | None = None,
    *,
    use_ssl: bool = False,
    timeout: int = 30,
) -> FlextLdapApi:
    """Create LDAP API instance with connection configuration.

    Args:
        server_uri: LDAP server URI
        bind_dn: Optional bind DN for authentication
        bind_password: Optional bind password
        use_ssl: Whether to use SSL/LDAPS
        timeout: Operation timeout in seconds

    Returns:
        FlextLdapApi: Configured LDAP API instance

    """
    # Parse server URI
    parsed = urlparse(server_uri)
    host = parsed.hostname or "localhost"
    port = parsed.port

    # Auto-detect SSL and port
    if parsed.scheme == "ldaps":
        use_ssl = True
        port = port or 636
    else:
        port = port or 389

    # Create connection configuration
    connection_config = FlextLdapConnectionConfig(
        server=host,
        port=port,
        bind_dn=bind_dn or "",
        bind_password=bind_password or "",
        use_ssl=use_ssl,
        timeout=timeout,
    )

    # Create settings with connection
    settings = FlextLdapSettings(default_connection=connection_config)

    return FlextLdapApi(settings)


# =============================================================================
# BACKWARD COMPATIBILITY AND LEGACY SUPPORT
# =============================================================================

# Import required types for backward compatibility - canonical mandatory

# Export all public symbols
__all__ = [
    # Primary API class
    "FlextLdapApi",
    "create_ldap_api",
    # Factory functions
    "get_ldap_api",
]
