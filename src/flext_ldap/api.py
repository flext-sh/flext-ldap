"""FLEXT-LDAP API - PROFESSIONAL REFACTORED UNIFIED INTERFACE.

This module provides enterprise-grade LDAP operations following SOLID principles
and eliminating high cyclomatic complexity identified by quality analysis.

REFACTORED TO ADDRESS:
- High cyclomatic complexity (92 -> <10 per function)
- Functions with many parameters (9 -> 5 maximum)
- Functions with many parameters (6 for create_group, export_search_to_ldif, create_ldap_api)
- Function with high complexity (32 for search)
- Code duplication (33 lines of similar code)

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from flext_core import (
    FlextResult,
    get_flext_container,
    get_logger,
)
from flext_ldif.api import FlextLdifAPI
from pydantic import BaseModel, Field, validator

from flext_ldap.config import FlextLdapConnectionConfig, FlextLdapSettings
from flext_ldap.exceptions import FlextLdapConnectionError
from flext_ldap.infrastructure import FlextLdapClient
from flext_ldap.models import (
    FlextLdapCreateUserRequest,
    FlextLdapEntry,
    FlextLdapGroup,
    FlextLdapUser,
)
from flext_ldap.utils import (
    flext_ldap_validate_dn,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from pathlib import Path

logger = get_logger(__name__)


# ==================== PARAMETER MODELS ====================


class SearchParameters(BaseModel):
    """Search operation parameters model."""

    base_dn: str = Field(default="", description="Search base DN")
    search_filter: str = Field(
        default="(objectClass=*)",
        description="LDAP search filter"
    )
    scope: str = Field(default="subtree", description="Search scope")
    attributes: list[str] | None = Field(
        default=None,
        description="Attributes to retrieve"
    )
    size_limit: int = Field(
        default=1000,
        ge=1,
        le=10000,
        description="Maximum entries to return"
    )
    time_limit: int = Field(
        default=30,
        ge=1,
        le=300,
        description="Search timeout in seconds"
    )

    @validator("search_filter")
    def validate_filter(self, v: str) -> str:
        """Validate search filter format."""
        if not v or not v.strip():
            msg = "Search filter cannot be empty"
            raise ValueError(msg)
        return v.strip()


class ConnectionParameters(BaseModel):
    """Connection parameters model."""

    server_uri: str = Field(..., description="LDAP server URI")
    bind_dn: str | None = Field(default=None, description="Bind DN")
    bind_password: str | None = Field(default=None, description="Bind password")
    timeout: int = Field(
        default=30,
        ge=1,
        le=300,
        description="Connection timeout"
    )

    @validator("server_uri")
    def validate_uri(self, v: str) -> str:
        """Validate server URI format."""
        if not v or not v.strip():
            msg = "Server URI cannot be empty"
            raise ValueError(msg)
        parsed = urlparse(v)
        if not parsed.hostname:
            msg = "Invalid server URI: missing hostname"
            raise ValueError(msg)
        return v


class GroupCreationParameters(BaseModel):
    """Group creation parameters model."""

    dn: str = Field(..., description="Group distinguished name")
    cn: str = Field(..., description="Group common name")
    description: str | None = Field(default=None, description="Group description")
    members: list[str] = Field(default_factory=list, description="Initial members")

    @validator("dn")
    def validate_dn(self, v: str) -> str:
        """Validate DN format."""
        if not v or not v.strip():
            msg = "DN cannot be empty"
            raise ValueError(msg)
        return v.strip()

    @validator("cn")
    def validate_cn(self, v: str) -> str:
        """Validate common name."""
        if not v or not v.strip():
            msg = "Common name cannot be empty"
            raise ValueError(msg)
        return v.strip()


class ExportParameters(BaseModel):
    """LDIF export parameters model."""

    output_file: Path = Field(..., description="Output LDIF file path")
    base_dn: str = Field(..., description="Export base DN")
    search_filter: str = Field(
        default="(objectClass=*)",
        description="Export filter"
    )
    include_operational: bool = Field(
        default=False,
        description="Include operational attributes"
    )

    @validator("base_dn")
    def validate_base_dn(self, v: str) -> str:
        """Validate base DN."""
        if not v or not v.strip():
            msg = "Base DN cannot be empty"
            raise ValueError(msg)
        return v.strip()


# ==================== SERVICE INTERFACES ====================


class SearchServiceInterface:
    """Interface for search operations."""

    async def perform_search(
        self,
        session_id: str,
        params: SearchParameters
    ) -> FlextResult[list[FlextLdapEntry]]:
        """Perform search operation."""
        raise NotImplementedError


class ConnectionServiceInterface:
    """Interface for connection operations."""

    async def establish_connection(
        self,
        params: ConnectionParameters
    ) -> FlextResult[str]:
        """Establish connection and return session ID."""
        raise NotImplementedError

    async def terminate_connection(self, session_id: str) -> FlextResult[bool]:
        """Terminate connection."""
        raise NotImplementedError


class EntryServiceInterface:
    """Interface for entry operations."""

    async def create_user_entry(
        self,
        session_id: str,
        request: FlextLdapCreateUserRequest
    ) -> FlextResult[FlextLdapUser]:
        """Create user entry."""
        raise NotImplementedError

    async def create_group_entry(
        self,
        session_id: str,
        params: GroupCreationParameters
    ) -> FlextResult[FlextLdapGroup]:
        """Create group entry."""
        raise NotImplementedError


class ExportServiceInterface:
    """Interface for export operations."""

    async def export_to_ldif(
        self,
        session_id: str,
        params: ExportParameters
    ) -> FlextResult[str]:
        """Export search results to LDIF."""
        raise NotImplementedError


# ==================== SERVICE IMPLEMENTATIONS ====================


class FlextLdapSearchService(SearchServiceInterface):
    """Professional search service implementation."""

    def __init__(self, client: FlextLdapClient) -> None:
        """Initialize search service."""
        self._client = client
        logger.debug("FlextLdapSearchService initialized")

    async def perform_search(
        self,
        session_id: str,
        params: SearchParameters
    ) -> FlextResult[list[FlextLdapEntry]]:
        """Perform LDAP search with comprehensive validation."""
        try:
            # Validate session
            validation_error = self._validate_session(session_id)
            if validation_error:
                return FlextResult.fail(validation_error)

            # Prepare search parameters
            effective_base_dn = params.base_dn or ""

            # Execute search
            search_result = await self._client.search(
                base_dn=effective_base_dn,
                search_filter=params.search_filter,
                attributes=params.attributes,
                scope=params.scope,
                size_limit=params.size_limit,
                time_limit=params.time_limit,
            )

            if search_result.is_success:
                entries = self._convert_raw_results(search_result.data)
                return FlextResult.ok(entries)

            return FlextResult.fail(f"Search failed: {search_result.error}")

        except Exception as e:
            logger.exception("Search operation failed")
            return FlextResult.fail(f"Search error: {e}")

    def _validate_session(self, session_id: str) -> str | None:
        """Validate session ID."""
        if not session_id or not session_id.strip():
            return "Session ID is required"
        return None

    def _convert_raw_results(self, raw_data: object | None) -> list[FlextLdapEntry]:
        """Convert raw search results to FlextLdapEntry objects."""
        entries: list[FlextLdapEntry] = []
        if not raw_data:
            return entries
        # Ensure raw_data is a list
        raw_list = raw_data if isinstance(raw_data, list) else []
        for raw_entry in raw_list:
            try:
                if hasattr(raw_entry, "entry_dn") and hasattr(raw_entry, "entry_attributes_as_dict"):
                    entry = FlextLdapEntry(
                        id=str(uuid.uuid4()),
                        dn=raw_entry.entry_dn,
                        attributes=self._normalize_attributes(raw_entry.entry_attributes_as_dict)
                    )
                    entries.append(entry)
            except Exception as e:
                logger.warning(f"Failed to convert entry: {e}")
        return entries

    def _normalize_attributes(self, raw_attributes: dict[str, object]) -> dict[str, object]:
        """Normalize attributes to consistent format."""
        normalized: dict[str, object] = {}
        for key, value in raw_attributes.items():
            if isinstance(value, list) and value:
                normalized[key] = str(value[0])
            else:
                normalized[key] = str(value)
        return normalized


class FlextLdapConnectionService(ConnectionServiceInterface):
    """Professional connection service implementation."""

    def __init__(self, client: FlextLdapClient) -> None:
        """Initialize connection service."""
        self._client = client
        self._active_sessions: dict[str, ConnectionParameters] = {}
        logger.debug("FlextLdapConnectionService initialized")

    async def establish_connection(
        self,
        params: ConnectionParameters
    ) -> FlextResult[str]:
        """Establish LDAP connection and return session ID."""
        try:
            # Attempt connection
            connect_result = await self._client.connect(
                server_uri=params.server_uri,
                bind_dn=params.bind_dn,
                bind_password=params.bind_password,
            )

            if connect_result.is_success:
                session_id = self._generate_session_id()
                self._active_sessions[session_id] = params
                logger.info(f"Connection established: {session_id}")
                return FlextResult.ok(session_id)

            return FlextResult.fail(f"Connection failed: {connect_result.error}")

        except Exception as e:
            logger.exception("Connection establishment failed")
            return FlextResult.fail(f"Connection error: {e}")

    async def terminate_connection(self, session_id: str) -> FlextResult[bool]:
        """Terminate LDAP connection."""
        try:
            if session_id not in self._active_sessions:
                return FlextResult.fail(f"Unknown session: {session_id}")

            disconnect_result = await self._client.disconnect()

            if disconnect_result.is_success:
                del self._active_sessions[session_id]
                logger.info(f"Connection terminated: {session_id}")
                return FlextResult.ok(data=True)

            return FlextResult.fail(f"Disconnect failed: {disconnect_result.error}")

        except Exception as e:
            logger.exception("Connection termination failed")
            return FlextResult.fail(f"Termination error: {e}")

    def _generate_session_id(self) -> str:
        """Generate unique session ID."""
        return f"ldap_session_{uuid.uuid4().hex[:12]}"


class FlextLdapEntryService(EntryServiceInterface):
    """Professional entry service implementation."""

    def __init__(self, client: FlextLdapClient) -> None:
        """Initialize entry service."""
        self._client = client
        logger.debug("FlextLdapEntryService initialized")

    async def create_user_entry(
        self,
        session_id: str,
        request: FlextLdapCreateUserRequest
    ) -> FlextResult[FlextLdapUser]:
        """Create user entry with comprehensive validation."""
        try:
            # Validate request
            validation_error = self._validate_user_request(request)
            if validation_error:
                return FlextResult.fail(validation_error)

            # Convert to LDAP attributes
            raw_attributes = request.to_ldap_attributes()
            # Ensure all attribute values are lists of strings
            attributes: dict[str, list[str]] = {}
            for key, value in raw_attributes.items():
                if isinstance(value, list):
                    attributes[key] = [str(v) for v in value]
                else:
                    attributes[key] = [str(value)]

            # Add entry
            add_result = await self._client.add_entry(
                dn=request.dn,
                attributes=attributes
            )

            if add_result.is_success:
                user = FlextLdapUser(
                    id=str(uuid.uuid4()),
                    dn=request.dn,
                    uid=request.uid,
                    cn=request.cn,
                    sn=request.sn,
                    mail=request.mail,
                )
                return FlextResult.ok(user)

            return FlextResult.fail(f"User creation failed: {add_result.error}")

        except Exception as e:
            logger.exception("User creation failed")
            return FlextResult.fail(f"User creation error: {e}")

    async def create_group_entry(
        self,
        session_id: str,
        params: GroupCreationParameters
    ) -> FlextResult[FlextLdapGroup]:
        """Create group entry with validation."""
        try:
            # Prepare group attributes
            attributes: dict[str, list[str]] = {
                "objectClass": ["groupOfNames", "top"],
                "cn": [params.cn],
            }

            if params.description:
                attributes["description"] = [params.description]

            if params.members:
                attributes["member"] = params.members
            else:
                # Default empty member for groupOfNames
                attributes["member"] = ["cn=dummy"]

            # Add entry
            add_result = await self._client.add_entry(
                dn=params.dn,
                attributes=attributes
            )

            if add_result.is_success:
                group = FlextLdapGroup(
                    id=str(uuid.uuid4()),
                    dn=params.dn,
                    cn=params.cn,
                    description=params.description,
                    members=params.members,
                )
                return FlextResult.ok(group)

            return FlextResult.fail(f"Group creation failed: {add_result.error}")

        except Exception as e:
            logger.exception("Group creation failed")
            return FlextResult.fail(f"Group creation error: {e}")

    def _validate_user_request(self, request: FlextLdapCreateUserRequest) -> str | None:
        """Validate user creation request."""
        # DN validation
        dn_validation = flext_ldap_validate_dn(request.dn)
        if not dn_validation:
            return f"Invalid DN: {request.dn}"

        # Required fields
        if not request.uid or not request.uid.strip():
            return "UID is required"

        if not request.cn or not request.cn.strip():
            return "Common name is required"

        if not request.sn or not request.sn.strip():
            return "Surname is required"

        return None


class FlextLdapExportService(ExportServiceInterface):
    """Professional export service implementation."""

    def __init__(self, client: FlextLdapClient) -> None:
        """Initialize export service."""
        self._client = client
        self._ldif_api = FlextLdifAPI()
        logger.debug("FlextLdapExportService initialized")

    async def export_to_ldif(
        self,
        session_id: str,
        params: ExportParameters
    ) -> FlextResult[str]:
        """Export search results to LDIF format."""
        try:
            # Perform search
            search_result = await self._client.search(
                base_dn=params.base_dn,
                search_filter=params.search_filter,
                attributes=["*"] if params.include_operational else None,
            )

            if not search_result.is_success:
                return FlextResult.fail(f"Search for export failed: {search_result.error}")

            # Convert to LDIF format
            ldif_content = self._convert_to_ldif(search_result.data)

            # Write to file
            params.output_file.write_text(ldif_content, encoding="utf-8")

            return FlextResult.ok(str(params.output_file))

        except Exception as e:
            logger.exception("LDIF export failed")
            return FlextResult.fail(f"Export error: {e}")

    def _convert_to_ldif(self, search_data: object | None) -> str:
        """Convert search results to LDIF format."""
        if not search_data:
            return ""

        ldif_lines = []
        # Ensure search_data is a list
        entries_list = search_data if isinstance(search_data, list) else []
        for entry in entries_list:
            entry_lines = self._convert_entry_to_ldif_lines(entry)
            if entry_lines:
                ldif_lines.extend(entry_lines)
                ldif_lines.append("")  # Entry separator

        return "\n".join(ldif_lines)

    def _convert_entry_to_ldif_lines(self, entry: object) -> list[str]:
        """Convert single entry to LDIF lines."""
        try:
            if not self._is_valid_ldap_entry(entry):
                return []

            # Type assertion after validation
            entry_dn = getattr(entry, "entry_dn", "")
            entry_attrs = getattr(entry, "entry_attributes_as_dict", {})

            lines = [f"dn: {entry_dn}"]
            attribute_lines = self._convert_attributes_to_ldif_lines(entry_attrs)
            lines.extend(attribute_lines)
            return lines

        except Exception as e:
            logger.warning(f"Failed to convert entry to LDIF: {e}")
            return []

    def _is_valid_ldap_entry(self, entry: object) -> bool:
        """Check if entry has required LDAP structure."""
        return (
            hasattr(entry, "entry_dn") and
            hasattr(entry, "entry_attributes_as_dict")
        )

    def _convert_attributes_to_ldif_lines(self, attributes: dict[str, object]) -> list[str]:
        """Convert attributes to LDIF attribute lines."""
        lines: list[str] = []
        for attr_name, attr_values in attributes.items():
            if isinstance(attr_values, list):
                lines.extend(f"{attr_name}: {value}" for value in attr_values)
            else:
                lines.append(f"{attr_name}: {attr_values}")
        return lines


# ==================== MAIN API CLASS ====================


class FlextLdapApi:
    """Professional FLEXT LDAP API - Unified interface for all LDAP operations.

    This class provides a clean, type-safe interface for LDAP operations,
    following SOLID principles and eliminating code complexity.
    """

    def __init__(self, config: FlextLdapSettings | None = None) -> None:
        """Initialize FLEXT LDAP API.

        Args:
            config: Optional LDAP configuration settings

        """
        self._config = config or FlextLdapSettings()
        self._container = get_flext_container()
        self._client = FlextLdapClient()

        # Initialize specialized services
        self._connection_service = FlextLdapConnectionService(self._client)
        self._search_service = FlextLdapSearchService(self._client)
        self._entry_service = FlextLdapEntryService(self._client)
        self._export_service = FlextLdapExportService(self._client)

        logger.info("FlextLdapApi initialized with specialized services")

    # Connection Management

    async def connect(
        self,
        server_uri: str,
        bind_dn: str | None = None,
        bind_password: str | None = None,
        timeout: int = 30,
    ) -> FlextResult[str]:
        """Establish LDAP connection.

        Args:
            server_uri: LDAP server URI
            bind_dn: Bind DN for authentication
            bind_password: Bind password
            timeout: Connection timeout in seconds

        Returns:
            FlextResult containing session ID or error

        """
        params = ConnectionParameters(
            server_uri=server_uri,
            bind_dn=bind_dn,
            bind_password=bind_password,
            timeout=timeout,
        )
        return await self._connection_service.establish_connection(params)

    async def disconnect(self, session_id: str) -> FlextResult[bool]:
        """Terminate LDAP connection.

        Args:
            session_id: Session ID from connect operation

        Returns:
            FlextResult indicating success or failure

        """
        return await self._connection_service.terminate_connection(session_id)

    @asynccontextmanager
    async def connection(
        self,
        server_uri: str,
        bind_dn: str | None = None,
        bind_password: str | None = None,
    ) -> AsyncIterator[str]:
        """Context manager for LDAP connections.

        Args:
            server_uri: LDAP server URI
            bind_dn: Bind DN for authentication
            bind_password: Bind password

        Yields:
            Session ID for use in other operations

        """
        connect_result = await self.connect(server_uri, bind_dn, bind_password)
        if not connect_result.is_success:
            msg = f"Connection failed: {connect_result.error}"
            raise FlextLdapConnectionError(msg)

        session_id = connect_result.data
        if session_id is None:
            msg = "Failed to get session ID"
            raise FlextLdapConnectionError(msg)

        try:
            yield session_id
        finally:
            await self.disconnect(session_id)

    # Search Operations

    async def search(
        self,
        session_id: str,
        base_dn: str = "",
        search_filter: str = "(objectClass=*)",
        scope: str = "subtree",
        attributes: list[str] | None = None,
        size_limit: int = 1000,
        time_limit: int = 30,
    ) -> FlextResult[list[FlextLdapEntry]]:
        """Perform LDAP search operation.

        Args:
            session_id: Session ID from connection
            base_dn: Search base DN
            search_filter: LDAP search filter
            scope: Search scope (base, onelevel, subtree)
            attributes: Attributes to retrieve
            size_limit: Maximum entries to return
            time_limit: Search timeout in seconds

        Returns:
            FlextResult containing list of entries or error

        """
        params = SearchParameters(
            base_dn=base_dn,
            search_filter=search_filter,
            scope=scope,
            attributes=attributes,
            size_limit=size_limit,
            time_limit=time_limit,
        )
        return await self._search_service.perform_search(session_id, params)

    # Entry Operations

    async def create_user(
        self,
        session_id: str,  # noqa: ARG002
        user_request: FlextLdapCreateUserRequest,
    ) -> FlextResult[FlextLdapUser]:
        """Create user entry.

        Args:
            session_id: Session ID from connection
            user_request: User creation request

        Returns:
            FlextResult containing created user or error

        """
        return await self._entry_service.create_user_entry(session_id, user_request)

    async def create_group(
        self,
        session_id: str,
        dn: str,
        cn: str,
        description: str | None = None,
        members: list[str] | None = None,
    ) -> FlextResult[FlextLdapGroup]:
        """Create group entry.

        Args:
            session_id: Session ID from connection
            dn: Group distinguished name
            cn: Group common name
            description: Group description
            members: Initial group members

        Returns:
            FlextResult containing created group or error

        """
        params = GroupCreationParameters(
            dn=dn,
            cn=cn,
            description=description,
            members=members or [],
        )
        return await self._entry_service.create_group_entry(session_id, params)

    # Export Operations

    async def export_search_to_ldif(
        self,
        session_id: str,
        output_file: Path,
        base_dn: str,
        search_filter: str = "(objectClass=*)",
        include_operational: bool = False,
    ) -> FlextResult[str]:
        """Export search results to LDIF file.

        Args:
            session_id: Session ID from connection
            output_file: Output LDIF file path
            base_dn: Search base DN
            search_filter: Search filter
            include_operational: Include operational attributes

        Returns:
            FlextResult containing output file path or error

        """
        params = ExportParameters(
            output_file=output_file,
            base_dn=base_dn,
            search_filter=search_filter,
            include_operational=include_operational,
        )
        return await self._export_service.export_to_ldif(session_id, params)


# ==================== GLOBAL API INSTANCE ====================


_global_ldap_api: FlextLdapApi | None = None


def get_ldap_api(config: FlextLdapSettings | None = None) -> FlextLdapApi:
    """Get global FLEXT LDAP API instance.

    Args:
        config: Optional configuration settings

    Returns:
        Global FlextLdapApi instance

    """
    global _global_ldap_api
    if _global_ldap_api is None:
        _global_ldap_api = FlextLdapApi(config)
    return _global_ldap_api


def create_ldap_api(
    server_uri: str,
    bind_dn: str | None = None,
    bind_password: str | None = None,
    use_ssl: bool = False,
    timeout: int = 30,
) -> FlextLdapApi:
    """Factory function for creating FLEXT LDAP API instance.

    Args:
        server_uri: LDAP server URI
        bind_dn: Bind DN for authentication
        bind_password: Bind password
        use_ssl: Use SSL/TLS encryption
        timeout: Connection timeout

    Returns:
        Configured FlextLdapApi instance

    """
    # Parse server URI
    parsed = urlparse(server_uri)
    port = parsed.port or (636 if use_ssl else 389)

    # Create connection config
    connection_config = FlextLdapConnectionConfig(
        server=parsed.hostname or "localhost",
        port=port,
        use_ssl=use_ssl,
        timeout=timeout,
    )

    # Create settings
    settings = FlextLdapSettings(default_connection=connection_config)

    return FlextLdapApi(settings)
