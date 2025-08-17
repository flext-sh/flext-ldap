"""FLEXT-LDAP API."""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlparse
from uuid import uuid4 as _uuid4

from flext_core import (
    FlextResult,
    get_flext_container,
    get_logger,
)
from flext_ldif.api import FlextLdifAPI
from pydantic import BaseModel, Field, ValidationError, field_validator

from flext_ldap.config import FlextLdapConnectionConfig, FlextLdapSettings
from flext_ldap.constants import FlextLdapDefaultValues
from flext_ldap.exceptions import FlextLdapConnectionError
from flext_ldap.infrastructure import FlextLdapClient
from flext_ldap.models import (
    FlextLdapCreateUserRequest,
    FlextLdapEntry,
    FlextLdapGroup,
    FlextLdapUser,
)
from flext_ldap.utils import (
    FlextLdapValidationHelpers,
    flext_ldap_validate_dn,
)

logger = get_logger(__name__)

_LDIF_AVAILABLE = True

# ==================== PARAMETER MODELS ====================


class FlextLdapSearchParams(BaseModel):
    """Parameters for LDAP search operations to reduce parameter count."""

    session_id: str | None = Field(
        default=None,
        description="Session ID from connection",
    )
    base_dn: str = Field(default="", description="Search base DN")
    search_filter: str = Field(
        default=FlextLdapDefaultValues.DEFAULT_SEARCH_FILTER,
        description="LDAP search filter",
    )
    attributes: list[str] | None = Field(
        default=None,
        description="Attributes to retrieve",
    )
    scope: str = Field(
        default=FlextLdapDefaultValues.DEFAULT_SEARCH_SCOPE,
        description="Search scope",
    )
    size_limit: int = Field(
        default=FlextLdapDefaultValues.DEFAULT_SIZE_LIMIT,
        description="Maximum entries to return",
    )
    time_limit: int = Field(
        default=FlextLdapDefaultValues.DEFAULT_TIMEOUT_SECONDS,
        description="Search timeout in seconds",
    )

    @field_validator("search_filter")
    @classmethod
    def validate_filter(cls, v: str) -> str:
        return FlextLdapValidationHelpers.validate_filter_field(v)


class FlextLdapExportParams(BaseModel):
    """Parameters for exporting search results to an LDIF file."""

    session_id: str = Field(..., description="Session ID from connection")
    output_file: str = Field(..., description="Output LDIF file path")
    base_dn: str = Field(..., description="Search base DN")
    search_filter: str = Field(
        default="(objectClass=*)",
        description="LDAP search filter",
    )
    include_operational: bool = Field(
        default=False,
        description="Include operational attributes",
    )
    encoding: str = Field(default="utf-8", description="Output file encoding")

    @field_validator("output_file")
    @classmethod
    def validate_output_file(cls, v: str) -> str:
        return FlextLdapValidationHelpers.validate_file_path_field(v)


class SearchParameters(BaseModel):
    """Parameters for a simple LDAP search operation."""

    base_dn: str = Field(default="", description="Search base DN")
    search_filter: str = Field(
        default="(objectClass=*)",
        description="LDAP search filter",
    )
    scope: str = Field(default="subtree", description="Search scope")
    attributes: list[str] | None = Field(
        default=None,
        description="Attributes to retrieve",
    )
    size_limit: int = Field(
        default=1000,
        ge=1,
        le=10000,
        description="Maximum entries to return",
    )
    time_limit: int = Field(
        default=30,
        ge=1,
        le=300,
        description="Search timeout in seconds",
    )

    @field_validator("search_filter")
    @classmethod
    def validate_filter(cls, v: str) -> str:
        return FlextLdapValidationHelpers.validate_filter_field(v)


class ConnectionParameters(BaseModel):
    """Parameters required to establish an LDAP connection."""

    server_uri: str = Field(..., description="LDAP server URI")
    bind_dn: str | None = Field(default=None, description="Bind DN")
    bind_password: str | None = Field(default=None, description="Bind password")
    timeout: int = Field(
        default=30,
        ge=1,
        le=300,
        description="Connection timeout",
    )

    @field_validator("server_uri")
    @classmethod
    def validate_uri(cls, v: str) -> str:
        return FlextLdapValidationHelpers.validate_uri_field(v)


class GroupCreationParameters(BaseModel):
    """Parameters required to create an LDAP group entry."""

    dn: str = Field(..., description="Group distinguished name")
    cn: str = Field(..., description="Group common name")
    description: str | None = Field(default=None, description="Group description")
    members: list[str] = Field(default_factory=list, description="Initial members")

    @field_validator("dn")
    @classmethod
    def validate_dn(cls, v: str) -> str:
        return FlextLdapValidationHelpers.validate_dn_field(v)

    @field_validator("cn")
    @classmethod
    def validate_cn(cls, v: str) -> str:
        return FlextLdapValidationHelpers.validate_cn_field(v)


class ExportParameters(BaseModel):
    """Export configuration used by the export service layer."""

    output_file: Path = Field(..., description="Output LDIF file path")
    base_dn: str = Field(..., description="Export base DN")
    search_filter: str = Field(
        default="(objectClass=*)",
        description="Export filter",
    )
    include_operational: bool = Field(
        default=False,
        description="Include operational attributes",
    )

    @field_validator("base_dn")
    @classmethod
    def validate_base_dn(cls, v: str) -> str:
        return FlextLdapValidationHelpers.validate_base_dn_field(v)


# ==================== SERVICE INTERFACES ====================


class SearchServiceInterface:
    """Interface for search-related operations."""

    async def perform_search(
        self,
        session_id: str,
        params: SearchParameters,
    ) -> FlextResult[list[FlextLdapEntry]]:
        raise NotImplementedError


class ConnectionServiceInterface:
    """Interface for connection lifecycle operations."""

    async def establish_connection(
        self,
        params: ConnectionParameters,
    ) -> FlextResult[str]:
        raise NotImplementedError

    async def terminate_connection(self, session_id: str) -> FlextResult[bool]:
        raise NotImplementedError


class EntryServiceInterface:
    """Interface for LDAP entry management operations."""

    async def create_user_entry(
        self,
        request: FlextLdapCreateUserRequest,
    ) -> FlextResult[FlextLdapUser]:
        raise NotImplementedError

    async def create_group_entry(
        self,
        params: GroupCreationParameters,
    ) -> FlextResult[FlextLdapGroup]:
        raise NotImplementedError


class ExportServiceInterface:
    """Interface for exporting search results to LDIF."""

    async def export_to_ldif(
        self,
        params: ExportParameters,
    ) -> FlextResult[str]:
        raise NotImplementedError


# ==================== SERVICE IMPLEMENTATIONS ====================


class FlextLdapSearchService(SearchServiceInterface):
    """Concrete implementation of LDAP search functionality."""

    def __init__(self, client: FlextLdapClient) -> None:
        self._client = client
        logger.debug("FlextLdapSearchService initialized")

    async def perform_search(
        self,
        session_id: str,
        params: SearchParameters,
    ) -> FlextResult[list[FlextLdapEntry]]:
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
        if not session_id or not session_id.strip():
            return "Session ID is required"
        return None

    def _convert_raw_results(self, raw_data: object | None) -> list[FlextLdapEntry]:
        entries: list[FlextLdapEntry] = []
        if not raw_data:
            return entries
        # Ensure raw_data is a list
        raw_list = raw_data if isinstance(raw_data, list) else []
        for raw_entry in raw_list:
            try:
                if hasattr(raw_entry, "entry_dn") and hasattr(
                    raw_entry,
                    "entry_attributes_as_dict",
                ):
                    entry = FlextLdapEntry(
                        id=str(_uuid4()),
                        dn=raw_entry.entry_dn,
                        attributes=self._normalize_attributes(
                            raw_entry.entry_attributes_as_dict,
                        ),
                    )
                    entries.append(entry)
            except Exception as e:
                logger.warning(f"Failed to convert entry: {e}")
        return entries

    def _normalize_attributes(
        self,
        raw_attributes: dict[str, object],
    ) -> dict[str, object]:
        normalized: dict[str, object] = {}
        for key, value in raw_attributes.items():
            if isinstance(value, list) and value:
                normalized[key] = str(value[0])
            else:
                normalized[key] = str(value)
        return normalized


class FlextLdapConnectionService(ConnectionServiceInterface):
    """Manage LDAP connections and in-memory session tracking."""

    def __init__(self, client: FlextLdapClient) -> None:
        self._client = client
        self._active_sessions: dict[str, ConnectionParameters] = {}
        logger.debug("FlextLdapConnectionService initialized")

    async def establish_connection(
        self,
        params: ConnectionParameters,
    ) -> FlextResult[str]:
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
        return f"ldap_session_{str(_uuid4()).replace('-', '')[:12]}"


class FlextLdapEntryService(EntryServiceInterface):
    """Create and manage LDAP user/group entries via the client."""

    def __init__(self, client: FlextLdapClient) -> None:
        self._client = client
        logger.debug("FlextLdapEntryService initialized")

    async def create_user_entry(
        self,
        request: FlextLdapCreateUserRequest,
    ) -> FlextResult[FlextLdapUser]:
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
                attributes=attributes,
            )

            if add_result.is_success:
                user = FlextLdapUser(
                    id=str(_uuid4()),
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
        params: GroupCreationParameters,
    ) -> FlextResult[FlextLdapGroup]:
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
                attributes=attributes,
            )

            if add_result.is_success:
                group = FlextLdapGroup(
                    id=str(_uuid4()),
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
    """Export search results to an LDIF file using flext-ldif when available."""

    def __init__(self, client: FlextLdapClient) -> None:
        self._client = client
        self._ldif_api = FlextLdifAPI() if FlextLdifAPI is not None else None
        logger.debug("FlextLdapExportService initialized")

    async def export_to_ldif(
        self,
        params: ExportParameters,
    ) -> FlextResult[str]:
        try:
            # Perform search
            search_result = await self._client.search(
                base_dn=params.base_dn,
                search_filter=params.search_filter,
                attributes=["*"] if params.include_operational else None,
            )

            if not search_result.is_success:
                return FlextResult.fail(
                    f"Search for export failed: {search_result.error}",
                )

            # Convert to LDIF format
            ldif_content = self._convert_to_ldif(search_result.data)

            # Write to file
            params.output_file.write_text(ldif_content, encoding="utf-8")

            return FlextResult.ok(str(params.output_file))

        except Exception as e:
            logger.exception("LDIF export failed")
            return FlextResult.fail(f"Export error: {e}")

    def _convert_to_ldif(self, search_data: object | None) -> str:
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
        return hasattr(entry, "entry_dn") and hasattr(entry, "entry_attributes_as_dict")

    def _convert_attributes_to_ldif_lines(
        self,
        attributes: dict[str, object],
    ) -> list[str]:
        lines: list[str] = []
        for attr_name, attr_values in attributes.items():
            if isinstance(attr_values, list):
                lines.extend(f"{attr_name}: {value}" for value in attr_values)
            else:
                lines.append(f"{attr_name}: {attr_values}")
        return lines


# ==================== MAIN API CLASS ====================


class FlextLdapApi:
    """High-level LDAP API facade that composes low-level services."""

    def __init__(self, config: FlextLdapSettings | None = None) -> None:
        self._config = config or FlextLdapSettings()
        self._container = get_flext_container()
        self._client = FlextLdapClient()

        # Initialize specialized services
        self._connection_service = FlextLdapConnectionService(self._client)
        self._search_service = FlextLdapSearchService(self._client)
        self._entry_service = FlextLdapEntryService(self._client)
        self._export_service = FlextLdapExportService(self._client)

        logger.info("FlextLdapApi initialized with specialized services")

    def _generate_id(self, fallback: str = "") -> str:
        id_generator = self._container.get("FlextIdGenerator").unwrap_or(None)
        if id_generator and hasattr(id_generator, "generate"):
            return str(id_generator.generate())
        return fallback or str(uuid.uuid4())

    # Connection Management

    async def connect(
        self,
        server_uri: str,
        bind_dn: str | None = None,
        bind_password: str | None = None,
        *,
        connection_timeout: int = 30,
    ) -> FlextResult[str]:
        try:
            params = ConnectionParameters(
                server_uri=server_uri,
                bind_dn=bind_dn,
                bind_password=bind_password,
                timeout=connection_timeout,
            )
        except ValidationError as e:  # Gracefully propagate validation failures
            detail = e.errors()[0]["msg"] if e.errors() else str(e)
            return FlextResult.fail(
                f"Connection failed: invalid connection parameters - {detail}",
            )

        return await self._connection_service.establish_connection(params)

    async def disconnect(self, session_id: str) -> FlextResult[bool]:
        return await self._connection_service.terminate_connection(session_id)

    @asynccontextmanager
    async def connection(
        self,
        server_uri: str,
        bind_dn: str | None = None,
        bind_password: str | None = None,
    ) -> AsyncIterator[str]:
        connect_result = await self.connect(server_uri, bind_dn, bind_password)
        if not connect_result.is_success:
            msg = f"Connection failed: {connect_result.error}"
            raise FlextLdapConnectionError(msg)

        session_id = connect_result.data or ""
        if not session_id:
            msg = "Failed to get session ID"
            raise FlextLdapConnectionError(msg)

        try:
            yield session_id
        finally:
            await self.disconnect(session_id)

    # Search Operations

    async def search(
        self,
        params: SearchParameters | None = None,
        *,
        # Testing convenience parameters
        session_id: str | None = None,
        base_dn: str = "",
        search_filter: str = "(objectClass=*)",
        attributes: list[str] | None = None,
        **options: object,
    ) -> FlextResult[list[FlextLdapEntry]]:
        # Use provided params or build from individual parameters
        if params is None:
            # Extract options with defaults
            scope = str(options.get("scope", "subtree"))
            size_limit_raw = options.get("size_limit", 1000)
            time_limit_raw = options.get("time_limit", 30)
            size_limit = (
                int(size_limit_raw) if isinstance(size_limit_raw, (int, str)) else 1000
            )
            time_limit = (
                int(time_limit_raw) if isinstance(time_limit_raw, (int, str)) else 30
            )

            params = SearchParameters(
                base_dn=base_dn,
                search_filter=search_filter,
                scope=scope,
                attributes=attributes,
                size_limit=size_limit,
                time_limit=time_limit,
            )

        # Support transitional session parameter
        transitional_session = options.get("session")
        effective_session = session_id or transitional_session or ""
        return await self._search_service.perform_search(str(effective_session), params)

    # Entry Operations

    async def create_user(
        self,
        user_request: FlextLdapCreateUserRequest,
    ) -> FlextResult[FlextLdapUser]:
        return await self._entry_service.create_user_entry(user_request)

    async def create_group(
        self,
        session_id: str,
        dn: str,
        cn: str,
        description: str | None = None,
        members: list[str] | None = None,
    ) -> FlextResult[FlextLdapGroup]:
        # Validate session ID
        if not session_id or not session_id.strip():
            return FlextResult.fail("Session ID is required for group creation")

        params = GroupCreationParameters(
            dn=dn,
            cn=cn,
            description=description,
            members=members or [],
        )
        return await self._entry_service.create_group_entry(params)

    async def create_entry(
        self,
        dn: str,
        attributes: dict[str, list[str]],
    ) -> FlextResult[FlextLdapEntry]:
        # Validate DN
        dn_validation = flext_ldap_validate_dn(dn)
        if not dn_validation:
            return FlextResult.fail(f"Invalid DN: {dn}")

        # Validate attributes
        if not attributes:
            return FlextResult.fail("Attributes cannot be empty")

        # Ensure all attribute values are lists of strings
        validated_attributes: dict[str, list[str]] = {}
        for attr_name, attr_values in attributes.items():
            validated_attributes[attr_name] = [str(value) for value in attr_values]

        try:
            # Create entry using the client's add operation
            add_result = await self._client.add_entry(dn, validated_attributes)

            if add_result.is_failure:
                return FlextResult.fail(f"Failed to add entry: {add_result.error}")

            # Create FlextLdapEntry from the added entry (convert to expected type)
            entry_attributes: dict[str, object] = dict(validated_attributes)
            created_entry = FlextLdapEntry(
                id=str(_uuid4()),
                dn=dn,
                attributes=entry_attributes,
            )

            logger.info(f"Successfully created entry: {dn}")
            return FlextResult.ok(created_entry)

        except Exception as e:
            logger.exception(f"Error creating entry {dn}")
            return FlextResult.fail(f"Entry creation error: {e}")

    async def delete_entry(self, dn: str) -> FlextResult[None]:
        """Delete an LDAP entry by DN using the underlying client.

        Exposto para uso por examples e testes de alto nível.
        """
        try:
            return await self._client.delete_entry(dn)
        except Exception as e:
            logger.exception("Entry deletion failed")
            return FlextResult.fail(f"Delete entry error: {e}")

    # Export Operations

    async def export_search_to_ldif(
        self,
        params: FlextLdapExportParams | None = None,
        *,
        # Testing convenience parameters
        session_id: str | None = None,
        output_file: str | Path | None = None,
        base_dn: str | None = None,
        search_filter: str = "(objectClass=*)",
        include_operational: bool = False,
    ) -> FlextResult[str]:
        # Use provided params or build from individual parameters
        if params is None:
            if not session_id or not session_id.strip():
                return FlextResult.fail("Session ID is required for export operations")
            if not output_file:
                return FlextResult.fail("Output file is required for export operations")
            if not base_dn:
                return FlextResult.fail("Base DN is required for export operations")

            params = FlextLdapExportParams(
                session_id=session_id,
                output_file=str(output_file),
                base_dn=base_dn,
                search_filter=search_filter,
                include_operational=include_operational,
            )

        # Create ExportParameters from FlextLdapExportParams
        export_params = ExportParameters(
            output_file=Path(params.output_file),
            base_dn=params.base_dn,
            search_filter=params.search_filter,
            include_operational=params.include_operational,
        )
        return await self._export_service.export_to_ldif(export_params)

    async def import_ldif_file(
        self,
        session_id: str,
        ldif_file_path: str,
    ) -> FlextResult[int]:
        try:
            ldif_path = Path(ldif_file_path)

            if not session_id or not session_id.strip():
                return FlextResult.fail("Session ID is required for LDIF import")

            if not ldif_path.exists():
                return FlextResult.fail(f"LDIF file not found: {ldif_file_path}")

            # Read LDIF file and apply each entry
            if not _LDIF_AVAILABLE:
                return FlextResult.fail(
                    "LDIF support is unavailable (flext-ldif not installed)",
                )

            # FlextLdifAPI is guaranteed to be available here due to _LDIF_AVAILABLE check
            ldif_api = FlextLdifAPI()

            # Parse LDIF file
            content = await asyncio.to_thread(ldif_path.read_text, encoding="utf-8")

            parse_result = ldif_api.parse(content)
            if not parse_result.success:
                return FlextResult.fail(
                    f"Failed to parse LDIF file: {parse_result.error}",
                )

            entries = parse_result.data or []
            processed_count = 0

            # Process each entry using client modify operations
            for entry in entries:
                try:
                    # Extract DN string value
                    dn_str = str(entry.dn.value)
                    if not dn_str:
                        continue

                    # Access the attributes dictionary directly
                    modifications = entry.attributes.attributes.copy()

                    # Use client to perform modification
                    if modifications:
                        modify_result = await self._client.modify_entry(
                            dn_str,
                            modifications,
                        )
                        if modify_result.is_success:
                            processed_count += 1

                except Exception as e:
                    logger.warning("Failed to process LDIF entry: %s", e)
                    continue

            return FlextResult.ok(processed_count)

        except Exception as e:
            logger.exception("LDIF import failed")
            return FlextResult.fail(f"LDIF import error: {e}")

    async def modify_entry(
        self,
        session_id: str,
        dn: str,
        modifications: dict[str, list[str] | str],
    ) -> FlextResult[bool]:
        try:
            if not session_id or not session_id.strip():
                return FlextResult.fail("Session ID is required for modify operations")
            if not dn:
                return FlextResult.fail("DN is required for modify operations")

            if not modifications:
                return FlextResult.fail("Modifications are required")

            # Convert modifications to client format (dict[str, list[str]])
            client_modifications: dict[str, list[str]] = {}

            for attr, values in modifications.items():
                if isinstance(values, list):
                    client_modifications[attr] = [str(v) for v in values]
                else:
                    # Handle single values or other types
                    client_modifications[attr] = [str(values)]

            # Use client to perform modification
            result = await self._client.modify_entry(dn, client_modifications)
            # Convert FlextResult[None] to FlextResult[bool]
            if result.is_success:
                return FlextResult.ok(data=True)
            return FlextResult.fail(result.error or "Modify operation failed")

        except Exception as e:
            logger.exception("Entry modification failed")
            return FlextResult.fail(f"Modify entry error: {e}")


# ==================== GLOBAL API INSTANCE ====================


_global_ldap_api: FlextLdapApi | None = None


def get_ldap_api(config: FlextLdapSettings | None = None) -> FlextLdapApi:
    """Return a process-wide singleton instance of FlextLdapApi.

    This convenience function mirrors existing public API patterns used by
    tests and examples across the repository.
    """
    global _global_ldap_api  # noqa: PLW0603
    if _global_ldap_api is None:
        _global_ldap_api = FlextLdapApi(config)
    return _global_ldap_api


def create_ldap_api(
    server_uri: str,
    *,
    use_ssl: bool = False,
    timeout: int = 30,
) -> FlextLdapApi:
    """Create a configured FlextLdapApi instance for the given server URI."""
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
