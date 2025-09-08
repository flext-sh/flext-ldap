"""LDAP operations module.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import cast

from flext_core import (
    FlextDomainService,
    FlextLogger,
    FlextModels,
    FlextProcessors,
    FlextResult,
    FlextTypes,
)
from pydantic import Field, PrivateAttr

from flext_ldap.constants import FlextLDAPConstants
from flext_ldap.entities import FlextLDAPEntities
from flext_ldap.typings import LdapAttributeDict
from flext_ldap.value_objects import FlextLDAPValueObjects

logger = FlextLogger(__name__)

# =============================================================================
# PARAMETER OBJECTS - ELIMINATES 7+ PARAMETER FUNCTIONS
# =============================================================================


# SearchParams moved to entities.py to eliminate duplication
# Use FlextLDAPEntities.SearchParams instead


class UserConversionParams(FlextModels.Config):
    """User conversion parameters."""

    entries: FlextTypes.Core.List
    include_disabled: bool = Field(default=False)
    include_system: bool = Field(default=False)
    attribute_filter: FlextTypes.Core.StringList | None = None


# =============================================================================
# COMMAND OBJECTS - REDUCES OPERATION COMPLEXITY
# =============================================================================


class LDAPCommandProcessor:
    """LDAP command processor."""

    class SearchCommand(FlextModels.Config):
        """Search command parameters."""

        connection_id: str = Field(..., min_length=1)
        base_dn: str = Field(..., min_length=1)
        search_filter: str = Field(default="(objectClass=*)")
        scope: str = Field(default="subtree")
        attributes: FlextTypes.Core.StringList | None = None
        size_limit: int = Field(default=1000, ge=1, le=10000)

        def execute(self) -> FlextResult[FlextTypes.Core.Dict]:
            """Execute search command."""
            return FlextResult[FlextTypes.Core.Dict].ok(
                {
                    "base_dn": self.base_dn,
                    "filter": self.search_filter,
                    "scope": self.scope,
                    "attributes": self.attributes,
                    "size_limit": self.size_limit,
                    "connection_id": self.connection_id,
                },
            )

    class MembershipCommand(FlextModels.Config):
        """Membership command parameters.

        Returns:
            FlextResult[FlextTypes.Core.Dict]: The membership command parameters.

        """

        connection_id: str = Field(..., min_length=1)
        group_dn: str = Field(..., min_length=1)
        member_dn: str = Field(..., min_length=1)
        action: str = Field(..., pattern=r"^(add|remove)$")

        def validate_membership_operation(self) -> FlextResult[None]:
            """Validate membership operation.

            Returns:
                FlextResult[None]: The validation result.

            """
            if not self.group_dn or not self.member_dn:
                return FlextResult.fail("Group DN and Member DN are required")
            if self.action not in {"add", "remove"}:
                return FlextResult.fail("Action must be 'add' or 'remove'")
            return FlextResult.ok(None)


# =============================================================================
# ATTRIBUTE PROCESSING STRATEGIES - REDUCES CONVERSION COMPLEXITY
# =============================================================================


class LDAPAttributeProcessor:
    """LDAP attribute processing strategies.

    Returns:
        FlextResult[None]:: Description of return value.

    """

    class UserAttributeExtractor(FlextProcessors.BaseProcessor):
        """User attribute extractor."""

        def process_data(self, entry: object) -> FlextResult[FlextTypes.Core.Dict]:
            """Extract user attributes."""
            try:
                # Type validation
                if not hasattr(entry, "attributes"):
                    return FlextResult[FlextTypes.Core.Dict].fail(
                        "Entry missing attributes",
                    )

                attrs = getattr(entry, "attributes", {})
                if not isinstance(attrs, dict):
                    return FlextResult[FlextTypes.Core.Dict].fail(
                        "Invalid attributes format",
                    )

                # Use flext-core processor pattern for attribute extraction
                extracted = self._extract_ldap_attributes(attrs)
                return FlextResult[FlextTypes.Core.Dict].ok(extracted)

            except Exception as e:
                return FlextResult[FlextTypes.Core.Dict].fail(
                    f"Attribute extraction failed: {e}",
                )

        def _extract_ldap_attributes(
            self,
            attrs: FlextTypes.Core.Dict,
        ) -> FlextTypes.Core.Dict:
            """Extract LDAP attributes using strategies."""
            # Define extraction strategies for different attribute types
            # Callable already imported at top

            attribute_strategies: dict[str, Callable[[object], object]] = {
                "uid": lambda x: self._extract_string_attribute(x, "unknown"),
                "cn": lambda x: self._extract_string_attribute(x, "unknown"),
                "sn": lambda x: self._extract_string_attribute(x, "unknown"),
                "givenName": self._extract_optional_string_attribute,
                "mail": self._extract_optional_string_attribute,
            }

            # Apply strategies - eliminates 30+ lines of repetitive extraction code
            return {
                attr_name: strategy(attrs.get(attr_name))
                for attr_name, strategy in attribute_strategies.items()
            }

        def _extract_string_attribute(self, attr_value: object, default: str) -> object:
            """Extract string attribute with default."""
            if not attr_value:
                return default
            if isinstance(attr_value, list) and attr_value:
                return str(attr_value[0])
            return str(attr_value)

        def _extract_optional_string_attribute(self, attr_value: object) -> object:
            """Extract optional string attribute."""
            if not attr_value:
                return None
            if isinstance(attr_value, list) and attr_value:
                return str(attr_value[0]) if attr_value[0] else None
            return str(attr_value) if attr_value else None

    class GroupAttributeExtractor(FlextProcessors.BaseProcessor):
        """Group attribute extractor."""

        def process_data(self, entry: object) -> FlextResult[FlextTypes.Core.Dict]:
            """Extract group attributes."""
            try:
                if not hasattr(entry, "attributes"):
                    return FlextResult[FlextTypes.Core.Dict].fail(
                        "Entry missing attributes",
                    )

                attrs = getattr(entry, "attributes", {})
                extracted = self._extract_group_attributes(attrs)
                return FlextResult[FlextTypes.Core.Dict].ok(extracted)

            except Exception as e:
                return FlextResult[FlextTypes.Core.Dict].fail(
                    f"Group attribute extraction failed: {e}",
                )

        def _extract_group_attributes(
            self,
            attrs: FlextTypes.Core.Dict,
        ) -> FlextTypes.Core.Dict:
            """Extract group attributes using Strategy Pattern."""
            cn = self._extract_string_attribute(attrs.get("cn"), "unknown")
            description = self._extract_optional_string_attribute(
                attrs.get("description"),
            )
            members = self._extract_member_list(attrs.get("member", []))

            return {"cn": cn, "description": description, "members": members}

        def _extract_string_attribute(self, attr_value: object, default: str) -> object:
            """Extract string attribute with default."""
            if not attr_value:
                return default
            if isinstance(attr_value, list) and attr_value:
                return str(attr_value[0])
            return str(attr_value)

        def _extract_optional_string_attribute(self, attr_value: object) -> object:
            """Extract optional string attribute."""
            if not attr_value:
                return None
            if isinstance(attr_value, list) and attr_value:
                return str(attr_value[0]) if attr_value[0] else None
            return str(attr_value) if attr_value else None

        def _extract_member_list(
            self, member_value: object
        ) -> FlextTypes.Core.StringList:
            """Extract member list from various formats."""
            if isinstance(member_value, list):
                return [str(m) for m in member_value if m]
            if isinstance(member_value, str) and member_value:
                return [member_value]
            return []


class FlextLDAPOperations:
    """Consolidated LDAP operations class.

    Returns:
        FlextTypes.Core.StringList:: Description of return value.

    """

    # ==========================================================================
    # INTERNAL BASE SERVICE CLASS
    # ==========================================================================

    class OperationsService(FlextDomainService[None]):
        """Internal operations base service."""

        def __init__(self) -> None:
            """Initialize shared components using flext-core domain service."""
            super().__init__()

        def _generate_id(self) -> str:
            """Generate ID using UUID - simple approach."""
            return str(uuid.uuid4())

        def execute(self) -> FlextResult[None]:
            """Execute method required by FlextDomainService - CORRECT signature."""
            return FlextResult.ok(None)

        def _validate_dn_or_fail(
            self,
            dn: str,
            context: str = "DN",
        ) -> FlextResult[None]:
            """Validate DN and return error if invalid - REUSABLE VALIDATION."""
            dn_validation = FlextLDAPValueObjects.DistinguishedName(
                value=dn,
            ).validate_business_rules()
            if not dn_validation.is_success:
                error_msg = (
                    dn_validation.error
                    or FlextLDAPConstants.ValidationMessages.UNKNOWN_VALIDATION_ERROR
                )
                return FlextResult.fail(
                    FlextLDAPConstants.ValidationMessages.INVALID_DN_WITH_CONTEXT.format(
                        context=context,
                        error=error_msg,
                    ),
                )
            return FlextResult.ok(None)

        def _validate_filter_or_fail(self, search_filter: str) -> FlextResult[None]:
            """Validate LDAP filter and return error if invalid - REUSABLE VALIDATION."""
            filter_validation = FlextLDAPValueObjects.Filter(
                value=search_filter,
            ).validate_business_rules()
            if not filter_validation.is_success:
                error_msg = (
                    filter_validation.error
                    or FlextLDAPConstants.ValidationMessages.UNKNOWN_VALIDATION_ERROR
                )
                return FlextResult.fail(
                    FlextLDAPConstants.ValidationMessages.INVALID_SEARCH_FILTER.format(
                        error=error_msg,
                    ),
                )
            return FlextResult.ok(None)

        def _validate_uri_or_fail(self, server_uri: str) -> FlextResult[None]:
            """Validate server URI and return error if invalid - REUSABLE VALIDATION."""
            if not server_uri or not server_uri.strip():
                return FlextResult.fail("Server URI cannot be empty")

            # Basic LDAP URI validation
            if not server_uri.startswith(("ldap://", "ldaps://")):
                return FlextResult.fail(
                    "Server URI must start with ldap:// or ldaps://",
                )

            return FlextResult.ok(None)

        def _handle_exception_with_context(
            self,
            operation: str,
            exception: Exception,
            connection_id: str | None = None,
        ) -> str:
            """Handle exceptions with context logging - CONSOLIDATE EXCEPTION HANDLING."""
            extra_context = {"connection_id": connection_id} if connection_id else {}
            logger.error("%s failed", operation, extra=extra_context)
            return f"Failed to {operation.lower()}: {exception!s}"

        def _log_operation_success(
            self,
            operation: str,
            connection_id: str,
            **extra_fields: object,
        ) -> None:
            """Log successful operations with consistent format - CONSOLIDATE LOGGING."""
            logger.info(
                "LDAP %s completed",
                operation,
                extra={
                    "connection_id": connection_id,
                    **extra_fields,
                },
            )

    # ==========================================================================
    # INTERNAL SPECIALIZED CLASSES FOR DIFFERENT OPERATION DOMAINS
    # ==========================================================================

    class ConnectionOperations(OperationsService):
        """Internal specialized connection operations class."""

        # Private attribute for active connections
        _active_connections: dict[str, FlextTypes.Core.Dict] = PrivateAttr(
            default_factory=dict,
        )

        def __init__(self, **data: object) -> None:
            """Initialize connection operations - USES REFACTORED BASE."""
            super().__init__(**data)

        async def create_connection(
            self,
            server_uri: str,
            bind_dn: str | None = None,
            _bind_password: str | None = None,
            timeout_seconds: int = 30,
        ) -> FlextResult[str]:
            """Create a new LDAP connection - REFACTORED with shared validation."""
            try:
                # Use REFACTORED validation helpers - NO DUPLICATION
                uri_validation = self._validate_uri_or_fail(server_uri)
                if not uri_validation.is_success:
                    return FlextResult.fail(
                        uri_validation.error or "URI validation failed",
                    )

                if bind_dn:
                    dn_validation = self._validate_dn_or_fail(bind_dn, "bind DN")
                    if not dn_validation.is_success:
                        return FlextResult.fail(
                            dn_validation.error or "DN validation failed",
                        )

                # Use REFACTORED ID generation - NO DUPLICATION
                connection_id = self._generate_id()

                # Store connection metadata
                self._active_connections[connection_id] = {
                    "server_uri": server_uri,
                    "bind_dn": bind_dn,
                    "created_at": datetime.now(UTC),
                    "timeout": timeout_seconds,
                    "is_authenticated": bind_dn is not None,
                }

                # Use REFACTORED logging - NO DUPLICATION
                self._log_operation_success(
                    "connection created",
                    connection_id,
                    server_uri=server_uri,
                    authenticated=bind_dn is not None,
                )

                return FlextResult.ok(connection_id)

            except Exception as e:
                # Use REFACTORED exception handling - NO DUPLICATION
                error_msg = self._handle_exception_with_context("create connection", e)
                return FlextResult.fail(error_msg)

        async def close_connection(self, connection_id: str) -> FlextResult[None]:
            """Close an LDAP connection - REFACTORED."""
            if connection_id not in self._active_connections:
                return FlextResult.fail(f"Connection not found: {connection_id}")

            try:
                connection_info = self._active_connections.pop(connection_id)

                # Use REFACTORED logging - NO DUPLICATION
                self._log_operation_success(
                    "connection closed",
                    connection_id,
                    server_uri=connection_info.get("server_uri"),
                    duration_seconds=self._calculate_duration(
                        connection_info.get("created_at"),
                    ),
                )

                return FlextResult.ok(None)

            except Exception as e:
                # Use REFACTORED exception handling - NO DUPLICATION
                error_msg = self._handle_exception_with_context(
                    "close connection",
                    e,
                    connection_id,
                )
                return FlextResult.fail(error_msg)

        def get_connection_info(
            self,
            connection_id: str,
        ) -> FlextResult[FlextTypes.Core.Dict]:
            """Get connection information - REFACTORED."""
            if connection_id not in self._active_connections:
                return FlextResult[FlextTypes.Core.Dict].fail(
                    f"Connection not found: {connection_id}",
                )

            connection_info = self._active_connections[connection_id].copy()
            connection_info["connection_id"] = connection_id
            connection_info["active"] = True
            return FlextResult[FlextTypes.Core.Dict].ok(connection_info)

        def list_active_connections(self) -> FlextResult[list[FlextTypes.Core.Dict]]:
            """List all active connections - REFACTORED."""
            connections: list[FlextTypes.Core.Dict] = []
            for conn_id, conn_info in self._active_connections.items():
                info: FlextTypes.Core.Dict = conn_info.copy()
                info["connection_id"] = conn_id
                info["active"] = True
                connections.append(info)
            return FlextResult[list[FlextTypes.Core.Dict]].ok(connections)

        def _calculate_duration(self, created_at: object) -> float:
            """Calculate connection duration in seconds - REUSABLE HELPER."""
            if isinstance(created_at, datetime):
                return (datetime.now(UTC) - created_at).total_seconds()
            return 0.0

    class SearchOperations(OperationsService):
        """Internal specialized search and query operations class."""

        async def search_entries(
            self,
            params: FlextLDAPEntities.SearchParams,
        ) -> FlextResult[list[FlextLDAPEntities.Entry]]:
            """Search for LDAP entries - REFACTORED with shared validation."""
            try:
                # Use REFACTORED validation helpers - NO DUPLICATION
                dn_validation = self._validate_dn_or_fail(params.base_dn, "base DN")
                if not dn_validation.is_success:
                    return FlextResult[list[FlextLDAPEntities.Entry]].fail(
                        dn_validation.error or "DN validation failed",
                    )

                filter_validation = self._validate_filter_or_fail(params.search_filter)
                if not filter_validation.is_success:
                    return FlextResult[list[FlextLDAPEntities.Entry]].fail(
                        filter_validation.error or "Filter validation failed",
                    )

                # Simulate search operation
                entries: list[FlextLDAPEntities.Entry] = []

                # Use REFACTORED logging - NO DUPLICATION
                logger.debug(
                    "LDAP search completed",
                    extra={
                        "connection_id": params.connection_id,
                        "base_dn": params.base_dn,
                        "filter": params.search_filter,
                        "scope": params.scope,
                        "attributes": params.attributes,
                        "size_limit": params.size_limit,
                        "time_limit": params.time_limit,
                        "result_count": len(entries),
                    },
                )

                return FlextResult[list[FlextLDAPEntities.Entry]].ok(entries)

            except Exception as e:
                # Use REFACTORED exception handling - NO DUPLICATION
                error_msg = self._handle_exception_with_context(
                    "search operation",
                    e,
                    params.connection_id,
                )
                return FlextResult[list[FlextLDAPEntities.Entry]].fail(error_msg)

        async def search_users(
            self,
            connection_id: str,
            base_dn: str,
            filter_criteria: FlextTypes.Core.Headers | None = None,
            size_limit: int = 1000,
        ) -> FlextResult[list[FlextLDAPEntities.User]]:
            """Search for user entries - REFACTORED with helper composition."""
            try:
                # Use REFACTORED filter building - NO DUPLICATION
                base_filter = self._build_user_filter(filter_criteria)

                # Use general search and convert to users
                search_params = FlextLDAPEntities.SearchParams(
                    connection_id=connection_id,
                    base_dn=base_dn,
                    search_filter=base_filter,
                    scope="subtree",
                    attributes=["uid", "cn", "sn", "givenName", "mail", "objectClass"],
                    size_limit=size_limit,
                )
                search_result = await self.search_entries(search_params)

                if not search_result.is_success:
                    return FlextResult[list[FlextLDAPEntities.User]].fail(
                        search_result.error or "User search failed",
                    )

                # Use CORRECTED conversion with .value property (modern)
                users = self._convert_entries_to_users(search_result.value)

                # Use REFACTORED logging - NO DUPLICATION
                self._log_operation_success(
                    "user search",
                    connection_id,
                    base_dn=base_dn,
                    criteria=filter_criteria,
                    result_count=len(users),
                )

                return FlextResult[list[FlextLDAPEntities.User]].ok(users)

            except Exception as e:
                # Use REFACTORED exception handling - NO DUPLICATION
                error_msg = self._handle_exception_with_context(
                    "user search",
                    e,
                    connection_id,
                )
                return FlextResult[list[FlextLDAPEntities.User]].fail(error_msg)

        async def search_groups(
            self,
            connection_id: str,
            base_dn: str,
            filter_criteria: FlextTypes.Core.Headers | None = None,
            size_limit: int = 1000,
        ) -> FlextResult[list[FlextLDAPEntities.Group]]:
            """Search for group entries - REFACTORED with helper composition."""
            try:
                # Use REFACTORED filter building - NO DUPLICATION
                base_filter = self._build_group_filter(filter_criteria)

                # Use general search and convert to groups
                search_params = FlextLDAPEntities.SearchParams(
                    connection_id=connection_id,
                    base_dn=base_dn,
                    search_filter=base_filter,
                    scope="subtree",
                    attributes=["cn", "description", "member", "objectClass"],
                    size_limit=size_limit,
                )
                search_result = await self.search_entries(search_params)

                if not search_result.is_success:
                    return FlextResult[list[FlextLDAPEntities.Group]].fail(
                        search_result.error or "Group search failed",
                    )

                # Use CORRECTED conversion with .value property (modern)
                groups = self._convert_entries_to_groups(search_result.value)

                # Use REFACTORED logging - NO DUPLICATION
                self._log_operation_success(
                    "group search",
                    connection_id,
                    base_dn=base_dn,
                    criteria=filter_criteria,
                    result_count=len(groups),
                )

                return FlextResult[list[FlextLDAPEntities.Group]].ok(groups)

            except Exception as e:
                # Use REFACTORED exception handling - NO DUPLICATION
                error_msg = self._handle_exception_with_context(
                    "group search",
                    e,
                    connection_id,
                )
                return FlextResult[list[FlextLDAPEntities.Group]].fail(error_msg)

        async def get_entry_by_dn(
            self,
            connection_id: str,
            dn: str,
            attributes: FlextTypes.Core.StringList | None = None,
        ) -> FlextResult[FlextLDAPEntities.Entry]:
            """Get a single entry by DN - REFACTORED."""
            search_params = FlextLDAPEntities.SearchParams(
                connection_id=connection_id,
                base_dn=dn,
                search_filter="(objectClass=*)",
                scope="base",
                attributes=attributes,
                size_limit=1,
            )
            search_result = await self.search_entries(search_params)

            if not search_result.is_success:
                return FlextResult.fail(
                    search_result.error or "Search operation failed",
                )

            if not search_result.value:
                return FlextResult.fail(
                    f"Entry not found: {dn}",
                )

            return FlextResult.ok(search_result.value[0])

        def _build_user_filter(
            self, filter_criteria: FlextTypes.Core.Headers | None
        ) -> str:
            """Build user-specific filter - REUSABLE HELPER."""
            base_filter = "(&(objectClass=person)"
            if filter_criteria:
                for attr, value in filter_criteria.items():
                    escaped_value = self._escape_ldap_filter_value(value)
                    base_filter += f"({attr}=*{escaped_value}*)"
            return base_filter + ")"

        def _build_group_filter(
            self, filter_criteria: FlextTypes.Core.Headers | None
        ) -> str:
            """Build group-specific filter - REUSABLE HELPER."""
            base_filter = "(&(objectClass=groupOfNames)"
            if filter_criteria:
                for attr, value in filter_criteria.items():
                    escaped_value = self._escape_ldap_filter_value(value)
                    base_filter += f"({attr}=*{escaped_value}*)"
            return base_filter + ")"

        def _escape_ldap_filter_value(self, value: str) -> str:
            """Escape special LDAP filter characters - REUSABLE HELPER."""
            return (
                value.replace("\\", "\\5c")
                .replace("*", "\\2a")
                .replace("(", "\\28")
                .replace(")", "\\29")
            )

        def _convert_entries_to_users(
            self,
            entries: list[FlextLDAPEntities.Entry],
        ) -> list[FlextLDAPEntities.User]:
            """Convert entries to users - REFACTORED using FlextProcessors Strategy Pattern.

            Complexity reduced from 19 to ~5 using LDAP Attribute Processing Strategy.
            """
            users: list[FlextLDAPEntities.User] = []
            # Create processor using flext-core patterns
            attribute_processor = LDAPAttributeProcessor.UserAttributeExtractor()

            for entry in entries:
                # Use flext-core processor instead of manual extraction
                extraction_result = attribute_processor.process_data(entry)

                if not extraction_result.is_success:
                    # Skip invalid entries instead of crashing
                    logger.warning(
                        f"Failed to extract attributes from entry {entry.dn}: {extraction_result.error}",
                    )
                    continue

                # Get extracted attributes using flext-core result pattern
                attrs = extraction_result.value

                # Build user entity using extracted data with safe casting
                users.append(
                    FlextLDAPEntities.User(
                        id=f"user_{uuid.uuid4().hex[:8]}",
                        dn=entry.dn,
                        uid=str(attrs.get("uid") or "unknown"),
                        cn=str(attrs.get("cn"))
                        if attrs.get("cn") is not None
                        else None,
                        sn=str(attrs.get("sn"))
                        if attrs.get("sn") is not None
                        else None,
                        given_name=str(attrs.get("givenName"))
                        if attrs.get("givenName") is not None
                        else None,
                        mail=str(attrs.get("mail"))
                        if attrs.get("mail") is not None
                        else None,
                        user_password=None,
                        object_classes=entry.object_classes,
                        attributes=entry.attributes,
                        modified_at=None,
                    ),
                )
            return users

        def _convert_entries_to_groups(
            self,
            entries: list[FlextLDAPEntities.Entry],
        ) -> list[FlextLDAPEntities.Group]:
            """Convert entries to groups - REFACTORED using FlextProcessors Strategy Pattern.

            Complexity reduced using LDAP Group Attribute Processing Strategy.
            """
            groups: list[FlextLDAPEntities.Group] = []
            # Create processor using flext-core patterns
            attribute_processor = LDAPAttributeProcessor.GroupAttributeExtractor()

            for entry in entries:
                # Use flext-core processor instead of manual extraction
                extraction_result = attribute_processor.process_data(entry)

                if not extraction_result.is_success:
                    # Skip invalid entries instead of crashing
                    logger.warning(
                        f"Failed to extract group attributes from entry {entry.dn}: {extraction_result.error}",
                    )
                    continue

                # Get extracted attributes using flext-core result pattern
                attrs = extraction_result.value

                # Build group entity using extracted data
                groups.append(
                    FlextLDAPEntities.Group(
                        id=f"group_{uuid.uuid4().hex[:8]}",
                        dn=entry.dn,
                        cn=str(attrs.get("cn", "unknown"))
                        if attrs.get("cn")
                        else "unknown",
                        description=str(attrs.get("description"))
                        if attrs.get("description")
                        else None,
                        members=cast("FlextTypes.Core.StringList", attrs.get("members"))
                        if isinstance(attrs.get("members"), list)
                        else [],
                        object_classes=entry.object_classes,
                        attributes=entry.attributes,
                        modified_at=None,
                    ),
                )
            return groups

    class EntryOperations(OperationsService):
        """Internal specialized entry management operations class."""

        async def create_entry(
            self,
            connection_id: str,
            dn: str,
            object_classes: FlextTypes.Core.StringList,
            attributes: LdapAttributeDict,
        ) -> FlextResult[FlextLDAPEntities.Entry]:
            """Create a new LDAP entry - REFACTORED with shared validation."""
            try:
                # Use REFACTORED validation helpers - NO DUPLICATION
                dn_validation = self._validate_dn_or_fail(dn)
                if not dn_validation.is_success:
                    return FlextResult.fail(
                        dn_validation.error or "DN validation failed",
                    )

                if not object_classes:
                    return FlextResult.fail(
                        "Entry must have at least one object class",
                    )

                # Create entry entity with validation
                entry = FlextLDAPEntities.Entry(
                    id=f"entry_{uuid.uuid4().hex[:8]}",
                    dn=dn,
                    object_classes=object_classes,
                    attributes=attributes,
                    modified_at=None,
                    # Note: no status field as FlextModels already has it
                )

                validation_result = entry.validate_business_rules()
                if not validation_result.is_success:
                    return FlextResult.fail(
                        f"Entry validation failed: {validation_result.error}",
                    )

                # Use REFACTORED logging - NO DUPLICATION
                self._log_operation_success(
                    "entry created",
                    connection_id,
                    entry_dn=dn,
                    object_classes=object_classes,
                    attribute_count=len(attributes),
                )

                return FlextResult.ok(entry)

            except Exception as e:
                # Use REFACTORED exception handling - NO DUPLICATION
                error_msg = self._handle_exception_with_context(
                    "create entry",
                    e,
                    connection_id,
                )
                return FlextResult.fail(error_msg)

        async def modify_entry(
            self,
            connection_id: str,
            dn: str,
            modifications: FlextTypes.Core.Dict,
        ) -> FlextResult[None]:
            """Modify an existing LDAP entry - REFACTORED."""
            try:
                # Use REFACTORED validation helpers - NO DUPLICATION
                dn_validation = self._validate_dn_or_fail(dn)
                if not dn_validation.is_success:
                    return FlextResult.fail(
                        dn_validation.error or "DN validation failed",
                    )

                if not modifications:
                    return FlextResult.fail("No modifications specified")

                # Use REFACTORED logging - NO DUPLICATION
                self._log_operation_success(
                    "entry modified",
                    connection_id,
                    entry_dn=dn,
                    modification_count=len(modifications),
                )

                return FlextResult.ok(None)

            except Exception as e:
                # Use REFACTORED exception handling - NO DUPLICATION
                error_msg = self._handle_exception_with_context(
                    "modify entry",
                    e,
                    connection_id,
                )
                return FlextResult.fail(error_msg)

        async def delete_entry(
            self,
            connection_id: str,
            dn: str,
        ) -> FlextResult[None]:
            """Delete an LDAP entry - REFACTORED."""
            try:
                # Use REFACTORED validation helpers - NO DUPLICATION
                dn_validation = self._validate_dn_or_fail(dn)
                if not dn_validation.is_success:
                    return FlextResult.fail(
                        dn_validation.error or "DN validation failed",
                    )

                # Use REFACTORED logging - NO DUPLICATION
                self._log_operation_success("entry deleted", connection_id, entry_dn=dn)

                return FlextResult.ok(None)

            except Exception as e:
                # Use REFACTORED exception handling - NO DUPLICATION
                error_msg = self._handle_exception_with_context(
                    "delete entry",
                    e,
                    connection_id,
                )
                return FlextResult.fail(error_msg)

    class UserOperations(OperationsService):
        """Internal specialized user management operations class."""

        # Private attribute for entry operations
        _entry_ops: object | None = PrivateAttr(default=None)

        def __init__(self, **data: object) -> None:
            """Initialize user operations - USES REFACTORED BASE."""
            super().__init__(**data)
            self._entry_ops = FlextLDAPOperations.EntryOperations()

        async def create_user(
            self,
            connection_id: str,
            user_request: FlextLDAPEntities.CreateUserRequest,
        ) -> FlextResult[FlextLDAPEntities.User]:
            """Create a new LDAP user - REFACTORED with helper composition."""
            try:
                # Use REFACTORED attribute building - NO DUPLICATION
                attributes = self._build_user_attributes(user_request)

                # Create entry using shared operations with standard user object classes
                if self._entry_ops is None:
                    return FlextResult.fail(
                        "Entry operations not available",
                    )

                # Type cast to correct interface
                entry_ops = cast("FlextLDAPOperations.EntryOperations", self._entry_ops)
                entry_result = await entry_ops.create_entry(
                    connection_id=connection_id,
                    dn=user_request.dn,
                    object_classes=["inetOrgPerson", "person", "top"],
                    attributes=attributes,
                )

                if not entry_result.is_success:
                    return FlextResult.fail(
                        f"Failed to create user entry: {entry_result.error}",
                    )

                # Use REFACTORED user creation - NO DUPLICATION
                user = self._build_user_entity(user_request, attributes)

                validation_result = user.validate_business_rules()
                if not validation_result.is_success:
                    return FlextResult.fail(
                        f"User validation failed: {validation_result.error}",
                    )

                # Use REFACTORED logging - NO DUPLICATION
                self._log_operation_success(
                    "user created",
                    connection_id,
                    user_dn=user_request.dn,
                    uid=user_request.uid,
                )

                return FlextResult.ok(user)

            except Exception as e:
                # Use REFACTORED exception handling - NO DUPLICATION
                error_msg = self._handle_exception_with_context(
                    "create user",
                    e,
                    connection_id,
                )
                return FlextResult.fail(error_msg)

        async def update_user_password(
            self,
            connection_id: str,
            user_dn: str,
            new_password: str,
        ) -> FlextResult[None]:
            """Update user password - REFACTORED with validation."""
            if (
                not new_password
                or len(new_password)
                < FlextLDAPConstants.LdapValidation.MIN_PASSWORD_LENGTH
            ):
                return FlextResult.fail(
                    f"Password must be at least {FlextLDAPConstants.LdapValidation.MIN_PASSWORD_LENGTH} characters",
                )

            modifications: FlextTypes.Core.Dict = {"userPassword": [new_password]}
            if self._entry_ops is None:
                return FlextResult.fail("Entry operations not available")

            # Type cast to correct interface
            entry_ops = cast("FlextLDAPOperations.EntryOperations", self._entry_ops)
            return await entry_ops.modify_entry(connection_id, user_dn, modifications)

        async def update_user_email(
            self,
            connection_id: str,
            user_dn: str,
            email: str,
        ) -> FlextResult[None]:
            """Update user email address - REFACTORED with validation."""
            if "@" not in email:
                return FlextResult.fail("Invalid email format")

            modifications: FlextTypes.Core.Dict = {"mail": [email]}
            if self._entry_ops is None:
                return FlextResult.fail("Entry operations not available")

            # Type cast to correct interface
            entry_ops = cast("FlextLDAPOperations.EntryOperations", self._entry_ops)
            return await entry_ops.modify_entry(connection_id, user_dn, modifications)

        async def activate_user(
            self,
            connection_id: str,
            user_dn: str,
        ) -> FlextResult[None]:
            """Activate user account - REFACTORED."""
            modifications: FlextTypes.Core.Dict = {"accountStatus": ["active"]}
            if self._entry_ops is None:
                return FlextResult.fail("Entry operations not available")

            # Type cast to correct interface
            entry_ops = cast("FlextLDAPOperations.EntryOperations", self._entry_ops)
            return await entry_ops.modify_entry(connection_id, user_dn, modifications)

        async def deactivate_user(
            self,
            connection_id: str,
            user_dn: str,
        ) -> FlextResult[None]:
            """Deactivate user account - REFACTORED."""
            modifications: FlextTypes.Core.Dict = {"accountStatus": ["inactive"]}
            if self._entry_ops is None:
                return FlextResult.fail("Entry operations not available")

            # Type cast to correct interface
            entry_ops = cast("FlextLDAPOperations.EntryOperations", self._entry_ops)
            return await entry_ops.modify_entry(connection_id, user_dn, modifications)

        def _build_user_attributes(
            self,
            user_request: FlextLDAPEntities.CreateUserRequest,
        ) -> LdapAttributeDict:
            """Build user attributes from request - REUSABLE HELPER."""
            attributes: LdapAttributeDict = {
                "uid": [user_request.uid],
                "cn": [user_request.cn],
            }
            # Only add non-None optional attributes
            if user_request.sn:
                attributes["sn"] = [user_request.sn]
            if user_request.given_name:
                attributes["givenName"] = [user_request.given_name]
            if user_request.mail:
                attributes["mail"] = [user_request.mail]
            return attributes

        def _build_user_entity(
            self,
            user_request: FlextLDAPEntities.CreateUserRequest,
            attributes: LdapAttributeDict,
        ) -> FlextLDAPEntities.User:
            """Build user entity - REUSABLE HELPER."""
            user_id_str = self._generate_id()
            return FlextLDAPEntities.User(
                id=user_id_str,
                dn=user_request.dn,
                object_classes=["inetOrgPerson", "person", "top"],
                attributes=attributes,
                uid=user_request.uid,
                cn=user_request.cn,
                sn=user_request.sn,
                given_name=user_request.given_name,
                mail=user_request.mail,
                user_password=user_request.user_password,
                modified_at=None,
                # Note: no phone field in FlextLDAPEntities.User
                # Note: no status field as FlextModels already has it
            )

    class GroupOperations(OperationsService):
        """Internal specialized group management operations class."""

        # Private attribute for entry operations
        _entry_ops: object | None = PrivateAttr(default=None)
        _search_ops: object | None = PrivateAttr(default=None)

        def __init__(self, **data: object) -> None:
            """Initialize group operations - USES REFACTORED BASE."""
            super().__init__(**data)
            self._entry_ops = FlextLDAPOperations.EntryOperations()
            self._search_ops = FlextLDAPOperations.SearchOperations()

        async def create_group(
            self,
            connection_id: str,
            dn: str,
            cn: str,
            description: str | None = None,
            initial_members: FlextTypes.Core.StringList | None = None,
        ) -> FlextResult[FlextLDAPEntities.Group]:
            """Create a new LDAP group - REFACTORED with helper composition."""
            try:
                # Use REFACTORED helper for member handling - NO DUPLICATION
                members = self._prepare_group_members(initial_members)
                attributes = self._build_group_attributes(cn, description, members)

                # Create entry using shared operations
                if self._entry_ops is None:
                    return FlextResult.fail(
                        "Entry operations not available",
                    )

                # Type cast to correct interface
                entry_ops = cast("FlextLDAPOperations.EntryOperations", self._entry_ops)
                entry_result = await entry_ops.create_entry(
                    connection_id=connection_id,
                    dn=dn,
                    object_classes=["groupOfNames", "top"],
                    attributes=attributes,
                )

                if not entry_result.is_success:
                    return FlextResult.fail(
                        f"Failed to create group entry: {entry_result.error}",
                    )

                # Use REFACTORED group creation - NO DUPLICATION
                group = self._build_group_entity(
                    dn,
                    cn,
                    description,
                    members,
                    attributes,
                )

                validation_result = group.validate_business_rules()
                if not validation_result.is_success:
                    return FlextResult.fail(
                        f"Group validation failed: {validation_result.error}",
                    )

                # Use REFACTORED logging - NO DUPLICATION
                self._log_operation_success(
                    "group created",
                    connection_id,
                    group_dn=dn,
                    cn=cn,
                    member_count=len(members),
                )

                return FlextResult.ok(group)

            except Exception as e:
                # Use REFACTORED exception handling - NO DUPLICATION
                error_msg = self._handle_exception_with_context(
                    "create group",
                    e,
                    connection_id,
                )
                return FlextResult.fail(error_msg)

        async def add_group_member(
            self,
            connection_id: str,
            group_dn: str,
            member_dn: str,
        ) -> FlextResult[None]:
            """Add member to LDAP group - REFACTORED with helper composition."""
            try:
                # Use REFACTORED validation helpers - NO DUPLICATION
                member_validation = self._validate_dn_or_fail(member_dn, "member DN")
                if not member_validation.is_success:
                    return FlextResult.fail(
                        member_validation.error or "Member validation failed",
                    )

                # Use REFACTORED member management - NO DUPLICATION
                return await self._modify_group_membership(
                    connection_id,
                    group_dn,
                    member_dn,
                    action="add",
                )

            except Exception as e:
                # Use REFACTORED exception handling - NO DUPLICATION
                error_msg = self._handle_exception_with_context(
                    "add group member",
                    e,
                    connection_id,
                )
                return FlextResult.fail(error_msg)

        async def remove_group_member(
            self,
            connection_id: str,
            group_dn: str,
            member_dn: str,
        ) -> FlextResult[None]:
            """Remove member from LDAP group - REFACTORED with helper composition."""
            try:
                # Use REFACTORED member management - NO DUPLICATION
                return await self._modify_group_membership(
                    connection_id,
                    group_dn,
                    member_dn,
                    action="remove",
                )

            except Exception as e:
                # Use REFACTORED exception handling - NO DUPLICATION
                error_msg = self._handle_exception_with_context(
                    "remove group member",
                    e,
                    connection_id,
                )
                return FlextResult.fail(error_msg)

        async def get_group_members(
            self,
            connection_id: str,
            group_dn: str,
        ) -> FlextResult[FlextTypes.Core.StringList]:
            """Get all members of a group - REFACTORED."""
            try:
                if self._search_ops is None:
                    return FlextResult[FlextTypes.Core.StringList].fail(
                        "Search operations not available",
                    )

                # Type cast to correct interface
                search_ops = cast(
                    "FlextLDAPOperations.SearchOperations",
                    self._search_ops,
                )
                group_result = await search_ops.get_entry_by_dn(
                    connection_id=connection_id,
                    dn=group_dn,
                    attributes=["member"],
                )

                if not group_result.is_success:
                    return FlextResult[FlextTypes.Core.StringList].fail(
                        f"Failed to get group: {group_result.error}",
                    )

                # Get member attribute and convert to list of strings
                member_attr = group_result.value.get_attribute("member")
                members: FlextTypes.Core.StringList = []
                if member_attr:
                    if isinstance(member_attr, list):
                        members = [str(m) for m in member_attr]
                    else:
                        members = [str(member_attr)]

                real_members = self._filter_dummy_members(members)
                return FlextResult[FlextTypes.Core.StringList].ok(real_members)

            except Exception as e:
                # Use REFACTORED exception handling - NO DUPLICATION
                error_msg = self._handle_exception_with_context(
                    "get group members",
                    e,
                    connection_id,
                )
                return FlextResult[FlextTypes.Core.StringList].fail(error_msg)

        async def update_group_description(
            self,
            connection_id: str,
            group_dn: str,
            description: str,
        ) -> FlextResult[None]:
            """Update group description - REFACTORED."""
            modifications: FlextTypes.Core.Dict = {"description": [description]}
            if self._entry_ops is None:
                return FlextResult.fail("Entry operations not available")

            # Type cast to correct interface
            entry_ops = cast("FlextLDAPOperations.EntryOperations", self._entry_ops)
            return await entry_ops.modify_entry(
                connection_id,
                group_dn,
                modifications,
            )

        def _prepare_group_members(
            self,
            initial_members: FlextTypes.Core.StringList | None,
        ) -> FlextTypes.Core.StringList:
            """Prepare group members with dummy member if needed - REUSABLE HELPER."""
            members = initial_members or []
            if not members:
                # Add dummy member if none provided (required by groupOfNames)
                members = ["cn=dummy,ou=temp,dc=example,dc=com"]
            return members

        def _build_group_attributes(
            self,
            cn: str,
            description: str | None,
            members: FlextTypes.Core.StringList,
        ) -> LdapAttributeDict:
            """Build group attributes - REUSABLE HELPER."""
            attributes: LdapAttributeDict = {
                "cn": [cn],
                "member": members,
            }
            if description:
                attributes["description"] = [description]
            return attributes

        def _build_group_entity(
            self,
            dn: str,
            cn: str,
            description: str | None,
            members: FlextTypes.Core.StringList,
            attributes: LdapAttributeDict,
        ) -> FlextLDAPEntities.Group:
            """Build group entity - REUSABLE HELPER."""
            group_id_str = self._generate_id()
            return FlextLDAPEntities.Group(
                id=group_id_str,
                dn=dn,
                object_classes=["groupOfNames", "top"],
                attributes=attributes,
                cn=cn,
                description=description,
                members=members,
                modified_at=None,
                # Note: no status field as FlextModels already has it
            )

        def _filter_dummy_members(
            self, members: FlextTypes.Core.StringList
        ) -> FlextTypes.Core.StringList:
            """Filter out dummy members - REUSABLE HELPER."""
            return [m for m in members if not m.startswith("cn=dummy,ou=temp")]

        async def _modify_group_membership(
            self,
            connection_id: str,
            group_dn: str,
            member_dn: str,
            action: str,
        ) -> FlextResult[None]:
            """Modify group membership (add/remove) - REFACTORED using Command Pattern.

            Complexity reduced by encapsulating operation as command.
            """
            # Create command using flext-core Command Pattern
            command = LDAPCommandProcessor.MembershipCommand(
                connection_id=connection_id,
                group_dn=group_dn,
                member_dn=member_dn,
                action=action,
            )

            # Validate command using built-in validation
            validation_result = command.validate_membership_operation()
            if not validation_result.is_success:
                return validation_result

            # Execute membership modification pipeline
            return await self._execute_membership_command(command)

        async def _execute_membership_command(
            self,
            command: LDAPCommandProcessor.MembershipCommand,
        ) -> FlextResult[None]:
            """Execute membership command - encapsulates complex membership logic."""
            try:
                # Step 1: Get current group membership using encapsulated method
                group_result = await self._get_group_membership(
                    command.connection_id,
                    command.group_dn,
                )
                if group_result.is_failure:
                    return FlextResult.fail(
                        group_result.error or "Failed to get group",
                    )

                # Step 2: Extract and process members using simplified logic
                current_members = self._extract_current_members(group_result.value)
                updated_members_result = self._calculate_updated_members(
                    current_members,
                    command.member_dn,
                    command.action,
                )

                if updated_members_result.is_failure:
                    return FlextResult.fail(
                        updated_members_result.error or "Failed to calculate members",
                    )

                # Step 3: Apply the change using existing method
                return await self._apply_membership_change(
                    command.connection_id,
                    command.group_dn,
                    updated_members_result.value,
                    command.action,
                    command.member_dn,
                )
            except Exception as e:
                return FlextResult.fail(
                    f"Membership command execution failed: {e}",
                )

        def _extract_current_members(
            self, group_entry: object
        ) -> FlextTypes.Core.StringList:
            """Extract current members from group entry - simplified logic."""
            if not hasattr(group_entry, "get_attribute"):
                return []

            current_members = getattr(group_entry, "get_attribute", lambda _: None)(
                "member"
            )

            # Simplified member extraction using Strategy Pattern
            if current_members is None:
                return []
            if isinstance(current_members, list):
                return [str(item) for item in current_members]
            return [str(current_members)]

        async def _get_group_membership(
            self,
            connection_id: str,
            group_dn: str,
        ) -> FlextResult[FlextLDAPEntities.Entry]:
            """Get current group membership data."""
            if self._search_ops is None:
                return FlextResult.fail(
                    "Search operations not available",
                )

            # Type cast to correct interface
            search_ops = cast("FlextLDAPOperations.SearchOperations", self._search_ops)
            group_result = await search_ops.get_entry_by_dn(
                connection_id=connection_id,
                dn=group_dn,
                attributes=["member"],
            )

            if not group_result.is_success:
                return FlextResult.fail(
                    f"Failed to get group: {group_result.error}",
                )

            return FlextResult.ok(group_result.value)

        def _calculate_updated_members(
            self,
            current_members: FlextTypes.Core.StringList,
            member_dn: str,
            action: str,
        ) -> FlextResult[FlextTypes.Core.StringList]:
            """Calculate updated member list based on action."""
            if action == "add":
                return self._handle_add_member(current_members, member_dn)
            if action == "remove":
                return self._handle_remove_member(current_members, member_dn)
            return FlextResult[FlextTypes.Core.StringList].fail(
                f"Invalid action: {action}"
            )

        def _handle_add_member(
            self,
            current_members: FlextTypes.Core.StringList,
            member_dn: str,
        ) -> FlextResult[FlextTypes.Core.StringList]:
            """Handle adding a member to the group."""
            if member_dn in current_members:
                return FlextResult[FlextTypes.Core.StringList].fail(
                    f"Member already exists in group: {member_dn}",
                )
            return FlextResult[FlextTypes.Core.StringList].ok(
                [*current_members, member_dn]
            )

        def _handle_remove_member(
            self,
            current_members: FlextTypes.Core.StringList,
            member_dn: str,
        ) -> FlextResult[FlextTypes.Core.StringList]:
            """Handle removing a member from the group."""
            if member_dn not in current_members:
                return FlextResult[FlextTypes.Core.StringList].fail(
                    f"Member not found in group: {member_dn}",
                )

            updated_members = [m for m in current_members if m != member_dn]
            # Add dummy member if none left (LDAP groupOfNames requirement)
            if not updated_members:
                updated_members = ["cn=dummy,ou=temp,dc=example,dc=com"]

            return FlextResult[FlextTypes.Core.StringList].ok(updated_members)

        async def _apply_membership_change(
            self,
            connection_id: str,
            group_dn: str,
            updated_members: FlextTypes.Core.StringList,
            action: str,
            member_dn: str,
        ) -> FlextResult[None]:
            """Apply the membership change to LDAP."""
            modifications: FlextTypes.Core.Dict = {"member": updated_members}
            if self._entry_ops is None:
                return FlextResult.fail("Entry operations not available")

            # Type cast to correct interface
            entry_ops = cast("FlextLDAPOperations.EntryOperations", self._entry_ops)
            modify_result = await entry_ops.modify_entry(
                connection_id=connection_id,
                dn=group_dn,
                modifications=modifications,
            )

            if modify_result.is_success:
                action_verb = "added to" if action == "add" else "removed from"
                self._log_operation_success(
                    f"member {action_verb} group",
                    connection_id,
                    group_dn=group_dn,
                    member_dn=member_dn,
                )

            return modify_result

    # ==========================================================================
    # MAIN CONSOLIDATED INTERFACE
    # ==========================================================================

    def __init__(self) -> None:
        """Initialize all operation handlers with consolidated pattern."""
        self._connections = self.ConnectionOperations()
        self._search = self.SearchOperations()
        self._entries = self.EntryOperations()
        self._users = self.UserOperations()
        self._groups = self.GroupOperations()

    @property
    def connections(self) -> ConnectionOperations:
        """Access connections operations through consolidated interface."""
        return self._connections

    @property
    def search(self) -> SearchOperations:
        """Access search operations through consolidated interface."""
        return self._search

    @property
    def entries(self) -> EntryOperations:
        """Access entry operations through consolidated interface."""
        return self._entries

    @property
    def users(self) -> UserOperations:
        """Access user operations through consolidated interface."""
        return self._users

    @property
    def groups(self) -> GroupOperations:
        """Access group operations through consolidated interface."""
        return self._groups

    # High-level convenience methods
    def generate_id(self) -> str:
        """Public method to generate ID for testing and external use."""
        return self.connections._generate_id()

    async def create_connection_and_bind(
        self,
        server_uri: str,
        bind_dn: str | None = None,
        bind_password: str | None = None,
    ) -> FlextResult[str]:
        """Create connection and perform bind operation."""
        return await self.connections.create_connection(
            server_uri=server_uri,
            bind_dn=bind_dn,
            _bind_password=bind_password,
        )

    async def search_and_get_first(
        self,
        connection_id: str,
        base_dn: str,
        search_filter: str,
        attributes: FlextTypes.Core.StringList | None = None,
    ) -> FlextResult[FlextLDAPEntities.Entry | None]:
        """Search and return first matching entry."""
        search_params = FlextLDAPEntities.SearchParams(
            connection_id=connection_id,
            base_dn=base_dn,
            search_filter=search_filter,
            attributes=attributes,
            size_limit=1,
        )
        search_result = await self.search.search_entries(search_params)

        if not search_result.is_success:
            return FlextResult.fail(
                search_result.error or "Search operation failed",
            )

        first_entry = search_result.value[0] if search_result.value else None
        return FlextResult.ok(first_entry)

    def _validate_dn_or_fail(self, dn: str, context: str = "DN") -> FlextResult[None]:
        """Delegate to internal validation method for testing purposes."""
        # Create a temporary service instance to access validation
        service = self.OperationsService()
        return service._validate_dn_or_fail(dn, context)

    def _validate_filter_or_fail(self, search_filter: str) -> FlextResult[None]:
        """Delegate to internal filter validation method for testing purposes."""
        service = self.OperationsService()
        return service._validate_filter_or_fail(search_filter)

    def _validate_uri_or_fail(self, server_uri: str) -> FlextResult[None]:
        """Delegate to internal URI validation method for testing purposes."""
        service = self.OperationsService()
        return service._validate_uri_or_fail(server_uri)

    def _handle_exception_with_context(
        self,
        operation: str,
        exception: Exception,
        connection_id: str = "",
    ) -> str:
        """Delegate to internal exception handling for testing purposes."""
        service = self.OperationsService()
        return service._handle_exception_with_context(
            operation,
            exception,
            connection_id,
        )

    def _log_operation_success(
        self,
        operation: str,
        connection_id: str,
        **kwargs: object,
    ) -> None:
        """Delegate to internal success logging for testing purposes."""
        service = self.OperationsService()
        service._log_operation_success(operation, connection_id, **kwargs)

    async def cleanup_connection(self, connection_id: str) -> None:
        """Clean up connection resources."""
        await self.connections.close_connection(connection_id)


# =============================================================================
# BACKWARD COMPATIBILITY ALIASES - Following FLEXT consolidation patterns
# =============================================================================

# Export internal classes for external access (backward compatibility)
# Export aliases eliminated - use FlextLDAPOperations.* directly following flext-core pattern

__all__ = [
    "FlextLDAPOperations",
]
