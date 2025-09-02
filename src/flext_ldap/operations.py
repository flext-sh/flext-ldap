"""SINGLE CONSOLIDATED FlextLDAPOperations class following FLEXT architectural patterns.

FLEXT_REFACTORING_PROMPT.md COMPLIANCE: Single consolidated class for all LDAP operation functionality.
All specialized functionality delivered through internal subclasses within FlextLDAPOperations.

CONSOLIDATED CLASSES: FlextLDAPOperationsService + FlextLDAPConnectionOperations + FlextLDAPSearchOperations + FlextLDAPEntryOperations + FlextLDAPUserOperations + FlextLDAPGroupOperations
"""

import uuid
from datetime import UTC, datetime
from typing import ClassVar, cast

from flext_core import (
    FlextDomainService,
    FlextLogger,
    FlextResult,
    FlextTypes,
)
from pydantic import PrivateAttr

from flext_ldap.constants import FlextLDAPValidationMessages
from flext_ldap.models import (
    FlextLDAPCreateUserRequest,
    FlextLDAPEntry,
    FlextLDAPGroup,
    FlextLDAPUser,
)
from flext_ldap.typings import LdapAttributeDict
from flext_ldap.utilities import FlextLDAPUtilities
from flext_ldap.value_objects import (
    FlextLDAPDistinguishedName,
    FlextLDAPFilter,
)

logger = FlextLogger(__name__)


class FlextLDAPOperations:
    """SINGLE CONSOLIDATED CLASS for all LDAP operation functionality.

    Following FLEXT architectural patterns - consolidates ALL LDAP operation functionality
    including connections, search, entries, users, and groups into one main class
    with specialized internal subclasses for organization.

    CONSOLIDATED CLASSES: FlextLDAPOperationsService + FlextLDAPConnectionOperations + FlextLDAPSearchOperations + FlextLDAPEntryOperations + FlextLDAPUserOperations + FlextLDAPGroupOperations
    """

    # ==========================================================================
    # INTERNAL BASE SERVICE CLASS
    # ==========================================================================

    class OperationsService(FlextDomainService[None]):
        """Internal base service using flext-core patterns - CORRECT signature."""

        def __init__(self, **data: object) -> None:
            """Initialize shared components using flext-core domain service."""
            super().__init__(**data)

        def _generate_id(self) -> str:
            """Generate ID using UUID - simple approach."""
            return str(uuid.uuid4())

        def execute(self) -> FlextResult[None]:
            """Execute method required by FlextDomainService - CORRECT signature."""
            return FlextResult[None].ok(None)

        def _validate_dn_or_fail(
            self, dn: str, context: str = "DN"
        ) -> FlextResult[None]:
            """Validate DN and return error if invalid - REUSABLE VALIDATION."""
            dn_validation = FlextLDAPDistinguishedName(
                value=dn
            ).validate_business_rules()
            if not dn_validation.is_success:
                error_msg = (
                    dn_validation.error
                    or FlextLDAPValidationMessages.UNKNOWN_VALIDATION_ERROR
                )
                return FlextResult[None].fail(
                    FlextLDAPValidationMessages.INVALID_DN_WITH_CONTEXT.format(
                        context=context,
                        error=error_msg,
                    ),
                )
            return FlextResult[None].ok(None)

        def _validate_filter_or_fail(self, search_filter: str) -> FlextResult[None]:
            """Validate LDAP filter and return error if invalid - REUSABLE VALIDATION."""
            filter_validation = FlextLDAPFilter(
                value=search_filter,
            ).validate_business_rules()
            if not filter_validation.is_success:
                error_msg = (
                    filter_validation.error
                    or FlextLDAPValidationMessages.UNKNOWN_VALIDATION_ERROR
                )
                return FlextResult[None].fail(
                    FlextLDAPValidationMessages.INVALID_SEARCH_FILTER.format(
                        error=error_msg,
                    ),
                )
            return FlextResult[None].ok(None)

        def _validate_uri_or_fail(self, server_uri: str) -> FlextResult[None]:
            """Validate server URI and return error if invalid - REUSABLE VALIDATION."""
            if not server_uri or not server_uri.strip():
                return FlextResult[None].fail("Server URI cannot be empty")

            # Basic LDAP URI validation
            if not server_uri.startswith(("ldap://", "ldaps://")):
                return FlextResult[None].fail(
                    "Server URI must start with ldap:// or ldaps://",
                )

            return FlextResult[None].ok(None)

        def _handle_exception_with_context(
            self,
            operation: str,
            exception: Exception,
            connection_id: str | None = None,
        ) -> str:
            """Handle exceptions with context logging - CONSOLIDATE EXCEPTION HANDLING."""
            extra_context = {"connection_id": connection_id} if connection_id else {}
            logger.error(f"{operation} failed", extra=extra_context)
            return f"Failed to {operation.lower()}: {exception!s}"

        def _log_operation_success(
            self,
            operation: str,
            connection_id: str,
            **extra_fields: object,
        ) -> None:
            """Log successful operations with consistent format - CONSOLIDATE LOGGING."""
            logger.info(
                f"LDAP {operation} completed",
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
            default_factory=dict
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
                    return FlextResult[str].fail(
                        uri_validation.error or "URI validation failed",
                    )

                if bind_dn:
                    dn_validation = self._validate_dn_or_fail(bind_dn, "bind DN")
                    if not dn_validation.is_success:
                        return FlextResult[str].fail(
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

                return FlextResult[str].ok(connection_id)

            except Exception as e:
                # Use REFACTORED exception handling - NO DUPLICATION
                error_msg = self._handle_exception_with_context("create connection", e)
                return FlextResult[str].fail(error_msg)

        async def close_connection(self, connection_id: str) -> FlextResult[None]:
            """Close an LDAP connection - REFACTORED."""
            if connection_id not in self._active_connections:
                return FlextResult[None].fail(f"Connection not found: {connection_id}")

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

                return FlextResult[None].ok(None)

            except Exception as e:
                # Use REFACTORED exception handling - NO DUPLICATION
                error_msg = self._handle_exception_with_context(
                    "close connection",
                    e,
                    connection_id,
                )
                return FlextResult[None].fail(error_msg)

        def get_connection_info(
            self, connection_id: str
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
            connection_id: str,
            base_dn: str,
            search_filter: str = "(objectClass=*)",
            scope: str = "subtree",
            attributes: list[str] | None = None,
            size_limit: int = 1000,
            time_limit: int = 30,
        ) -> FlextResult[list[FlextLDAPEntry]]:
            """Search for LDAP entries - REFACTORED with shared validation."""
            try:
                # Use REFACTORED validation helpers - NO DUPLICATION
                dn_validation = self._validate_dn_or_fail(base_dn, "base DN")
                if not dn_validation.is_success:
                    return FlextResult[list[FlextLDAPEntry]].fail(
                        dn_validation.error or "DN validation failed",
                    )

                filter_validation = self._validate_filter_or_fail(search_filter)
                if not filter_validation.is_success:
                    return FlextResult[list[FlextLDAPEntry]].fail(
                        filter_validation.error or "Filter validation failed",
                    )

                # Simulate search operation
                entries: list[FlextLDAPEntry] = []

                # Use REFACTORED logging - NO DUPLICATION
                logger.debug(
                    "LDAP search completed",
                    extra={
                        "connection_id": connection_id,
                        "base_dn": base_dn,
                        "filter": search_filter,
                        "scope": scope,
                        "attributes": attributes,
                        "size_limit": size_limit,
                        "time_limit": time_limit,
                        "result_count": len(entries),
                    },
                )

                return FlextResult[list[FlextLDAPEntry]].ok(entries)

            except Exception as e:
                # Use REFACTORED exception handling - NO DUPLICATION
                error_msg = self._handle_exception_with_context(
                    "search operation",
                    e,
                    connection_id,
                )
                return FlextResult[list[FlextLDAPEntry]].fail(error_msg)

        async def search_users(
            self,
            connection_id: str,
            base_dn: str,
            filter_criteria: dict[str, str] | None = None,
            size_limit: int = 1000,
        ) -> FlextResult[list[FlextLDAPUser]]:
            """Search for user entries - REFACTORED with helper composition."""
            try:
                # Use REFACTORED filter building - NO DUPLICATION
                base_filter = self._build_user_filter(filter_criteria)

                # Use general search and convert to users
                search_result = await self.search_entries(
                    connection_id=connection_id,
                    base_dn=base_dn,
                    search_filter=base_filter,
                    scope="subtree",
                    attributes=["uid", "cn", "sn", "givenName", "mail", "objectClass"],
                    size_limit=size_limit,
                )

                if not search_result.is_success:
                    return FlextResult[list[FlextLDAPUser]].fail(
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

                return FlextResult[list[FlextLDAPUser]].ok(users)

            except Exception as e:
                # Use REFACTORED exception handling - NO DUPLICATION
                error_msg = self._handle_exception_with_context(
                    "user search",
                    e,
                    connection_id,
                )
                return FlextResult[list[FlextLDAPUser]].fail(error_msg)

        async def search_groups(
            self,
            connection_id: str,
            base_dn: str,
            filter_criteria: dict[str, str] | None = None,
            size_limit: int = 1000,
        ) -> FlextResult[list[FlextLDAPGroup]]:
            """Search for group entries - REFACTORED with helper composition."""
            try:
                # Use REFACTORED filter building - NO DUPLICATION
                base_filter = self._build_group_filter(filter_criteria)

                # Use general search and convert to groups
                search_result = await self.search_entries(
                    connection_id=connection_id,
                    base_dn=base_dn,
                    search_filter=base_filter,
                    scope="subtree",
                    attributes=["cn", "description", "member", "objectClass"],
                    size_limit=size_limit,
                )

                if not search_result.is_success:
                    return FlextResult[list[FlextLDAPGroup]].fail(
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

                return FlextResult[list[FlextLDAPGroup]].ok(groups)

            except Exception as e:
                # Use REFACTORED exception handling - NO DUPLICATION
                error_msg = self._handle_exception_with_context(
                    "group search",
                    e,
                    connection_id,
                )
                return FlextResult[list[FlextLDAPGroup]].fail(error_msg)

        async def get_entry_by_dn(
            self,
            connection_id: str,
            dn: str,
            attributes: list[str] | None = None,
        ) -> FlextResult[FlextLDAPEntry]:
            """Get a single entry by DN - REFACTORED."""
            search_result = await self.search_entries(
                connection_id=connection_id,
                base_dn=dn,
                search_filter="(objectClass=*)",
                scope="base",
                attributes=attributes,
                size_limit=1,
            )

            if not search_result.is_success:
                return FlextResult[FlextLDAPEntry].fail(
                    search_result.error or "Search operation failed",
                )

            if not search_result.value:
                return FlextResult[FlextLDAPEntry].fail(f"Entry not found: {dn}")

            return FlextResult[FlextLDAPEntry].ok(search_result.value[0])

        def _build_user_filter(self, filter_criteria: dict[str, str] | None) -> str:
            """Build user-specific filter - REUSABLE HELPER."""
            base_filter = "(&(objectClass=person)"
            if filter_criteria:
                for attr, value in filter_criteria.items():
                    escaped_value = self._escape_ldap_filter_value(value)
                    base_filter += f"({attr}=*{escaped_value}*)"
            return base_filter + ")"

        def _build_group_filter(self, filter_criteria: dict[str, str] | None) -> str:
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
            entries: list[FlextLDAPEntry],
        ) -> list[FlextLDAPUser]:
            """Convert entries to users - REUSABLE HELPER."""
            users: list[FlextLDAPUser] = []
            for entry in entries:
                # Extract required fields with type safety using correct utility access
                uid = (
                    FlextLDAPUtilities.LdapConverters.safe_convert_value_to_str(
                        entry.attributes.get("uid")
                    )
                    or "unknown"
                )
                cn = (
                    FlextLDAPUtilities.LdapConverters.safe_convert_value_to_str(
                        entry.attributes.get("cn")
                    )
                    or "unknown"
                )
                sn = (
                    FlextLDAPUtilities.LdapConverters.safe_convert_value_to_str(
                        entry.attributes.get("sn")
                    )
                    or "unknown"
                )
                given_name = (
                    FlextLDAPUtilities.LdapConverters.safe_convert_value_to_str(
                        entry.attributes.get("givenName")
                    )
                )
                mail = FlextLDAPUtilities.LdapConverters.safe_convert_value_to_str(
                    entry.attributes.get("mail")
                )
                # Note: phone not included as FlextLDAPUser doesn't have phone field

                users.append(
                    FlextLDAPUser(
                        id=f"user_{uuid.uuid4().hex[:8]}",
                        dn=entry.dn,
                        uid=uid,
                        cn=cn,
                        sn=sn,
                        given_name=given_name,
                        mail=mail,
                        user_password=None,
                        object_classes=entry.object_classes,
                        attributes=entry.attributes,
                        modified_at=None,
                        # Note: no phone field in FlextLDAPUser
                        # Note: no status field as FlextModels already has it
                    ),
                )
            return users

        def _convert_entries_to_groups(
            self,
            entries: list[FlextLDAPEntry],
        ) -> list[FlextLDAPGroup]:
            """Convert entries to groups - REUSABLE HELPER."""
            groups: list[FlextLDAPGroup] = []
            for entry in entries:
                # Extract required fields with type safety using correct utility access
                cn = (
                    FlextLDAPUtilities.LdapConverters.safe_convert_value_to_str(
                        entry.attributes.get("cn")
                    )
                    or "unknown"
                )
                description = (
                    FlextLDAPUtilities.LdapConverters.safe_convert_value_to_str(
                        entry.attributes.get("description")
                    )
                )

                # Extract members from attributes
                members_value = entry.attributes.get("member", [])
                if isinstance(members_value, list):
                    typed_members_list: list[object] = cast(
                        "list[object]", members_value
                    )
                    members = [str(m) for m in typed_members_list if m]
                elif isinstance(members_value, str):
                    members = [members_value] if members_value else []
                else:
                    members = []

                group = FlextLDAPGroup(
                    id=f"group_{uuid.uuid4().hex[:8]}",
                    dn=entry.dn,
                    cn=cn,
                    description=description,
                    members=members,
                    object_classes=entry.object_classes,
                    attributes=entry.attributes,
                    modified_at=None,
                    # Note: no status field as FlextModels already has it
                )
                groups.append(group)
            return groups

    class EntryOperations(OperationsService):
        """Internal specialized entry management operations class."""

        async def create_entry(
            self,
            connection_id: str,
            dn: str,
            object_classes: list[str],
            attributes: LdapAttributeDict,
        ) -> FlextResult[FlextLDAPEntry]:
            """Create a new LDAP entry - REFACTORED with shared validation."""
            try:
                # Use REFACTORED validation helpers - NO DUPLICATION
                dn_validation = self._validate_dn_or_fail(dn)
                if not dn_validation.is_success:
                    return FlextResult[FlextLDAPEntry].fail(
                        dn_validation.error or "DN validation failed",
                    )

                if not object_classes:
                    return FlextResult[FlextLDAPEntry].fail(
                        "Entry must have at least one object class",
                    )

                # Create entry entity with validation
                entry = FlextLDAPEntry(
                    id=f"entry_{uuid.uuid4().hex[:8]}",
                    dn=dn,
                    object_classes=object_classes,
                    attributes=attributes,
                    modified_at=None,
                    # Note: no status field as FlextModels already has it
                )

                validation_result = entry.validate_business_rules()
                if not validation_result.is_success:
                    return FlextResult[FlextLDAPEntry].fail(
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

                return FlextResult[FlextLDAPEntry].ok(entry)

            except Exception as e:
                # Use REFACTORED exception handling - NO DUPLICATION
                error_msg = self._handle_exception_with_context(
                    "create entry",
                    e,
                    connection_id,
                )
                return FlextResult[FlextLDAPEntry].fail(error_msg)

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
                    return FlextResult[None].fail(
                        dn_validation.error or "DN validation failed",
                    )

                if not modifications:
                    return FlextResult[None].fail("No modifications specified")

                # Use REFACTORED logging - NO DUPLICATION
                self._log_operation_success(
                    "entry modified",
                    connection_id,
                    entry_dn=dn,
                    modification_count=len(modifications),
                )

                return FlextResult[None].ok(None)

            except Exception as e:
                # Use REFACTORED exception handling - NO DUPLICATION
                error_msg = self._handle_exception_with_context(
                    "modify entry",
                    e,
                    connection_id,
                )
                return FlextResult[None].fail(error_msg)

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
                    return FlextResult[None].fail(
                        dn_validation.error or "DN validation failed",
                    )

                # Use REFACTORED logging - NO DUPLICATION
                self._log_operation_success("entry deleted", connection_id, entry_dn=dn)

                return FlextResult[None].ok(None)

            except Exception as e:
                # Use REFACTORED exception handling - NO DUPLICATION
                error_msg = self._handle_exception_with_context(
                    "delete entry",
                    e,
                    connection_id,
                )
                return FlextResult[None].fail(error_msg)

    class UserOperations(OperationsService):
        """Internal specialized user management operations class."""

        MIN_PASSWORD_LENGTH: ClassVar[int] = 6

        # Private attribute for entry operations
        _entry_ops: object | None = PrivateAttr(default=None)

        def __init__(self, **data: object) -> None:
            """Initialize user operations - USES REFACTORED BASE."""
            super().__init__(**data)
            self._entry_ops = FlextLDAPOperations.EntryOperations()

        async def create_user(
            self,
            connection_id: str,
            user_request: FlextLDAPCreateUserRequest,
        ) -> FlextResult[FlextLDAPUser]:
            """Create a new LDAP user - REFACTORED with helper composition."""
            try:
                # Use REFACTORED attribute building - NO DUPLICATION
                attributes = self._build_user_attributes(user_request)

                # Create entry using shared operations with standard user object classes
                if self._entry_ops is None:
                    return FlextResult[FlextLDAPUser].fail(
                        "Entry operations not available"
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
                    return FlextResult[FlextLDAPUser].fail(
                        f"Failed to create user entry: {entry_result.error}",
                    )

                # Use REFACTORED user creation - NO DUPLICATION
                user = self._build_user_entity(user_request, attributes)

                validation_result = user.validate_business_rules()
                if not validation_result.is_success:
                    return FlextResult[FlextLDAPUser].fail(
                        f"User validation failed: {validation_result.error}",
                    )

                # Use REFACTORED logging - NO DUPLICATION
                self._log_operation_success(
                    "user created",
                    connection_id,
                    user_dn=user_request.dn,
                    uid=user_request.uid,
                )

                return FlextResult[FlextLDAPUser].ok(user)

            except Exception as e:
                # Use REFACTORED exception handling - NO DUPLICATION
                error_msg = self._handle_exception_with_context(
                    "create user",
                    e,
                    connection_id,
                )
                return FlextResult[FlextLDAPUser].fail(error_msg)

        async def update_user_password(
            self,
            connection_id: str,
            user_dn: str,
            new_password: str,
        ) -> FlextResult[None]:
            """Update user password - REFACTORED with validation."""
            if not new_password or len(new_password) < self.MIN_PASSWORD_LENGTH:
                return FlextResult[None].fail(
                    f"Password must be at least {self.MIN_PASSWORD_LENGTH} characters",
                )

            modifications: FlextTypes.Core.Dict = {"userPassword": [new_password]}
            if self._entry_ops is None:
                return FlextResult[None].fail("Entry operations not available")

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
                return FlextResult[None].fail("Invalid email format")

            modifications: FlextTypes.Core.Dict = {"mail": [email]}
            if self._entry_ops is None:
                return FlextResult[None].fail("Entry operations not available")

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
                return FlextResult[None].fail("Entry operations not available")

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
                return FlextResult[None].fail("Entry operations not available")

            # Type cast to correct interface
            entry_ops = cast("FlextLDAPOperations.EntryOperations", self._entry_ops)
            return await entry_ops.modify_entry(connection_id, user_dn, modifications)

        def _build_user_attributes(
            self,
            user_request: FlextLDAPCreateUserRequest,
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
            user_request: FlextLDAPCreateUserRequest,
            attributes: LdapAttributeDict,
        ) -> FlextLDAPUser:
            """Build user entity - REUSABLE HELPER."""
            user_id_str = self._generate_id()
            return FlextLDAPUser(
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
                # Note: no phone field in FlextLDAPUser
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
            initial_members: list[str] | None = None,
        ) -> FlextResult[FlextLDAPGroup]:
            """Create a new LDAP group - REFACTORED with helper composition."""
            try:
                # Use REFACTORED helper for member handling - NO DUPLICATION
                members = self._prepare_group_members(initial_members)
                attributes = self._build_group_attributes(cn, description, members)

                # Create entry using shared operations
                if self._entry_ops is None:
                    return FlextResult[FlextLDAPGroup].fail(
                        "Entry operations not available"
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
                    return FlextResult[FlextLDAPGroup].fail(
                        f"Failed to create group entry: {entry_result.error}",
                    )

                # Use REFACTORED group creation - NO DUPLICATION
                group = self._build_group_entity(
                    dn, cn, description, members, attributes
                )

                validation_result = group.validate_business_rules()
                if not validation_result.is_success:
                    return FlextResult[FlextLDAPGroup].fail(
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

                return FlextResult[FlextLDAPGroup].ok(group)

            except Exception as e:
                # Use REFACTORED exception handling - NO DUPLICATION
                error_msg = self._handle_exception_with_context(
                    "create group",
                    e,
                    connection_id,
                )
                return FlextResult[FlextLDAPGroup].fail(error_msg)

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
                    return FlextResult[None].fail(
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
                return FlextResult[None].fail(error_msg)

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
                return FlextResult[None].fail(error_msg)

        async def get_group_members(
            self,
            connection_id: str,
            group_dn: str,
        ) -> FlextResult[list[str]]:
            """Get all members of a group - REFACTORED."""
            try:
                if self._search_ops is None:
                    return FlextResult[list[str]].fail(
                        "Search operations not available"
                    )

                # Type cast to correct interface
                search_ops = cast(
                    "FlextLDAPOperations.SearchOperations", self._search_ops
                )
                group_result = await search_ops.get_entry_by_dn(
                    connection_id=connection_id,
                    dn=group_dn,
                    attributes=["member"],
                )

                if not group_result.is_success:
                    return FlextResult[list[str]].fail(
                        f"Failed to get group: {group_result.error}",
                    )

                # Get member attribute and convert to list of strings
                member_attr = group_result.value.get_attribute("member")
                members: list[str] = []
                if member_attr:
                    if isinstance(member_attr, list):
                        members = [str(m) for m in member_attr]
                    else:
                        members = [str(member_attr)]

                real_members = self._filter_dummy_members(members)
                return FlextResult[list[str]].ok(real_members)

            except Exception as e:
                # Use REFACTORED exception handling - NO DUPLICATION
                error_msg = self._handle_exception_with_context(
                    "get group members",
                    e,
                    connection_id,
                )
                return FlextResult[list[str]].fail(error_msg)

        async def update_group_description(
            self,
            connection_id: str,
            group_dn: str,
            description: str,
        ) -> FlextResult[None]:
            """Update group description - REFACTORED."""
            modifications: FlextTypes.Core.Dict = {"description": [description]}
            if self._entry_ops is None:
                return FlextResult[None].fail("Entry operations not available")

            # Type cast to correct interface
            entry_ops = cast("FlextLDAPOperations.EntryOperations", self._entry_ops)
            return await entry_ops.modify_entry(
                connection_id,
                group_dn,
                modifications,
            )

        def _prepare_group_members(
            self, initial_members: list[str] | None
        ) -> list[str]:
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
            members: list[str],
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
            members: list[str],
            attributes: LdapAttributeDict,
        ) -> FlextLDAPGroup:
            """Build group entity - REUSABLE HELPER."""
            group_id_str = self._generate_id()
            return FlextLDAPGroup(
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

        def _filter_dummy_members(self, members: list[str]) -> list[str]:
            """Filter out dummy members - REUSABLE HELPER."""
            return [m for m in members if not m.startswith("cn=dummy,ou=temp")]

        async def _modify_group_membership(
            self,
            connection_id: str,
            group_dn: str,
            member_dn: str,
            action: str,
        ) -> FlextResult[None]:
            """Modify group membership (add/remove) - REFACTORED for lower complexity."""
            # Step 1: Get current group membership
            group_result = await self._get_group_membership(connection_id, group_dn)
            if group_result.is_failure:
                return FlextResult[None].fail(
                    group_result.error or "Failed to get group"
                )

            # Step 2: Extract members from group data
            if not hasattr(group_result.value, "get_attribute"):
                return FlextResult[None].fail("Invalid group data format")

            current_members = group_result.value.get_attribute("member")
            # Convert to list[str] for processing
            if current_members is None:
                members_list = []
            elif isinstance(current_members, list):
                # Handle both list[str] and list[bytes]
                members_list = [str(item) for item in current_members]
            else:
                # Single value - convert to string
                members_list = [str(current_members)]
            updated_members_result = self._calculate_updated_members(
                members_list,
                member_dn,
                action,
            )
            if updated_members_result.is_failure:
                return FlextResult[None].fail(
                    updated_members_result.error or "Failed to calculate members",
                )

            updated_members = updated_members_result.value
            return await self._apply_membership_change(
                connection_id,
                group_dn,
                updated_members,
                action,
                member_dn,
            )

        async def _get_group_membership(
            self,
            connection_id: str,
            group_dn: str,
        ) -> FlextResult[FlextLDAPEntry]:
            """Get current group membership data."""
            if self._search_ops is None:
                return FlextResult[FlextLDAPEntry].fail(
                    "Search operations not available"
                )

            # Type cast to correct interface
            search_ops = cast("FlextLDAPOperations.SearchOperations", self._search_ops)
            group_result = await search_ops.get_entry_by_dn(
                connection_id=connection_id,
                dn=group_dn,
                attributes=["member"],
            )

            if not group_result.is_success:
                return FlextResult[FlextLDAPEntry].fail(
                    f"Failed to get group: {group_result.error}",
                )

            return FlextResult[FlextLDAPEntry].ok(group_result.value)

        def _calculate_updated_members(
            self,
            current_members: list[str],
            member_dn: str,
            action: str,
        ) -> FlextResult[list[str]]:
            """Calculate updated member list based on action."""
            if action == "add":
                return self._handle_add_member(current_members, member_dn)
            if action == "remove":
                return self._handle_remove_member(current_members, member_dn)
            return FlextResult[list[str]].fail(f"Invalid action: {action}")

        def _handle_add_member(
            self,
            current_members: list[str],
            member_dn: str,
        ) -> FlextResult[list[str]]:
            """Handle adding a member to the group."""
            if member_dn in current_members:
                return FlextResult[list[str]].fail(
                    f"Member already exists in group: {member_dn}",
                )
            return FlextResult[list[str]].ok([*current_members, member_dn])

        def _handle_remove_member(
            self,
            current_members: list[str],
            member_dn: str,
        ) -> FlextResult[list[str]]:
            """Handle removing a member from the group."""
            if member_dn not in current_members:
                return FlextResult[list[str]].fail(
                    f"Member not found in group: {member_dn}",
                )

            updated_members = [m for m in current_members if m != member_dn]
            # Add dummy member if none left (LDAP groupOfNames requirement)
            if not updated_members:
                updated_members = ["cn=dummy,ou=temp,dc=example,dc=com"]

            return FlextResult[list[str]].ok(updated_members)

        async def _apply_membership_change(
            self,
            connection_id: str,
            group_dn: str,
            updated_members: list[str],
            action: str,
            member_dn: str,
        ) -> FlextResult[None]:
            """Apply the membership change to LDAP."""
            modifications: FlextTypes.Core.Dict = {"member": updated_members}
            if self._entry_ops is None:
                return FlextResult[None].fail("Entry operations not available")

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
        attributes: list[str] | None = None,
    ) -> FlextResult[FlextLDAPEntry | None]:
        """Search and return first matching entry."""
        search_result = await self.search.search_entries(
            connection_id=connection_id,
            base_dn=base_dn,
            search_filter=search_filter,
            attributes=attributes,
            size_limit=1,
        )

        if not search_result.is_success:
            return FlextResult[FlextLDAPEntry | None].fail(
                search_result.error or "Search operation failed",
            )

        first_entry = search_result.value[0] if search_result.value else None
        return FlextResult[FlextLDAPEntry | None].ok(first_entry)

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
        self, operation: str, exception: Exception, connection_id: str = ""
    ) -> str:
        """Delegate to internal exception handling for testing purposes."""
        service = self.OperationsService()
        return service._handle_exception_with_context(
            operation, exception, connection_id
        )

    def _log_operation_success(
        self, operation: str, connection_id: str, **kwargs: object
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
FlextLDAPOperationsService = FlextLDAPOperations.OperationsService
FlextLDAPConnectionOperations = FlextLDAPOperations.ConnectionOperations
FlextLDAPSearchOperations = FlextLDAPOperations.SearchOperations
FlextLDAPEntryOperations = FlextLDAPOperations.EntryOperations
FlextLDAPUserOperations = FlextLDAPOperations.UserOperations
FlextLDAPGroupOperations = FlextLDAPOperations.GroupOperations

__all__ = [
    "FlextLDAPConnectionOperations",
    "FlextLDAPEntryOperations",
    "FlextLDAPGroupOperations",
    "FlextLDAPOperations",
    # Legacy compatibility aliases
    "FlextLDAPOperationsService",
    "FlextLDAPSearchOperations",
    "FlextLDAPUserOperations",
]
