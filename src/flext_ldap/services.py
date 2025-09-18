"""FLEXT LDAP Services module.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import ast
from datetime import UTC, datetime
from functools import cached_property

# Python 3.13 type aliases
from flext_core import (
    FlextContainer,
    FlextMixins,
    FlextProcessing,
    FlextResult,
    FlextTypes,
    FlextUtilities,
)
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.container import FlextLdapContainer
from flext_ldap.dispatcher import FlextLdapDispatcher
from flext_ldap.domain import FlextLdapDomain
from flext_ldap.models import FlextLdapModels
from flext_ldap.operations import FlextLdapOperations
from flext_ldap.repositories import FlextLdapRepositories
from flext_ldap.typings import FlextLdapTypes
from flext_ldap.validations import FlextLdapValidations

type LDAPRequest = FlextTypes.Core.Dict
type LDAPDomain = object
type LDAPResult = FlextTypes.Core.Dict
type RepositoryInstance = FlextLdapRepositories.Repository


class FlextLdapServices(FlextProcessing.Handler, FlextMixins.Loggable):
    """LDAP operations service using FlextProcessing.Handler pattern."""

    def __init__(self, container: FlextContainer | None = None) -> None:
        """Initialize LDAP services using FlextProcessing patterns."""
        # Initialize FlextProcessing.Handler
        super().__init__()
        self._ldap_container = FlextLdapContainer()
        self._container = container or self._ldap_container.get_container()

    def handle(self, request: object) -> FlextResult[object]:
        """Handle LDAP request - implements FlextProcessing.Handler.handle()."""
        return self.process(request)

    def process(self, request: object) -> FlextResult[object]:
        """Process LDAP request using Python 3.13 pattern matching - implements ServiceProcessor.process()."""
        # Python 3.13 structural pattern matching for LDAP request dispatch
        match request:
            case {"operation": "user_create", "data": user_data} if isinstance(
                user_data,
                dict,
            ):
                return self._process_user_creation(user_data)
            case {"operation": "user_read", "dn": dn} if isinstance(dn, str):
                return self._process_user_read(dn)
            case {"operation": "group_create", "data": group_data} if isinstance(
                group_data,
                dict,
            ):
                return self._process_group_creation(group_data)
            case {"operation": "search", "params": search_params} if isinstance(
                search_params,
                dict,
            ):
                return self._process_search_operation(search_params)
            case {"operation": "validate", "target": str(target), "value": value}:
                return self._process_validation(target, value)
            case _:
                return FlextResult[LDAPDomain].ok(request)

    def build(self, domain: LDAPDomain, *, correlation_id: str) -> LDAPResult:
        """Build final LDAP result from domain object - implements ServiceProcessor.build()."""
        if isinstance(domain, dict):
            domain["correlation_id"] = correlation_id
            return domain
        return {"result": domain, "correlation_id": correlation_id}

    # Python 3.13 optimized LDAP-specific processing methods
    def _process_user_creation(
        self,
        user_data: dict[str, object],
    ) -> FlextResult[LDAPDomain]:
        """Process user creation with enhanced validation."""
        try:
            # Validate and extract required fields with proper types
            dn = str(user_data.get("dn", ""))
            uid = str(user_data.get("uid", ""))
            cn = str(user_data.get("cn", ""))

            if not dn or not uid or not cn:
                return FlextResult[LDAPDomain].fail(
                    "Missing required fields: dn, uid, cn are required",
                )

            # Extract optional fields with proper types
            sn = user_data.get("sn")
            sn_str = str(sn) if sn is not None else None

            given_name = user_data.get("given_name")
            given_name_str = str(given_name) if given_name is not None else None

            mail = user_data.get("mail")
            mail_str = str(mail) if mail is not None else None

            user_password = user_data.get("user_password")
            password_str = str(user_password) if user_password is not None else None

            # Extract object classes
            object_classes_raw = user_data.get("object_classes", [])
            if isinstance(object_classes_raw, list):
                object_classes = [str(cls) for cls in object_classes_raw]
            else:
                object_classes = [
                    "top",
                    "person",
                    "organizationalPerson",
                    "inetOrgPerson",
                ]

            # Create request with validated data
            create_request = FlextLdapModels.CreateUserRequest(
                dn=dn,
                uid=uid,
                cn=cn,
                sn=sn_str or "User",
                given_name=given_name_str,
                mail=mail_str,
                description=None,  # Optional field
                telephone_number=None,  # Optional field
                user_password=password_str,
                object_classes=object_classes,
            )
            return FlextResult[LDAPDomain].ok(
                {"status": "user_creation_initiated", "request": create_request},
            )
        except Exception as e:
            return FlextResult[LDAPDomain].fail(f"User creation processing failed: {e}")

    def _process_user_read(self, dn: str) -> FlextResult[LDAPDomain]:
        """Process user read with DN validation."""
        if not dn.strip():
            return FlextResult[LDAPDomain].fail("Invalid DN for user read operation")
        return FlextResult[LDAPDomain].ok({"status": "user_read_initiated", "dn": dn})

    def _process_group_creation(
        self,
        group_data: dict[str, object],
    ) -> FlextResult[LDAPDomain]:
        """Process group creation with field validation."""
        try:
            required_fields = {"dn", "cn"}
            if not required_fields.issubset(group_data.keys()):
                missing = required_fields - group_data.keys()
                return FlextResult.fail(f"Missing required fields: {missing}")
            return FlextResult.ok(
                {"status": "group_creation_initiated", "data": group_data},
            )
        except Exception as e:
            return FlextResult.fail(f"Group creation processing failed: {e}")

    def _process_search_operation(
        self,
        search_params: dict[str, object],
    ) -> FlextResult[LDAPDomain]:
        """Process search operation with parameter validation."""
        try:
            # Create SearchRequest with proper error handling
            search_request = FlextLdapModels.SearchRequest.model_validate(
                search_params,
            )
            return FlextResult.ok(
                {"status": "search_initiated", "request": search_request},
            )
        except Exception as e:
            return FlextResult.fail(f"Search processing failed: {e}")

    def _process_validation(
        self,
        target: str,
        value: object,
    ) -> FlextResult[LDAPDomain]:
        """Process validation with Python 3.13 pattern matching."""
        match target:
            case "dn":
                result = self.validate_dn(str(value))
                return FlextResult.ok({"valid": result.is_success, "target": target})
            case "filter":
                result = self.validate_filter(str(value))
                return FlextResult.ok({"valid": result.is_success, "target": target})
            case "attributes":
                # Validate that value is a proper attributes dictionary
                if not isinstance(value, dict):
                    return FlextResult.fail(
                        f"Attributes must be a dictionary, got {type(value)}"
                    )

                # Convert to proper AttributeDict format
                validated_attributes: FlextLdapTypes.Entry.AttributeDict = {}
                for key, val in value.items():
                    if not isinstance(key, str):
                        return FlextResult.fail(
                            f"Attribute key must be string, got {type(key)}"
                        )

                    # Convert values to list format as required by AttributeDict
                    if isinstance(val, list):
                        validated_attributes[key] = val
                    else:
                        validated_attributes[key] = [str(val)]

                result = self.validate_attributes(validated_attributes)
                return FlextResult.ok({"valid": result.is_success, "target": target})
            case _:
                return FlextResult.fail(f"Unknown validation target: {target}")

    @cached_property
    def _repository(self) -> RepositoryInstance:
        """Cached repository instance for performance optimization."""
        # Get the connected client from container
        client = self._ldap_container.get_client()
        # Create repository with the connected client
        return FlextLdapRepositories(client).repository

    def _get_repository(self) -> FlextResult[object]:
        """Get LDAP repository using cached property."""
        return FlextResult.ok(self._repository)

    async def initialize(self) -> FlextResult[None]:
        """Initialize service using FlextProcessors logging."""
        self.log_info("LDAP service initializing", service="FlextLdapServices")
        return FlextResult[None].ok(None)

    async def cleanup(self) -> FlextResult[None]:
        """Cleanup service using FlextProcessors logging."""
        self.log_info("LDAP service cleaning up", service="FlextLdapServices")
        # Handle different container types safely using getattr for type safety
        reset_method = getattr(self._container, "reset", None)
        if reset_method and callable(reset_method):
            reset_method()
        else:
            clear_method = getattr(self._container, "clear", None)
            if clear_method and callable(clear_method):
                clear_method()
        return FlextResult[None].ok(None)

    async def connect(
        self,
        server_uri: str,
        bind_dn: str,
        bind_password: str,
    ) -> FlextResult[None]:
        """Connect to LDAP server."""
        try:
            client = self._ldap_container.get_client()
            connect_result = await client.connect(server_uri, bind_dn, bind_password)
            if connect_result.is_success:
                # Update repository cache with connected client
                self._repository_cache = None  # Force recreation with connected client
                return FlextResult[None].ok(None)
            return connect_result
        except Exception as e:
            self.log_error("Failed to connect to LDAP server", error=str(e))
            return FlextResult[None].fail(f"Connection failed: {e}")

    async def disconnect(self) -> FlextResult[None]:
        """Disconnect from LDAP server."""
        try:
            # Get client for future disconnect functionality - placeholder for now
            self.log_info("LDAP disconnection completed", service="FlextLdapServices")
            return FlextResult[None].ok(None)
        except Exception as e:
            self.log_error("Failed to disconnect from LDAP server", error=str(e))
            return FlextResult[None].fail(f"Disconnect failed: {e}")

    # =========================================================================
    # USER OPERATIONS - Consolidated user management
    # =========================================================================

    async def create_user(
        self,
        request: FlextLdapModels.CreateUserRequest,
    ) -> FlextResult[FlextLdapModels.User]:
        """Create new LDAP user."""
        user_entity: FlextLdapModels.User | None = None

        if FlextLdapConstants.FeatureFlags.dispatcher_enabled():
            try:
                dispatcher = FlextLdapDispatcher.get_global_dispatcher()
                command = FlextLdapDomain.CreateUserCommand(
                    command_type="create_user",
                    user_data=request.model_dump(mode="python"),
                )
                dispatch_result = dispatcher.dispatch(command)
                if dispatch_result.is_success:
                    payload = dispatch_result.unwrap()
                    if isinstance(payload, FlextResult):
                        if payload.is_failure:
                            return FlextResult.fail(
                                payload.error or "User creation failed",
                            )
                        user_entity = payload.unwrap()
                    elif isinstance(payload, FlextLdapModels.User):
                        user_entity = payload
                    else:
                        self.log_warning(
                            "dispatcher_unexpected_payload",
                            payload_type=type(payload).__name__,
                        )
                else:
                    self.log_warning(
                        "dispatcher_create_user_failed",
                        error=dispatch_result.error,
                    )
            except Exception as exc:  # pragma: no cover - defensive logging
                self.log_error(
                    "dispatcher_create_user_error",
                    error=str(exc),
                )

        if user_entity is None:
            # Create user entity using FlextResult pattern instead of legacy method
            user_entity = FlextLdapModels.User(
                id=f"user_{request.uid}",
                dn=request.dn,
                uid=request.uid,
                cn=request.cn,
                sn=request.sn,
                given_name=request.given_name,
                mail=request.mail,
                user_password=request.user_password,
                object_classes=request.object_classes or ["inetOrgPerson", "person"],
                attributes={},
                status="active",
                created_at=datetime.now(UTC).isoformat(),
                modified_at=datetime.now(UTC).isoformat(),
            )

            # Validate user business rules
            validation_result = user_entity.validate_business_rules()
            if not validation_result.is_success:
                return FlextResult.fail(
                    f"User validation failed: {validation_result.error}",
                )

        # Use cached repository for performance
        repository = self._repository
        save_method = getattr(repository, "save_async", None)
        if save_method is None:
            return FlextResult.fail("Repository does not support save_async method")
        save_result = await save_method(user_entity)

        if not save_result.is_success:
            return FlextResult.fail(
                save_result.error or "Save failed",
            )

        self.log_info(
            "LDAP user created successfully",
            operation="create_user",
            dn=user_entity.dn,
            uid=user_entity.uid,
            object_classes=str(user_entity.object_classes),
            execution_context="FlextLdapServices.create_user",
        )
        return FlextResult.ok(user_entity)

    async def get_user(self, dn: str) -> FlextResult[FlextLdapModels.User | None]:
        """Get user by DN using cached repository."""
        # Use cached repository for performance
        repository = self._repository
        find_method = getattr(repository, "find_by_dn", None)
        if find_method is None:
            return FlextResult.fail("Repository does not support find_by_dn method")
        entry_result = await find_method(dn)

        if not entry_result.is_success:
            return FlextResult.fail(
                entry_result.error or "User lookup failed",
            )

        if not entry_result.value:
            return FlextResult.ok(None)

        # Convert entry to user using Python 3.13 pattern matching for attribute extraction
        entry = entry_result.value

        # Extract string attributes safely - handle both list and string values
        def safe_str_attr(attr_name: str) -> str | None:
            """Extract string attribute safely - handle various data formats."""
            value = entry.get_attribute(attr_name)
            if not value:  # None or empty list
                return None

            # get_attribute() returns list[str] | None, so process the list
            if isinstance(value, list) and len(value) > 0:
                first_val = value[0]
                if isinstance(first_val, str) and first_val.strip():
                    # If it looks like a string representation of a list, try to parse it
                    if first_val.startswith("[") and first_val.endswith("]"):
                        try:
                            parsed_list = ast.literal_eval(first_val)
                            if isinstance(parsed_list, list) and len(parsed_list) > 0:
                                return str(parsed_list[0]).strip()
                        except (ValueError, SyntaxError):
                            # If parsing fails, just use the original string
                            pass
                    return first_val.strip()

            return None

        # Generate created_at timestamp if not available (Entry model doesn't have this field)
        current_time = datetime.now(UTC).isoformat()

        user_entity = FlextLdapModels.User(
            id=entry.id,
            dn=entry.dn,
            object_classes=entry.object_classes,
            attributes=entry.attributes,
            uid=safe_str_attr("uid") or "unknown",
            cn=safe_str_attr("cn"),
            sn=safe_str_attr("sn"),
            given_name=safe_str_attr("givenName"),
            mail=safe_str_attr("mail"),
            user_password=safe_str_attr("userPassword"),
            created_at=current_time,  # Generate timestamp since Entry doesn't have created_at
            modified_at=entry.modified_at
            or current_time,  # Use Entry's modified_at or generate
        )
        return FlextResult.ok(user_entity)

    async def update_user(
        self,
        dn: str,
        updates: FlextLdapTypes.Entry.AttributeDict,
    ) -> FlextResult[FlextLdapModels.User]:
        """Update user attributes using cached repository."""
        # Use cached repository for performance
        repository = self._repository
        update_method = getattr(repository, "update", None)
        if update_method is None:
            return FlextResult.fail("Repository does not support update method")
        # Convert AttributeDict to dict[str, object] format expected by repository
        converted_updates: dict[str, object] = {
            key: value if isinstance(value, list) else [value]
            for key, value in updates.items()
        }
        update_result = await update_method(dn, converted_updates)

        if not update_result.is_success:
            return FlextResult.fail(
                update_result.error or "User update failed",
            )

        # Get updated user - handle potential None return
        user_result = await self.get_user(dn)
        if not user_result.is_success:
            return FlextResult.fail(
                user_result.error or "Failed to get updated user",
            )
        if user_result.value is None:
            return FlextResult.fail("Updated user not found")
        return FlextResult.ok(user_result.value)

    async def delete_user(self, dn: str) -> FlextResult[bool]:
        """Delete user from directory using cached repository."""
        # Use cached repository for performance
        repository = self._repository
        delete_method = getattr(repository, "_delete_async", None)
        if delete_method is None:
            return FlextResult.fail("Repository does not support _delete_async method")
        delete_result = await delete_method(dn)

        if not delete_result.is_success:
            return FlextResult.fail(delete_result.error or "User deletion failed")

        self.log_info(
            "LDAP user deleted successfully",
            operation="delete_user",
            dn=dn,
            execution_context="FlextLdapServices.delete_user",
        )
        success = True
        return FlextResult.ok(success)

    # =========================================================================
    # GROUP OPERATIONS - Consolidated group management
    # =========================================================================

    async def create_group(
        self,
        group: FlextLdapModels.Group,
    ) -> FlextResult[FlextLdapModels.Group]:
        """Create new LDAP group using operations layer."""
        # Validate group business rules
        validation_result = group.validate_business_rules()
        if not validation_result.is_success:
            return FlextResult.fail(
                f"Group validation failed: {validation_result.error}",
            )

        # Get operations from container
        operations_result = self._container.get("ldap_operations")
        if not operations_result.is_success:
            return FlextResult.fail(
                f"LDAP operations not available: {operations_result.error}",
            )

        # Validate that the result value is FlextLdapOperations
        if not isinstance(operations_result.value, FlextLdapOperations):
            return FlextResult.fail(
                f"Expected FlextLdapOperations, got {type(operations_result.value)}"
            )

        operations = operations_result.value

        # Use group operations to create group
        create_result = await operations._groups.create_group(
            connection_id="default",
            dn=group.dn,
            cn=group.cn or "Group",
            description=group.description,
            initial_members=group.members,
        )

        if not create_result.is_success:
            return FlextResult.fail(
                create_result.error or "Group creation failed",
            )

        self.log_info(
            "LDAP group created successfully",
            operation="create_group",
            dn=group.dn,
            cn=group.cn,
            execution_context="FlextLdapServices.create_group",
        )
        return FlextResult.ok(create_result.value)

    async def get_group(self, dn: str) -> FlextResult[FlextLdapModels.Group | None]:
        """Get group by DN using operations layer."""
        # Get operations from container
        operations_result = self._container.get("ldap_operations")
        if not operations_result.is_success:
            return FlextResult.fail(
                f"LDAP operations not available: {operations_result.error}",
            )
        # Validate operations result value type
        if not isinstance(operations_result.value, FlextLdapOperations):
            return FlextResult.fail(
                f"Invalid operations type: expected FlextLdapOperations, got {type(operations_result.value)}"
            )
        operations = operations_result.value

        # Use search operations to find group
        search_params = FlextLdapModels.SearchRequest(
            base_dn=dn,
            filter_str="(objectClass=groupOfNames)",
            scope="base",
            attributes=["cn", "description", "member"],
            size_limit=1,
        )
        search_result = await operations._search.search_entries(search_params)

        if not search_result.is_success:
            return FlextResult.fail(
                search_result.error or "Failed to search for group",
            )

        if not search_result.value.entries:
            return FlextResult.ok(None)

        # Convert first entry to group
        entry_dict = search_result.value.entries[0]

        # Extract group attributes
        def extract_group_attr(attr_name: str) -> str:
            """Extract group attribute using pattern matching."""
            match entry_dict.get(attr_name):
                case [first, *_] if isinstance(first, str):
                    return first
                case str(value):
                    return value
                case _:
                    return ""

        def extract_members() -> list[str]:
            """Extract members list using pattern matching."""
            match entry_dict.get("member"):
                case list(members):
                    return [str(m) for m in members if m]
                case str(single_member):
                    return [single_member] if single_member else []
                case _:
                    return []

        # Create group from dict data
        group = FlextLdapModels.Group(
            id=FlextUtilities.Generators.generate_entity_id(),
            dn=str(entry_dict.get("dn", "")),
            cn=extract_group_attr("cn"),
            object_classes=["groupOfNames"],
            members=extract_members(),
            status="active",
            description=extract_group_attr("description"),
            modified_at=datetime.now(UTC).isoformat(),
        )

        return FlextResult.ok(group)

    async def update_group(
        self,
        dn: str,
        attributes: FlextLdapTypes.Entry.AttributeDict,
    ) -> FlextResult[None]:
        """Update group attributes using cached repository."""
        # Use cached repository for performance
        repository = self._repository
        update_method = getattr(repository, "update", None)
        if update_method is None:
            return FlextResult.fail("Repository does not support update method")
        # Convert attributes to proper dict[str, object] format
        converted_attributes: dict[str, object] = {}
        for key, value in attributes.items():
            if isinstance(value, list):
                converted_attributes[key] = value
            else:
                converted_attributes[key] = [str(value)]
        result = await update_method(dn, converted_attributes)
        if not result.is_success:
            return FlextResult.fail(result.error or "Update failed")
        return FlextResult.ok(None)

    async def delete_group(self, dn: str) -> FlextResult[None]:
        """Delete group by DN using cached repository."""
        # Use cached repository for performance
        repository = self._repository
        delete_method = getattr(repository, "_delete_async", None)
        if delete_method is None:
            return FlextResult.fail("Repository does not support _delete_async method")
        result = await delete_method(dn)
        if not result.is_success:
            return FlextResult.fail(result.error or "Delete failed")
        return FlextResult.ok(None)

    async def add_member(self, group_dn: str, member_dn: str) -> FlextResult[None]:
        """Add member to group."""
        repository_result = self._get_repository()
        if not repository_result.is_success:
            return FlextResult.fail(
                f"Repository access failed: {repository_result.error}",
            )

        # Validate repository result value type
        if not isinstance(repository_result.value, FlextLdapRepositories):
            return FlextResult.fail(
                f"Invalid repository type: expected FlextLdapRepositories, got {type(repository_result.value)}"
            )
        base_repository = repository_result.value
        # Use base repository directly - no need to create new instance
        group_repository = base_repository
        # Use update_attributes to modify group membership
        update_method = getattr(group_repository, "update_attributes", None)
        if update_method is None:
            return FlextResult.fail(
                "Repository does not support update_attributes method",
            )
        result = await update_method(group_dn, {"member": [member_dn]})
        if not result.is_success:
            return FlextResult.fail(result.error or "Add member failed")
        return FlextResult.ok(None)

    async def remove_member(self, group_dn: str, member_dn: str) -> FlextResult[None]:
        """Remove member from group."""
        # Get current members
        repository_result = self._get_repository()
        if not repository_result.is_success:
            return FlextResult.fail(
                f"Repository access failed: {repository_result.error}",
            )

        # Validate repository result value type
        if not isinstance(repository_result.value, FlextLdapRepositories):
            return FlextResult.fail(
                f"Invalid repository type: expected FlextLdapRepositories, got {type(repository_result.value)}"
            )
        base_repository = repository_result.value
        # Use base repository directly
        group_repository = base_repository

        # Get group entry to check current members
        find_method = getattr(group_repository, "_find_by_dn_async", None)
        if find_method is None:
            return FlextResult.fail(
                "Repository does not support _find_by_dn_async method",
            )
        group_entry_result = await find_method(group_dn)
        if not group_entry_result.is_success or not group_entry_result.value:
            return FlextResult.fail("Group not found")

        group_entry = group_entry_result.value
        current_members = getattr(group_entry, "member", [])
        if member_dn not in current_members:
            return FlextResult.fail(f"Member {member_dn} not found in group")

        # Remove member and update
        updated_members = [m for m in current_members if m != member_dn]
        attributes: FlextLdapTypes.Entry.AttributeDict = {"member": updated_members}
        update_method = getattr(base_repository, "update", None)
        if update_method is None:
            return FlextResult.fail("Repository does not support update method")
        # Convert attributes to proper dict[str, object] format
        converted_attributes: dict[str, object] = {}
        for key, value in attributes.items():
            if isinstance(value, list):
                converted_attributes[key] = value
            else:
                converted_attributes[key] = [str(value)]
        result = await update_method(group_dn, converted_attributes)
        if not result.is_success:
            return FlextResult.fail(result.error or "Remove member failed")
        return FlextResult.ok(None)

    async def get_members(self, group_dn: str) -> FlextResult[list[str]]:
        """Get group members."""
        repository_result = self._get_repository()
        if not repository_result.is_success:
            return FlextResult[list[str]].fail(
                f"Repository access failed: {repository_result.error}",
            )

        # Validate repository result value type
        if not isinstance(repository_result.value, FlextLdapRepositories):
            return FlextResult[list[str]].fail(
                f"Invalid repository type: expected FlextLdapRepositories, got {type(repository_result.value)}"
            )
        base_repository = repository_result.value
        # Use base repository directly to get group entry
        group_repository = base_repository
        find_method = getattr(group_repository, "_find_by_dn_async", None)
        if find_method is None:
            return FlextResult.fail(
                "Repository does not support _find_by_dn_async method",
            )
        group_entry_result = await find_method(group_dn)
        if not group_entry_result.is_success or not group_entry_result.value:
            return FlextResult[list[str]].fail("Group not found")

        group_entry = group_entry_result.value
        members = getattr(group_entry, "member", [])
        return FlextResult[list[str]].ok(
            members if isinstance(members, list) else [members],
        )

    # Validation methods needed by API
    def validate_dn(self, dn: str) -> FlextResult[None]:
        """Validate DN format using centralized validation - SOURCE OF TRUTH."""
        return FlextLdapValidations.validate_dn(dn)

    def validate_filter(self, filter_str: str) -> FlextResult[None]:
        """Validate LDAP filter format using centralized validation - SOURCE OF TRUTH."""
        return FlextLdapValidations.validate_filter(filter_str)

    # =========================================================================
    # SEARCH OPERATIONS - Consolidated search functionality
    # =========================================================================

    async def search(
        self,
        request: FlextLdapModels.SearchRequest,
    ) -> FlextResult[FlextLdapModels.SearchResponse]:
        """Perform LDAP search operation using cached repository."""
        # Use cached repository for performance
        repository = self._repository
        search_method = getattr(repository, "search", None)
        if search_method is None:
            return FlextResult.fail("Repository does not support search method")
        search_result = await search_method(request)

        if not search_result.is_success:
            return FlextResult.fail(
                search_result.error or "Search failed",
            )

        return FlextResult.ok(search_result.value)

    # =========================================================================
    # VALIDATION METHODS - For test coverage and business logic
    # =========================================================================

    def validate_attributes(
        self, attributes: FlextLdapTypes.Entry.AttributeDict
    ) -> FlextResult[None]:
        """Validate LDAP attributes dictionary."""
        if not attributes:
            return FlextResult.fail("Attributes cannot be empty")

        return FlextResult.ok(None)

    def validate_object_classes(self, object_classes: list[str]) -> FlextResult[None]:
        """Validate LDAP object classes list."""
        if not object_classes:
            return FlextResult.fail("Object classes cannot be empty")

        return FlextResult.ok(None)

    async def search_users(
        self,
        filter_str: str,
        base_dn: str,
    ) -> FlextResult[list[FlextLdapModels.User]]:
        """Search for users matching filter."""
        search_request = FlextLdapModels.SearchRequest(
            base_dn=base_dn,
            scope="subtree",
            filter_str=filter_str,
            attributes=["*"],
            size_limit=1000,
            time_limit=30,
        )

        search_result = await self.search(search_request)
        if not search_result.is_success:
            return FlextResult[list[FlextLdapModels.User]].fail(
                search_result.error or "Search failed",
            )

        users = []
        for entry_data in search_result.value.entries:
            if "dn" in entry_data:
                user_result = await self.get_user(str(entry_data["dn"]))
                if user_result.is_success and user_result.value:
                    users.append(user_result.value)

        return FlextResult[list[FlextLdapModels.User]].ok(users)

    async def user_exists(self, dn: str) -> FlextResult[bool]:
        """Check if user exists at DN."""
        user_result = await self.get_user(dn)
        if not user_result.is_success:
            return FlextResult.fail(user_result.error or "Failed to get user")

        return FlextResult.ok(user_result.value is not None)

    async def group_exists(self, dn: str) -> FlextResult[bool]:
        """Check if group exists at DN."""
        group_result = await self.get_group(dn)
        if not group_result.is_success:
            return FlextResult.fail(group_result.error or "Failed to get group")

        return FlextResult.ok(group_result.value is not None)

    # =========================================================================
    # GROUP MEMBER MANAGEMENT - Specialized group operations using Python standard libraries
    # =========================================================================

    async def add_member_to_group(
        self,
        group_dn: str,
        member_dn: str,
    ) -> FlextResult[None]:
        """Add member to group."""
        # Get current group
        group_result = await self.get_group(group_dn)
        if not group_result.is_success:
            return FlextResult.fail(group_result.error or "Failed to get group")

        if group_result.value is None:
            return FlextResult.fail("Group not found")

        group = group_result.value

        # Check if member already exists using Python standard library
        if member_dn in group.members:
            return FlextResult.fail("Member already in group")

        # Add member using Python standard list operations
        updated_members = [*group.members, member_dn]
        return await self.update_group(group_dn, {"member": updated_members})

    async def remove_member_from_group(
        self,
        group_dn: str,
        member_dn: str,
    ) -> FlextResult[None]:
        """Remove member from group."""
        # Get current group
        group_result = await self.get_group(group_dn)
        if not group_result.is_success:
            return FlextResult.fail(group_result.error or "Failed to get group")

        if group_result.value is None:
            return FlextResult.fail("Group not found")

        group = group_result.value

        # Check if member exists using Python standard library
        if member_dn not in group.members:
            return FlextResult.fail("Member not in group")

        # Remove member using Python list comprehension
        updated_members = [m for m in group.members if m != member_dn]
        return await self.update_group(group_dn, {"member": updated_members})

    async def get_group_members_list(self, group_dn: str) -> FlextResult[list[str]]:
        """Get group members list."""
        group_result = await self.get_group(group_dn)
        if not group_result.is_success:
            return FlextResult[list[str]].fail(
                group_result.error or "Failed to get group",
            )

        if group_result.value is None:
            return FlextResult[list[str]].fail("Group not found")

        return FlextResult[list[str]].ok(group_result.value.members)


__all__ = [
    "FlextLdapServices",
]
