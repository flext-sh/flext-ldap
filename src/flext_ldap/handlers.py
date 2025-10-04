"""LDAP command and query handlers implementing Application.Handler protocol.

This module provides handler classes that implement the Application.Handler
protocol from flext-core. Handlers process CQRS commands and queries for LDAP
operations with proper domain-driven design.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from abc import abstractmethod
from typing import Generic, TypeVar

from flext_core import FlextLogger, FlextResult

from flext_ldap.models import FlextLdapModels
from flext_ldap.repositories import UserRepository, GroupRepository

_logger = FlextLogger(__name__)

TCommand = TypeVar("TCommand", bound=FlextLdapModels.CqrsCommand)
TQuery = TypeVar("TQuery", bound=FlextLdapModels.CqrsQuery)


class LdapCommandHandler(Generic[TCommand]):
    """Base class for LDAP command handlers implementing Application.Handler protocol.

    This class provides the foundation for LDAP command handlers, implementing
    the flext-core Application.Handler protocol through structural subtyping.
    """

    def __init__(self) -> None:
        """Initialize command handler."""
        self._logger = FlextLogger(__name__)

    def handle(self, command: TCommand) -> FlextResult[object]:
        """Handle command - implements Application.Handler protocol.

        Args:
            command: Command to handle

        Returns:
            FlextResult with command result
        """
        try:
            # Validate command
            validation_result = self._validate_command(command)
            if validation_result.is_failure:
                return FlextResult[object].fail(
                    validation_result.error or "Command validation failed"
                )

            # Execute command
            return self._execute_command(command)

        except Exception as e:
            self._logger.error(
                "Command handling failed",
                error=str(e),
                command_type=command.command_type,
                error_type=type(e).__name__,
            )
            return FlextResult[object].fail(f"Command execution failed: {e}")

    def can_handle(self, command: object) -> bool:
        """Check if handler can process command - implements Application.Handler protocol.

        Args:
            command: Command to check

        Returns:
            True if handler can process the command
        """
        return isinstance(
            command, FlextLdapModels.CqrsCommand
        ) and self._can_handle_command(command)

    def _validate_command(self, command: TCommand) -> FlextResult[None]:
        """Validate command before execution.

        Args:
            command: Command to validate

        Returns:
            FlextResult indicating validation success
        """
        if not command.command_type:
            return FlextResult[None].fail("Command type is required")

        if not isinstance(command.payload, dict):
            return FlextResult[None].fail("Command payload must be a dictionary")

        return FlextResult[None].ok(None)

    @abstractmethod
    def _can_handle_command(self, command: object) -> bool:
        """Check if this handler can process the specific command type.

        Args:
            command: Command to check

        Returns:
            True if handler can process the command
        """
        ...

    @abstractmethod
    def _execute_command(self, command: TCommand) -> FlextResult[object]:
        """Execute the command logic.

        Args:
            command: Command to execute

        Returns:
            FlextResult with execution result
        """
        ...


class LdapQueryHandler(Generic[TQuery]):
    """Base class for LDAP query handlers implementing Application.Handler protocol.

    This class provides the foundation for LDAP query handlers, implementing
    the flext-core Application.Handler protocol through structural subtyping.
    """

    def __init__(self) -> None:
        """Initialize query handler."""
        self._logger = FlextLogger(__name__)

    def handle(self, query: TQuery) -> FlextResult[object]:
        """Handle query - implements Application.Handler protocol.

        Args:
            query: Query to handle

        Returns:
            FlextResult with query result
        """
        try:
            # Validate query
            validation_result = self._validate_query(query)
            if validation_result.is_failure:
                return FlextResult[object].fail(
                    validation_result.error or "Query validation failed"
                )

            # Execute query
            return self._execute_query(query)

        except Exception as e:
            self._logger.error(
                "Query handling failed",
                error=str(e),
                query_type=query.query_type,
                error_type=type(e).__name__,
            )
            return FlextResult[object].fail(f"Query execution failed: {e}")

    def can_handle(self, query: object) -> bool:
        """Check if handler can process query - implements Application.Handler protocol.

        Args:
            query: Query to check

        Returns:
            True if handler can process the query
        """
        return isinstance(query, FlextLdapModels.CqrsQuery) and self._can_handle_query(
            query
        )

    def _validate_query(self, query: TQuery) -> FlextResult[None]:
        """Validate query before execution.

        Args:
            query: Query to validate

        Returns:
            FlextResult indicating validation success
        """
        if not query.query_type:
            return FlextResult[None].fail("Query type is required")

        if not isinstance(query.parameters, dict):
            return FlextResult[None].fail("Query parameters must be a dictionary")

        return FlextResult[None].ok(None)

    @abstractmethod
    def _can_handle_query(self, query: object) -> bool:
        """Check if this handler can process the specific query type.

        Args:
            query: Query to check

        Returns:
            True if handler can process the query
        """
        ...

    @abstractmethod
    def _execute_query(self, query: TQuery) -> FlextResult[object]:
        """Execute the query logic.

        Args:
            query: Query to execute

        Returns:
            FlextResult with execution result
        """
        ...


class CreateUserCommandHandler(LdapCommandHandler[FlextLdapModels.CqrsCommand]):
    """Handler for CreateUser commands implementing Application.Handler protocol."""

    def __init__(self) -> None:
        """Initialize CreateUser command handler."""
        super().__init__()
        self._user_repository = UserRepository()

    def _can_handle_command(self, command: object) -> bool:
        """Check if this handler can process CreateUser commands."""
        return (
            isinstance(command, FlextLdapModels.CqrsCommand)
            and command.command_type == "create_user"
        )

    def _execute_command(
        self, command: FlextLdapModels.CqrsCommand
    ) -> FlextResult[object]:
        """Execute CreateUser command.

        Expected payload:
        {
            "dn": "cn=john,ou=users,dc=example,dc=com",
            "uid": "john",
            "cn": "John Doe",
            "sn": "Doe",
            "mail": "john@example.com"
        }
        """
        payload = command.payload

        # Create user entity
        create_request = FlextLdapModels.CreateUserRequest(
            dn=payload.get("dn"),
            uid=payload.get("uid"),
            cn=payload.get("cn"),
            sn=payload.get("sn"),
            mail=payload.get("mail"),
            object_classes=payload.get(
                "object_classes", ["person", "organizationalPerson"]
            ),
        )

        # Validate request
        validation_result = create_request.validate_request()
        if validation_result.is_failure:
            return FlextResult[object].fail(
                validation_result.error or "Invalid user creation request"
            )

        # Execute via repository
        result = self._user_repository.add(create_request.to_user())
        if result.is_failure:
            return FlextResult[object].fail(result.error or "User creation failed")

        user = result.unwrap()
        self._logger.info(
            "User created successfully", user_dn=user.dn, user_uid=user.uid
        )

        return FlextResult[object].ok({"user": user, "status": "created"})


class UpdateUserCommandHandler(LdapCommandHandler[FlextLdapModels.CqrsCommand]):
    """Handler for UpdateUser commands implementing Application.Handler protocol."""

    def __init__(self) -> None:
        """Initialize UpdateUser command handler."""
        super().__init__()
        self._user_repository = UserRepository()

    def _can_handle_command(self, command: object) -> bool:
        """Check if this handler can process UpdateUser commands."""
        return (
            isinstance(command, FlextLdapModels.CqrsCommand)
            and command.command_type == "update_user"
        )

    def _execute_command(
        self, command: FlextLdapModels.CqrsCommand
    ) -> FlextResult[object]:
        """Execute UpdateUser command.

        Expected payload:
        {
            "dn": "cn=john,ou=users,dc=example,dc=com",
            "attributes": {
                "cn": "John Smith",
                "mail": "john.smith@example.com"
            }
        }
        """
        payload = command.payload
        dn = payload.get("dn")
        attributes = payload.get("attributes", {})

        if not dn:
            return FlextResult[object].fail("User DN is required")

        if not attributes:
            return FlextResult[object].fail("Attributes to update are required")

        # Get existing user
        get_result = self._user_repository.get_by_id(dn)
        if get_result.is_failure:
            return FlextResult[object].fail(get_result.error or "User lookup failed")

        user = get_result.unwrap()
        if user is None:
            return FlextResult[object].fail("User not found")

        # Update user attributes
        update_result = self._user_repository.update(user)
        if update_result.is_failure:
            return FlextResult[object].fail(update_result.error or "User update failed")

        updated_user = update_result.unwrap()
        self._logger.info("User updated successfully", user_dn=updated_user.dn)

        return FlextResult[object].ok({"user": updated_user, "status": "updated"})


class DeleteUserCommandHandler(LdapCommandHandler[FlextLdapModels.CqrsCommand]):
    """Handler for DeleteUser commands implementing Application.Handler protocol."""

    def __init__(self) -> None:
        """Initialize DeleteUser command handler."""
        super().__init__()
        self._user_repository = UserRepository()

    def _can_handle_command(self, command: object) -> bool:
        """Check if this handler can process DeleteUser commands."""
        return (
            isinstance(command, FlextLdapModels.CqrsCommand)
            and command.command_type == "delete_user"
        )

    def _execute_command(
        self, command: FlextLdapModels.CqrsCommand
    ) -> FlextResult[object]:
        """Execute DeleteUser command.

        Expected payload:
        {
            "dn": "cn=john,ou=users,dc=example,dc=com"
        }
        """
        payload = command.payload
        dn = payload.get("dn")

        if not dn:
            return FlextResult[object].fail("User DN is required")

        # Delete user
        delete_result = self._user_repository.delete(dn)
        if delete_result.is_failure:
            return FlextResult[object].fail(
                delete_result.error or "User deletion failed"
            )

        deleted = delete_result.unwrap()
        if not deleted:
            return FlextResult[object].fail("User not found")

        self._logger.info("User deleted successfully", user_dn=dn)

        return FlextResult[object].ok({"dn": dn, "status": "deleted"})


class GetUserQueryHandler(LdapQueryHandler[FlextLdapModels.CqrsQuery]):
    """Handler for GetUser queries implementing Application.Handler protocol."""

    def __init__(self) -> None:
        """Initialize GetUser query handler."""
        super().__init__()
        self._user_repository = UserRepository()

    def _can_handle_query(self, query: object) -> bool:
        """Check if this handler can process GetUser queries."""
        return (
            isinstance(query, FlextLdapModels.CqrsQuery)
            and query.query_type == "get_user"
        )

    def _execute_query(self, query: FlextLdapModels.CqrsQuery) -> FlextResult[object]:
        """Execute GetUser query.

        Expected parameters:
        {
            "dn": "cn=john,ou=users,dc=example,dc=com"
        }
        or
        {
            "uid": "john"
        }
        """
        params = query.parameters
        dn = params.get("dn")
        uid = params.get("uid")

        if not dn and not uid:
            return FlextResult[object].fail("Either user DN or UID is required")

        user_id = dn or uid

        # Get user
        get_result = self._user_repository.get_by_id(user_id)
        if get_result.is_failure:
            return FlextResult[object].fail(get_result.error or "User lookup failed")

        user = get_result.unwrap()
        if user is None:
            return FlextResult[object].ok(None)  # Not found, but not an error

        return FlextResult[object].ok(user)


class ListUsersQueryHandler(LdapQueryHandler[FlextLdapModels.CqrsQuery]):
    """Handler for ListUsers queries implementing Application.Handler protocol."""

    def __init__(self) -> None:
        """Initialize ListUsers query handler."""
        super().__init__()
        self._user_repository = UserRepository()

    def _can_handle_query(self, query: object) -> bool:
        """Check if this handler can process ListUsers queries."""
        return (
            isinstance(query, FlextLdapModels.CqrsQuery)
            and query.query_type == "list_users"
        )

    def _execute_query(self, query: FlextLdapModels.CqrsQuery) -> FlextResult[object]:
        """Execute ListUsers query.

        Expected parameters:
        {
            "base_dn": "ou=users,dc=example,dc=com",  # optional
            "filter": "(objectClass=person)"          # optional
        }
        """
        params = query.parameters

        # Get all users (repository handles filtering)
        get_result = self._user_repository.get_all()
        if get_result.is_failure:
            return FlextResult[object].fail(get_result.error or "User listing failed")

        users = get_result.unwrap()

        # Apply client-side filtering if needed
        base_dn = params.get("base_dn")
        filter_str = params.get("filter")

        if base_dn or filter_str:
            # For now, return all and let client filter
            # Could be enhanced with more sophisticated filtering
            pass

        return FlextResult[object].ok({"users": users, "count": len(users)})


class GetGroupQueryHandler(LdapQueryHandler[FlextLdapModels.CqrsQuery]):
    """Handler for GetGroup queries implementing Application.Handler protocol."""

    def __init__(self) -> None:
        """Initialize GetGroup query handler."""
        super().__init__()
        self._group_repository = GroupRepository()

    def _can_handle_query(self, query: object) -> bool:
        """Check if this handler can process GetGroup queries."""
        return (
            isinstance(query, FlextLdapModels.CqrsQuery)
            and query.query_type == "get_group"
        )

    def _execute_query(self, query: FlextLdapModels.CqrsQuery) -> FlextResult[object]:
        """Execute GetGroup query.

        Expected parameters:
        {
            "dn": "cn=REDACTED_LDAP_BIND_PASSWORDs,ou=groups,dc=example,dc=com"
        }
        or
        {
            "cn": "REDACTED_LDAP_BIND_PASSWORDs"
        }
        """
        params = query.parameters
        dn = params.get("dn")
        cn = params.get("cn")

        if not dn and not cn:
            return FlextResult[object].fail("Either group DN or CN is required")

        group_id = dn or cn

        # Get group
        get_result = self._group_repository.get_by_id(group_id)
        if get_result.is_failure:
            return FlextResult[object].fail(get_result.error or "Group lookup failed")

        group = get_result.unwrap()
        if group is None:
            return FlextResult[object].ok(None)  # Not found, but not an error

        return FlextResult[object].ok(group)


# Handler registry for easy access
class LdapHandlerRegistry:
    """Registry of all LDAP command and query handlers."""

    @staticmethod
    def get_command_handlers() -> list[LdapCommandHandler]:
        """Get all available command handlers."""
        return [
            CreateUserCommandHandler(),
            UpdateUserCommandHandler(),
            DeleteUserCommandHandler(),
        ]

    @staticmethod
    def get_query_handlers() -> list[LdapQueryHandler]:
        """Get all available query handlers."""
        return [
            GetUserQueryHandler(),
            ListUsersQueryHandler(),
            GetGroupQueryHandler(),
        ]

    @staticmethod
    def get_all_handlers() -> list[LdapCommandHandler | LdapQueryHandler]:
        """Get all available handlers."""
        return [
            *LdapHandlerRegistry.get_command_handlers(),
            *LdapHandlerRegistry.get_query_handlers(),
        ]
