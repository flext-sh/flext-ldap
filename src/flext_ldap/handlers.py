"""LDAP command and query handlers implementing Application.Handler protocol.

This module provides handler classes that implement the Application.Handler
protocol from flext-core. Handlers process CQRS commands and queries for LDAP
operations with proper domain-driven design.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from abc import abstractmethod
from typing import Generic, TypeVar, cast

from flext_core import FlextLogger, FlextProtocols, FlextResult

from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels
from flext_ldap.repositories import FlextLdapRepositories

logger = FlextLogger(__name__)

TCommand = TypeVar("TCommand", bound=FlextLdapModels.CqrsCommand)
TQuery = TypeVar("TQuery", bound=FlextLdapModels.CqrsQuery)


class FlextLdapHandlers:
    """Unified namespace class for LDAP command and query handlers.

    Consolidates all LDAP handlers into a single namespace class following
    FLEXT single-class-per-module pattern while maintaining CQRS architecture.
    """

    class FlextLdapLdapCommandHandler(
        FlextProtocols.Application.Handler,
        Generic[TCommand],
    ):
        """Base class for LDAP command handlers implementing Application.Handler protocol.

        This class provides the foundation for LDAP command handlers, implementing
        the flext-core Application.Handler protocol through explicit inheritance.
        """

        def __init__(self) -> None:
            """Initialize command handler."""
            self.logger = FlextLogger(__name__)

        def __call__(self, message: object) -> FlextResult[object]:
            """Make handler callable - implements Application.Handler protocol.

            Args:
                message: Message to handle (typically a command)

            Returns:
                FlextResult with handling result

            """
            if not isinstance(message, FlextLdapModels.CqrsCommand):
                return FlextResult[object].fail("Message must be a CqrsCommand")
            return self.handle(cast("TCommand", message))

        def execute(self, message: object) -> FlextResult[object]:
            """Execute handler - implements Application.Handler protocol.

            Args:
                message: Message to execute

            Returns:
                FlextResult with execution result

            """
            return self(message)

        def validate(self, message: object) -> FlextResult[None]:
            """Validate message - implements Application.Handler protocol.

            Args:
                message: Message to validate

            Returns:
                FlextResult indicating validation success

            """
            if not isinstance(message, FlextLdapModels.CqrsCommand):
                return FlextResult[None].fail("Message must be a CqrsCommand")
            return self._validate_command(cast("TCommand", message))

        def validate_command(self, command: object) -> FlextResult[None]:
            """Validate command - implements Application.Handler protocol.

            Args:
                command: Command to validate

            Returns:
                FlextResult indicating validation success

            """
            if not isinstance(command, FlextLdapModels.CqrsCommand):
                return FlextResult[None].fail("Command must be a CqrsCommand")
            return self._validate_command(cast("TCommand", command))

        def validate_query(self, query: object) -> FlextResult[None]:
            """Validate query - implements Application.Handler protocol (not applicable for command handlers).

            Args:
                query: Query to validate (unused for command handlers)

            Returns:
                FlextResult indicating this is not a query handler

            """
            _ = query  # Unused in command handlers
            return FlextResult[None].fail("Command handler cannot validate queries")

        @property
        def handler_name(self) -> str:
            """Get handler name - implements Application.Handler protocol."""
            return self.__class__.__name__

        @property
        def mode(self) -> str:
            """Get handler mode - implements Application.Handler protocol."""
            return "command"

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
                        validation_result.error or "Command validation failed",
                    )

                # Execute command
                return self._execute_command(command)

            except Exception as e:
                self.logger.exception("Command handling failed", exception=e)
                return FlextResult[object].fail(f"Command execution failed: {e}")

        def can_handle(self, command: object) -> bool:
            """Check if handler can process command - implements Application.Handler protocol.

            Args:
                command: Command to check

            Returns:
                True if handler can process the command

            """
            return isinstance(
                command,
                FlextLdapModels.CqrsCommand,
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

    class FlextLdapLdapQueryHandler(
        FlextProtocols.Application.Handler,
        Generic[TQuery],
    ):
        """Base class for LDAP query handlers implementing Application.Handler protocol.

        This class provides the foundation for LDAP query handlers, implementing
        the flext-core Application.Handler protocol through explicit inheritance.
        """

        def __init__(self) -> None:
            """Initialize query handler."""
            self.logger = FlextLogger(__name__)

        def __call__(self, message: object) -> FlextResult[object]:
            """Make handler callable - implements Application.Handler protocol.

            Args:
                message: Message to handle (typically a query)

            Returns:
                FlextResult with handling result

            """
            if not isinstance(message, FlextLdapModels.CqrsQuery):
                return FlextResult[object].fail("Message must be a CqrsQuery")
            return self.handle(cast("TQuery", message))

        def execute(self, message: object) -> FlextResult[object]:
            """Execute handler - implements Application.Handler protocol.

            Args:
                message: Message to execute

            Returns:
                FlextResult with execution result

            """
            return self(message)

        def validate(self, message: object) -> FlextResult[None]:
            """Validate message - implements Application.Handler protocol.

            Args:
                message: Message to validate

            Returns:
                FlextResult indicating validation success

            """
            if not isinstance(message, FlextLdapModels.CqrsQuery):
                return FlextResult[None].fail("Message must be a CqrsQuery")
            return self._validate_query(cast("TQuery", message))

        def validate_command(self, command: object) -> FlextResult[None]:
            """Validate command - implements Application.Handler protocol (not applicable for query handlers).

            Args:
                command: Command to validate (unused for query handlers)

            Returns:
                FlextResult indicating this is not a command handler

            """
            _ = command  # Unused in query handlers
            return FlextResult[None].fail("Query handler cannot validate commands")

        def validate_query(self, query: object) -> FlextResult[None]:
            """Validate query - implements Application.Handler protocol.

            Args:
                query: Query to validate

            Returns:
                FlextResult indicating validation success

            """
            if not isinstance(query, FlextLdapModels.CqrsQuery):
                return FlextResult[None].fail("Query must be a CqrsQuery")
            return self._validate_query(cast("TQuery", query))

        @property
        def handler_name(self) -> str:
            """Get handler name - implements Application.Handler protocol."""
            return self.__class__.__name__

        @property
        def mode(self) -> str:
            """Get handler mode - implements Application.Handler protocol."""
            return "query"

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
                        validation_result.error or "Query validation failed",
                    )

                # Execute query
                return self._execute_query(query)

            except Exception as e:
                self.logger.exception("Query handling failed", exception=e)
                return FlextResult[object].fail(f"Query execution failed: {e}")

        def can_handle(self, query: object) -> bool:
            """Check if handler can process query - implements Application.Handler protocol.

            Args:
                query: Query to check

            Returns:
                True if handler can process the query

            """
            return isinstance(
                query,
                FlextLdapModels.CqrsQuery,
            ) and self._can_handle_query(query)

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

    class FlextLdapCreateUserCommandHandler(
        FlextLdapLdapCommandHandler[FlextLdapModels.CqrsCommand],
    ):
        """Handler for CreateUser commands implementing Application.Handler protocol."""

        def __init__(self) -> None:
            """Initialize CreateUser command handler."""
            super().__init__()
            self._user_repository = FlextLdapRepositories.UserRepository()

        def _can_handle_command(self, command: object) -> bool:
            """Check if this handler can process CreateUser commands."""
            return (
                isinstance(command, FlextLdapModels.CqrsCommand)
                and command.command_type == "create_user"
            )

        def _execute_command(
            self,
            command: FlextLdapModels.CqrsCommand,
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

            # Extract and validate required fields with type casting
            dn = cast("str", payload.get(FlextLdapConstants.DictKeys.DN))
            uid = cast("str", payload.get(FlextLdapConstants.DictKeys.UID))
            cn = cast("str", payload.get(FlextLdapConstants.DictKeys.CN))
            sn = cast("str", payload.get(FlextLdapConstants.DictKeys.SN))
            mail_raw = payload.get(FlextLdapConstants.DictKeys.MAIL)
            mail = cast("str", mail_raw) if mail_raw is not None else None
            object_classes_raw = payload.get("object_classes", ["person", "organizationalPerson"])
            object_classes = cast("list[str]", object_classes_raw)

            # Basic validation
            if not dn or not uid or not cn or not sn:
                return FlextResult[object].fail("Required fields missing: dn, uid, cn, sn")

            # Create user entity
            create_request = FlextLdapModels.CreateUserRequest(
                dn=dn,
                uid=uid,
                cn=cn,
                sn=sn,
                mail=mail,
                object_classes=object_classes,
            )

            # Convert to LdapUser for repository
            user = FlextLdapModels.LdapUser(
                dn=create_request.dn,
                uid=create_request.uid,
                cn=create_request.cn,
                sn=create_request.sn,
                mail=create_request.mail or "",
            )

            # Execute via repository
            result = self._user_repository.add(user)
            if result.is_failure:
                return FlextResult[object].fail(result.error or "User creation failed")

            user = result.unwrap()
            self.logger.info(
                "User created successfully",
                user_dn=user.dn,
                user_uid=user.uid,
            )

            return FlextResult[object].ok({"user": user, "status": "created"})

    class FlextLdapUpdateUserCommandHandler(
        FlextLdapLdapCommandHandler[FlextLdapModels.CqrsCommand],
    ):
        """Handler for UpdateUser commands implementing Application.Handler protocol."""

        def __init__(self) -> None:
            """Initialize UpdateUser command handler."""
            super().__init__()
            self._user_repository = FlextLdapRepositories.UserRepository()

        def _can_handle_command(self, command: object) -> bool:
            """Check if this handler can process UpdateUser commands."""
            return (
                isinstance(command, FlextLdapModels.CqrsCommand)
                and command.command_type == "update_user"
            )

        def _execute_command(
            self,
            command: FlextLdapModels.CqrsCommand,
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
            dn_raw = payload.get(FlextLdapConstants.DictKeys.DN)
            dn = cast("str", dn_raw) if dn_raw is not None else None
            attributes = payload.get(FlextLdapConstants.DictKeys.ATTRIBUTES, {})

            if not dn:
                return FlextResult[object].fail("User DN is required")

            if not attributes:
                return FlextResult[object].fail("Attributes to update are required")

            # Get existing user
            get_result = self._user_repository.get_by_id(dn)
            if get_result.is_failure:
                return FlextResult[object].fail(
                    get_result.error or "User lookup failed",
                )

            user = get_result.unwrap()
            if user is None:
                return FlextResult[object].fail("User not found")

            # Update user attributes
            update_result = self._user_repository.update(user)
            if update_result.is_failure:
                return FlextResult[object].fail(
                    update_result.error or "User update failed",
                )

            updated_user = update_result.unwrap()
            self.logger.info("User updated successfully", user_dn=updated_user.dn)

            return FlextResult[object].ok({"user": updated_user, "status": "updated"})

    class FlextLdapGetUserQueryHandler(
        FlextLdapLdapQueryHandler[FlextLdapModels.CqrsQuery],
    ):
        """Handler for GetUser queries implementing Application.Handler protocol."""

        def __init__(self) -> None:
            """Initialize GetUser query handler."""
            super().__init__()
            self._user_repository = FlextLdapRepositories.UserRepository()

        def _can_handle_query(self, query: object) -> bool:
            """Check if this handler can process GetUser queries."""
            return (
                isinstance(query, FlextLdapModels.CqrsQuery)
                and query.query_type == "get_user"
            )

        def _execute_query(
            self,
            query: FlextLdapModels.CqrsQuery,
        ) -> FlextResult[object]:
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
            dn_raw = params.get(FlextLdapConstants.DictKeys.DN)
            uid_raw = params.get(FlextLdapConstants.DictKeys.UID)

            dn = cast("str", dn_raw) if dn_raw is not None else None
            uid = cast("str", uid_raw) if uid_raw is not None else None

            if not dn and not uid:
                return FlextResult[object].fail("Either user DN or UID is required")

            user_id = dn or uid or ""  # Should never be empty due to check above

            # Get user
            get_result = self._user_repository.get_by_id(user_id)
            if get_result.is_failure:
                return FlextResult[object].fail(
                    get_result.error or "User lookup failed",
                )

            user = get_result.unwrap()
            if user is None:
                return FlextResult[object].ok(None)  # Not found, but not an error

            return FlextResult[object].ok(user)

    class FlextLdapListUsersQueryHandler(
        FlextLdapLdapQueryHandler[FlextLdapModels.CqrsQuery],
    ):
        """Handler for ListUsers queries implementing Application.Handler protocol."""

        def __init__(self) -> None:
            """Initialize ListUsers query handler."""
            super().__init__()
            self._user_repository = FlextLdapRepositories.UserRepository()

        def _can_handle_query(self, query: object) -> bool:
            """Check if this handler can process ListUsers queries."""
            return (
                isinstance(query, FlextLdapModels.CqrsQuery)
                and query.query_type == "list_users"
            )

        def _execute_query(
            self,
            query: FlextLdapModels.CqrsQuery,
        ) -> FlextResult[object]:
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
                return FlextResult[object].fail(
                    get_result.error or "User listing failed",
                )

            users = get_result.unwrap()

            # Apply client-side filtering if needed
            base_dn = params.get(FlextLdapConstants.DictKeys.BASE_DN)
            filter_str = params.get(FlextLdapConstants.DictKeys.FILTER)

            if base_dn or filter_str:
                # For now, return all and let client filter
                # Could be enhanced with more sophisticated filtering
                pass

            return FlextResult[object].ok({"users": users, "count": len(users)})

    class FlextLdapLdapHandlerRegistry:
        """Registry of all LDAP command and query handlers."""

        @staticmethod
        def get_command_handlers() -> list[
            FlextLdapHandlers.FlextLdapLdapCommandHandler
        ]:
            """Get all available command handlers."""
            return [
                FlextLdapHandlers.FlextLdapCreateUserCommandHandler(),
                FlextLdapHandlers.FlextLdapUpdateUserCommandHandler(),
            ]

        @staticmethod
        def get_query_handlers() -> list[FlextLdapHandlers.FlextLdapLdapQueryHandler]:
            """Get all available query handlers."""
            return [
                FlextLdapHandlers.FlextLdapGetUserQueryHandler(),
                FlextLdapHandlers.FlextLdapListUsersQueryHandler(),
            ]

        @staticmethod
        def get_all_handlers() -> list[
            FlextLdapHandlers.FlextLdapLdapCommandHandler
            | FlextLdapHandlers.FlextLdapLdapQueryHandler
        ]:
            """Get all available handlers."""
            return [
                *FlextLdapHandlers.FlextLdapLdapHandlerRegistry.get_command_handlers(),
                *FlextLdapHandlers.FlextLdapLdapHandlerRegistry.get_query_handlers(),
            ]
