"""LDAP Factory for FLEXT LDAP.

Advanced factory for creating LDAP components with centralized configuration.
This module provides factory methods for LDAP clients, services, and requests
with proper validation and configuration management.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Any, override

from flext_core import (
    FlextBus,
    FlextContainer,
    FlextContext,
    FlextDispatcher,
    FlextHandlers,
    FlextModels,
    FlextProcessors,
    FlextRegistry,
    FlextResult,
)
from flext_ldap.clients import FlextLdapClient
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.domain_services import (
    FlextLdapDomainServices,
)
from flext_ldap.models import FlextLdapModels
from flext_ldap.services import FlextLdapAdvancedService
from flext_ldap.workflows import (
    FlextLdapWorkflowOrchestrator,
)


class FlextLdapFactory(FlextHandlers[object, object]):
    """Advanced factory for creating LDAP components with centralized configuration.

    This factory uses the Factory pattern to create complex LDAP components
    with proper dependency injection and configuration validation using
    advanced FLEXT ecosystem patterns.
    """

    @override
    def __init__(self, config: FlextModels.CqrsConfig.Handler) -> None:
        """Initialize factory with configuration."""
        super().__init__(config=config)
        self._container: FlextContainer = FlextContainer()
        self._bus: FlextBus = FlextBus()
        self._dispatcher: FlextDispatcher = FlextDispatcher()
        self._processors: FlextProcessors = FlextProcessors()
        self._ldap_registry: FlextRegistry = FlextRegistry(self._dispatcher)
        self._context = FlextContext()

    @override
    def handle(self, message: object) -> FlextResult[object]:
        """Handle factory creation requests with advanced routing."""
        try:
            if not isinstance(message, dict):
                return FlextResult[object].fail("Message must be a dictionary")

            factory_type = message.get("factory_type")
            if not isinstance(factory_type, str):
                return FlextResult[object].fail("Factory type must be a string")

            if factory_type == "advanced_service":
                return self._create_advanced_service_ecosystem(message)
            if factory_type == "workflow_orchestrator":
                return self._create_workflow_orchestrator_ecosystem(message)
            if factory_type == "domain_services":
                return self._create_domain_services_ecosystem(message)
            if factory_type == "command_query_services":
                return self._create_command_query_services_ecosystem(message)
            if factory_type == "saga_orchestrator":
                return self._create_saga_orchestrator_ecosystem(message)
            return FlextResult[object].fail(f"Unknown factory type: {factory_type}")

        except Exception as e:
            return FlextResult[object].fail(f"Factory creation failed: {e}")

    def _create_advanced_service_ecosystem(
        self, message: dict[str, Any]
    ) -> FlextResult[object]:
        """Create advanced service with full ecosystem integration."""
        try:
            client_config = message.get("client_config", {})

            # Create client using ecosystem patterns
            client_result = self.create_client(client_config)
            if client_result.is_failure:
                return FlextResult[object].fail(
                    f"Client creation failed: {client_result.error}"
                )

            # Create advanced service with ecosystem components
            service = FlextLdapAdvancedService(
                config=self.config, client=client_result.value
            )

            return FlextResult[object].ok(service)

        except Exception as e:
            return FlextResult[object].fail(f"Advanced service creation failed: {e}")

    def _create_workflow_orchestrator_ecosystem(
        self, message: dict[str, Any]
    ) -> FlextResult[object]:
        """Create workflow orchestrator with full ecosystem integration."""
        try:
            client_config = message.get("client_config", {})

            # Create client using ecosystem patterns
            client_result = self.create_client(client_config)
            if client_result.is_failure:
                return FlextResult[object].fail(
                    f"Client creation failed: {client_result.error}"
                )

            # Create workflow orchestrator with ecosystem components
            orchestrator = FlextLdapWorkflowOrchestrator(
                config=self.config, client=client_result.value
            )

            return FlextResult[object].ok(orchestrator)

        except Exception as e:
            return FlextResult[object].fail(
                f"Workflow orchestrator creation failed: {e}"
            )

    def _create_domain_services_ecosystem(
        self, message: dict[str, Any]
    ) -> FlextResult[object]:
        """Create domain services with full ecosystem integration."""
        try:
            client_config = message.get("client_config", {})

            # Create client using ecosystem patterns
            client_result = self.create_client(client_config)
            if client_result.is_failure:
                return FlextResult[object].fail(
                    f"Client creation failed: {client_result.error}"
                )

            # Create domain services with ecosystem components
            domain_services = FlextLdapDomainServices(
                config=self.config,
                client=client_result.value,
                container=self._container,
                bus=self._bus,
                dispatcher=self._dispatcher,
                processors=self._processors,
                registry=self._ldap_registry,
            )

            return FlextResult[object].ok(domain_services)

        except Exception as e:
            return FlextResult[object].fail(f"Domain services creation failed: {e}")

    def _create_command_query_services_ecosystem(
        self, message: dict[str, Any]
    ) -> FlextResult[object]:
        """Create command query services with full ecosystem integration."""
        try:
            client_config = message.get("client_config", {})

            # Create client using ecosystem patterns
            client_result = self.create_client(client_config)
            if client_result.is_failure:
                return FlextResult[object].fail(
                    f"Client creation failed: {client_result.error}"
                )

            # Create command query services through domain services
            domain_services = FlextLdapDomainServices(
                config=self.config,
                client=client_result.value,
                container=self._container,
                bus=self._bus,
                dispatcher=self._dispatcher,
                processors=self._processors,
                registry=self._ldap_registry,
            )

            # Get CQRS services as nested class
            cqrs_result = domain_services.get_cqrs_services(self.config)
            if cqrs_result.is_failure:
                return FlextResult[object].fail(
                    f"CQRS services creation failed: {cqrs_result.error}"
                )

            cqrs_services = cqrs_result.value

            return FlextResult[object].ok(cqrs_services)

        except Exception as e:
            return FlextResult[object].fail(
                f"Command query services creation failed: {e}"
            )

    def _create_saga_orchestrator_ecosystem(
        self, message: dict[str, Any]
    ) -> FlextResult[object]:
        """Create saga orchestrator with full ecosystem integration."""
        try:
            client_config = message.get("client_config", {})

            # Create client using ecosystem patterns
            client_result = self.create_client(client_config)
            if client_result.is_failure:
                return FlextResult[object].fail(
                    f"Client creation failed: {client_result.error}"
                )

            # Create saga orchestrator with ecosystem components
            saga_orchestrator = FlextLdapWorkflowOrchestrator.SagaOrchestrator(
                config=self.config, client=client_result.value
            )

            return FlextResult[object].ok(saga_orchestrator)

        except Exception as e:
            return FlextResult[object].fail(f"Saga orchestrator creation failed: {e}")

    @staticmethod
    def create_advanced_service(
        client_config: dict[str, Any], service_config: dict[str, Any] | None = None
    ) -> FlextResult[FlextLdapAdvancedService]:
        """DEPRECATED: Create an advanced LDAP service with full configuration.

        This method is deprecated and will be removed in a future version.
        Use FlextLdapFactory.handle() with factory_type="advanced_service" instead.

        Args:
            client_config: Configuration for LDAP client
            service_config: Configuration for the service

        Returns:
            FlextResult containing the configured service or error

        """
        try:
            # Validate client configuration
            client_validation = FlextLdapFactory._validate_client_config(client_config)
            if client_validation.is_failure:
                return FlextResult[FlextLdapAdvancedService].fail(
                    f"Client configuration validation failed: {client_validation.error}"
                )

            # Create client
            client_result = FlextLdapFactory.create_client(client_config)
            if client_result.is_failure:
                return FlextResult[FlextLdapAdvancedService].fail(
                    f"Client creation failed: {client_result.error}"
                )

            client = client_result.value

            # Create service configuration
            service_config_dict = service_config or {}
            handler_config = FlextModels.CqrsConfig.Handler(
                handler_id=service_config_dict.get(
                    "handler_id", "ldap_advanced_service"
                ),
                handler_name=service_config_dict.get(
                    "handler_name", "LDAP Advanced Service"
                ),
                handler_type=service_config_dict.get("handler_type", "command"),
                command_timeout=service_config_dict.get("timeout", 30),
                max_command_retries=service_config_dict.get("retry_count", 3),
            )

            # Create service
            service = FlextLdapAdvancedService(config=handler_config, client=client)

            return FlextResult[FlextLdapAdvancedService].ok(service)

        except Exception as e:
            return FlextResult[FlextLdapAdvancedService].fail(
                f"Service creation failed: {e}"
            )

    @staticmethod
    def create_client(config: dict[str, Any]) -> FlextResult[FlextLdapClient]:
        """DEPRECATED: Create an LDAP client with configuration validation.

        This method is deprecated and will be removed in a future version.
        Use FlextLdapFactory.handle() with factory_type="client" instead.

        Args:
            config: Client configuration dictionary

        Returns:
            FlextResult containing the configured client or error

        """
        try:
            # Validate configuration
            validation_result = FlextLdapFactory._validate_client_config(config)
            if validation_result.is_failure:
                return FlextResult[FlextLdapClient].fail(
                    f"Configuration validation failed: {validation_result.error}"
                )

            # Create client configuration
            client_config = FlextLdapModels.ConnectionConfig(
                server=config["server_uri"],
                bind_dn=config.get("bind_dn"),
                bind_password=config.get("bind_password"),
            )

            # Create client with configuration
            client = FlextLdapClient(config=client_config)

            return FlextResult[FlextLdapClient].ok(client)

        except Exception as e:
            return FlextResult[FlextLdapClient].fail(f"Client creation failed: {e}")

    @staticmethod
    def create_user_request(
        user_data: dict[str, Any], *, validation_strict: bool = True
    ) -> FlextResult[FlextLdapModels.CreateUserRequest]:
        """Create a user request with validation and defaults.

        Args:
            user_data: User data dictionary
            validation_strict: Whether to use strict validation (keyword-only)

        Returns:
            FlextResult containing the validated request or error

        """
        try:
            # Validate required fields
            required_fields = ["dn", "uid", "cn", "sn"]
            missing_fields = [
                field for field in required_fields if field not in user_data
            ]
            if missing_fields:
                return FlextResult[FlextLdapModels.CreateUserRequest].fail(
                    f"Missing required fields: {missing_fields}"
                )

            # Apply defaults and validation
            validated_data = FlextLdapFactory._apply_user_defaults(user_data)

            if validation_strict:
                validation_result = FlextLdapFactory._validate_user_data(validated_data)
                if validation_result.is_failure:
                    return FlextResult[FlextLdapModels.CreateUserRequest].fail(
                        f"User data validation failed: {validation_result.error}"
                    )

            # Create request
            request = FlextLdapModels.CreateUserRequest(
                dn=validated_data["dn"],
                uid=validated_data["uid"],
                cn=validated_data["cn"],
                sn=validated_data["sn"],
                given_name=validated_data.get("given_name"),
                mail=validated_data.get("mail"),
                telephone_number=validated_data.get("telephone_number"),
                department=validated_data.get("department"),
                title=validated_data.get("title"),
                organization=validated_data.get("organization"),
                user_password=validated_data.get("user_password"),
                description=validated_data.get("description"),
            )

            return FlextResult[FlextLdapModels.CreateUserRequest].ok(request)

        except Exception as e:
            return FlextResult[FlextLdapModels.CreateUserRequest].fail(
                f"Request creation failed: {e}"
            )

    @staticmethod
    def create_search_request(
        search_data: dict[str, Any],
    ) -> FlextResult[FlextLdapModels.SearchRequest]:
        """Create a search request with validation and defaults.

        Args:
            search_data: Search data dictionary

        Returns:
            FlextResult containing the validated request or error

        """
        try:
            # Validate required fields
            required_fields = ["base_dn", "filter_str"]
            missing_fields = [
                field for field in required_fields if field not in search_data
            ]
            if missing_fields:
                return FlextResult[FlextLdapModels.SearchRequest].fail(
                    f"Missing required fields: {missing_fields}"
                )

            # Apply defaults
            validated_data = FlextLdapFactory._apply_search_defaults(search_data)

            # Create request
            request = FlextLdapModels.SearchRequest(
                base_dn=validated_data["base_dn"],
                filter_str=validated_data["filter_str"],
                scope=validated_data.get("scope", "subtree"),
                attributes=validated_data.get("attributes", []),
                page_size=validated_data.get(
                    "page_size", FlextLdapConstants.Connection.DEFAULT_PAGE_SIZE
                ),
                paged_cookie=validated_data.get("paged_cookie", b""),
            )

            return FlextResult[FlextLdapModels.SearchRequest].ok(request)

        except Exception as e:
            return FlextResult[FlextLdapModels.SearchRequest].fail(
                f"Search request creation failed: {e}"
            )

    @staticmethod
    def create_bulk_operation_config(
        operation_data: dict[str, Any],
    ) -> FlextResult[dict[str, Any]]:
        """Create bulk operation configuration with validation.

        Args:
            operation_data: Operation configuration data

        Returns:
            FlextResult containing validated configuration or error

        """
        try:
            # Validate operation type
            operation_type = operation_data.get("operation_type")
            if not isinstance(operation_type, str):
                return FlextResult[dict[str, Any]].fail(
                    "Operation type must be a string"
                )

            valid_operations = ["create", "update", "delete", "bulk_update"]
            if operation_type not in valid_operations:
                return FlextResult[dict[str, Any]].fail(
                    f"Invalid operation type. Must be one of: {valid_operations}"
                )

            # Validate data
            items_data = operation_data.get("items_data")
            if not isinstance(items_data, list):
                return FlextResult[dict[str, Any]].fail("Items data must be a list")

            if len(items_data) == 0:
                return FlextResult[dict[str, Any]].fail("Items data cannot be empty")

            # Apply defaults and validation
            batch_size = operation_data.get("batch_size", 10)
            if not isinstance(batch_size, int):
                return FlextResult[dict[str, Any]].fail("Batch size must be an integer")

            # Validate batch size using constant
            if batch_size <= 0:
                return FlextResult[dict[str, Any]].fail(
                    "Batch size must be greater than 0"
                )

            if batch_size > FlextLdapConstants.Connection.DEFAULT_PAGE_SIZE:
                return FlextResult[dict[str, Any]].fail(
                    f"Batch size cannot exceed {FlextLdapConstants.Connection.DEFAULT_PAGE_SIZE}"
                )

            config = {
                "operation_type": operation_type,
                "items_data": items_data,
                "batch_size": batch_size,
                "continue_on_error": operation_data.get("continue_on_error", True),
                "rollback_on_failure": operation_data.get("rollback_on_failure", False),
                "validation_strict": operation_data.get("validation_strict", True),
                "timeout_per_operation": operation_data.get(
                    "timeout_per_operation", 30
                ),
            }

            return FlextResult[dict[str, Any]].ok(config)

        except Exception as e:
            return FlextResult[dict[str, Any]].fail(
                f"Bulk operation configuration failed: {e}"
            )

    # =============================================================================
    # PRIVATE VALIDATION AND HELPER METHODS
    # =============================================================================

    @staticmethod
    def _validate_client_config(config: dict[str, Any]) -> FlextResult[None]:
        """Validate client configuration."""
        try:
            # Required fields
            required_fields = ["server_uri"]
            missing_fields = [field for field in required_fields if field not in config]
            if missing_fields:
                return FlextResult[None].fail(
                    f"Missing required fields: {missing_fields}"
                )

            # Validate server_uri
            server_uri = config["server_uri"]
            if not isinstance(server_uri, str):
                return FlextResult[None].fail("Server URI must be a string")

            if not server_uri.startswith((
                FlextLdapConstants.Protocol.PROTOCOL_PREFIX_LDAP,
                FlextLdapConstants.Protocol.PROTOCOL_PREFIX_LDAPS,
            )):
                return FlextResult[None].fail(
                    "Server URI must start with ldap:// or ldaps://"
                )

            # Validate optional fields
            if "bind_dn" in config and not isinstance(config["bind_dn"], str):
                return FlextResult[None].fail("Bind DN must be a string")

            if "bind_password" in config and not isinstance(
                config["bind_password"], str
            ):
                return FlextResult[None].fail("Bind password must be a string")

            # Validate connection options
            connection_options = config.get("connection_options", {})
            if not isinstance(connection_options, dict):
                return FlextResult[None].fail("Connection options must be a dictionary")

            # Validate search options
            search_options = config.get("search_options", {})
            if not isinstance(search_options, dict):
                return FlextResult[None].fail("Search options must be a dictionary")

            return FlextResult[None].ok(None)

        except Exception as e:
            return FlextResult[None].fail(f"Configuration validation failed: {e}")

    @staticmethod
    def _validate_user_data(user_data: dict[str, Any]) -> FlextResult[None]:
        """Validate user data for strict validation."""
        try:
            # Validate DN format
            dn = user_data.get("dn", "")
            if not isinstance(dn, str) or not dn.strip():
                return FlextResult[None].fail("DN must be a non-empty string")

            # Validate UID format
            uid = user_data.get("uid", "")
            if not isinstance(uid, str) or not uid.strip():
                return FlextResult[None].fail("UID must be a non-empty string")

            # Validate CN format
            cn = user_data.get("cn", "")
            if not isinstance(cn, str) or not cn.strip():
                return FlextResult[None].fail("CN must be a non-empty string")

            # Validate SN format
            sn = user_data.get("sn", "")
            if not isinstance(sn, str) or not sn.strip():
                return FlextResult[None].fail("SN must be a non-empty string")

            # Validate email format if provided
            mail = user_data.get("mail")
            if mail is not None:
                if not isinstance(mail, str):
                    return FlextResult[None].fail("Mail must be a string")
                if "@" not in mail:
                    return FlextResult[None].fail("Mail must be a valid email address")

            return FlextResult[None].ok(None)

        except Exception as e:
            return FlextResult[None].fail(f"User data validation failed: {e}")

    @staticmethod
    def _apply_user_defaults(user_data: dict[str, Any]) -> dict[str, Any]:
        """Apply default values to user data."""
        defaults = {
            "scope": "subtree",
            "attributes": [],
        }

        result = user_data.copy()
        for key, default_value in defaults.items():
            if key not in result:
                result[key] = default_value

        return result

    @staticmethod
    def _apply_search_defaults(search_data: dict[str, Any]) -> dict[str, Any]:
        """Apply default values to search data."""
        defaults = {
            "scope": "subtree",
            "attributes": [],
            "page_size": FlextLdapConstants.Connection.DEFAULT_PAGE_SIZE,
            "paged_cookie": b"",
        }

        result = search_data.copy()
        for key, default_value in defaults.items():
            if key not in result:
                result[key] = default_value

        return result
