"""Advanced LDAP Services for FLEXT LDAP.

Advanced service layer providing comprehensive LDAP operations with monadic patterns
and FlextResult railways for type-safe error handling and composition.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextHandlers, FlextModels, FlextResult
from flext_ldap.clients import FlextLdapClient
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.exceptions import FlextLdapExceptions
from flext_ldap.models import FlextLdapModels
from flext_ldap.typings import FlextLdapTypes
from flext_ldap.workflows import FlextLdapWorkflowOrchestrator


class FlextLdapAdvancedService(FlextHandlers[object, object]):
    """Advanced LDAP service using composition and monadic patterns.

    This service simplifies complex LDAP operations by combining multiple
    operations into atomic, type-safe workflows using FlextResults railways.
    """

    def __init__(
        self, config: FlextModels.CqrsConfig.Handler, client: FlextLdapClient
    ) -> None:
        """Initialize advanced service with client and configuration."""
        super().__init__(config=config)
        self._client = client
        self._models = FlextLdapModels
        self._types = FlextLdapTypes
        self._constants = FlextLdapConstants
        self._exceptions = FlextLdapExceptions

        # Initialize advanced orchestrators
        self._workflow_orchestrator = FlextLdapWorkflowOrchestrator(config, client)

    def handle(self, message: object) -> FlextResult[object]:
        """Handle LDAP service requests with advanced routing."""
        try:
            if not isinstance(message, dict):
                return FlextResult[object].fail("Message must be a dictionary")

            operation = message.get("operation")
            if not isinstance(operation, str):
                return FlextResult[object].fail("Operation must be a string")

            # Route to advanced service operations using workflow orchestrator
            if operation == "authenticate_and_create_session":
                # Delegate to enterprise user provisioning workflow
                workflow_message = {
                    **message,
                    "workflow_type": "enterprise_user_provisioning",
                    "operation": "authenticate_and_create_session",
                }
                return self._workflow_orchestrator.handle(workflow_message)
            if operation == "bulk_user_operations":
                # Delegate to organizational restructure workflow
                workflow_message = {
                    **message,
                    "workflow_type": "organizational_restructure",
                    "operation": "bulk_user_operations",
                }
                return self._workflow_orchestrator.handle(workflow_message)
            if operation == "group_membership_workflow":
                # Delegate to multi-domain synchronization workflow
                workflow_message = {
                    **message,
                    "workflow_type": "multi_domain_synchronization",
                    "operation": "group_membership_workflow",
                }
                return self._workflow_orchestrator.handle(workflow_message)
            if operation == "user_lifecycle_management":
                # Delegate to compliance audit workflow
                workflow_message = {
                    **message,
                    "workflow_type": "compliance_audit_workflow",
                    "operation": "user_lifecycle_management",
                }
                return self._workflow_orchestrator.handle(workflow_message)
            if operation == "directory_health_check":
                # Delegate to advanced security workflow
                workflow_message = {
                    **message,
                    "workflow_type": "advanced_security_workflow",
                    "operation": "directory_health_check",
                }
                return self._workflow_orchestrator.handle(workflow_message)
            # All operations delegate to workflow orchestrator - no legacy fallbacks
            return self._workflow_orchestrator.handle(message)

        except Exception as e:
            return FlextResult[object].fail(f"Service operation failed: {e}")
