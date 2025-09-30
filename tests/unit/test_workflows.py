"""Unit tests for flext-ldap workflows module."""

from __future__ import annotations

from typing import Any

from flext_core import FlextModels
from flext_ldap.clients import FlextLdapClient
from flext_ldap.workflows import FlextLdapWorkflowOrchestrator


class TestFlextLdapWorkflowOrchestrator:
    """Tests for FlextLdapWorkflowOrchestrator class."""

    def test_workflow_initialization(self) -> None:
        """Test workflow initialization."""
        config = FlextModels.CqrsConfig.Handler.create_handler_config(
            handler_type="command",
            default_name="TestWorkflow",
            default_id="test-workflow",
        )
        client = FlextLdapClient()
        workflow = FlextLdapWorkflowOrchestrator(config, client)
        assert workflow is not None
        # Test public interface only - no protected attribute access
        assert hasattr(workflow, "handle")
        assert callable(workflow.handle)

    def test_handle_invalid_message_type(self) -> None:
        """Test handling invalid message type."""
        config = FlextModels.CqrsConfig.Handler.create_handler_config(
            handler_type="command",
            default_name="TestWorkflow",
            default_id="test-workflow",
        )
        client = FlextLdapClient()
        workflow = FlextLdapWorkflowOrchestrator(config, client)

        result = workflow.handle("invalid_message")
        assert result.is_failure
        assert result.error is not None
        assert "Message must be DomainMessage model or dictionary" in result.error

    def test_handle_missing_workflow_type(self) -> None:
        """Test handling message with missing workflow type."""
        config = FlextModels.CqrsConfig.Handler.create_handler_config(
            handler_type="command",
            default_name="TestWorkflow",
            default_id="test-workflow",
        )
        client = FlextLdapClient()
        workflow = FlextLdapWorkflowOrchestrator(config, client)

        message: dict[str, Any] = {"data": "test"}
        result = workflow.handle(message)
        assert result.is_failure
        assert result.error is not None
        assert "Workflow type must be a string" in result.error

    def test_handle_invalid_workflow_type(self) -> None:
        """Test handling message with invalid workflow type."""
        config = FlextModels.CqrsConfig.Handler.create_handler_config(
            handler_type="command",
            default_name="TestWorkflow",
            default_id="test-workflow",
        )
        client = FlextLdapClient()
        workflow = FlextLdapWorkflowOrchestrator(config, client)

        message: dict[str, Any] = {"workflow_type": 123}
        result = workflow.handle(message)
        assert result.is_failure
        assert result.error is not None
        assert "Workflow type must be a string" in result.error

    def test_handle_unknown_workflow_type(self) -> None:
        """Test handling unknown workflow type."""
        config = FlextModels.CqrsConfig.Handler.create_handler_config(
            handler_type="command",
            default_name="TestWorkflow",
            default_id="test-workflow",
        )
        client = FlextLdapClient()
        workflow = FlextLdapWorkflowOrchestrator(config, client)

        message: dict[str, Any] = {"workflow_type": "unknown_workflow"}
        result = workflow.handle(message)
        assert result.is_failure
        assert result.error is not None
        assert "Unknown workflow type: unknown_workflow" in result.error

    def test_handle_enterprise_user_provisioning(self) -> None:
        """Test handling enterprise user provisioning workflow."""
        config = FlextModels.CqrsConfig.Handler.create_handler_config(
            handler_type="command",
            default_name="TestWorkflow",
            default_id="test-workflow",
        )
        client = FlextLdapClient()
        workflow = FlextLdapWorkflowOrchestrator(config, client)

        message: dict[str, Any] = {
            "workflow_type": "enterprise_user_provisioning",
            "user_data": {},
        }
        result = workflow.handle(message)
        assert result.is_failure  # Should fail due to missing validation data
        assert result.error is not None

    def test_handle_organizational_restructure(self) -> None:
        """Test handling organizational restructure workflow."""
        config = FlextModels.CqrsConfig.Handler.create_handler_config(
            handler_type="command",
            default_name="TestWorkflow",
            default_id="test-workflow",
        )
        client = FlextLdapClient()
        workflow = FlextLdapWorkflowOrchestrator(config, client)

        message: dict[str, Any] = {
            "workflow_type": "organizational_restructure",
            "restructure_data": {},
        }
        result = workflow.handle(message)
        assert result.is_success  # Should succeed with default implementations
        assert result.data is not None

    def test_handle_compliance_audit_workflow(self) -> None:
        """Test handling compliance audit workflow."""
        config = FlextModels.CqrsConfig.Handler.create_handler_config(
            handler_type="command",
            default_name="TestWorkflow",
            default_id="test-workflow",
        )
        client = FlextLdapClient()
        workflow = FlextLdapWorkflowOrchestrator(config, client)

        message: dict[str, Any] = {
            "workflow_type": "compliance_audit_workflow",
            "audit_data": {},
        }
        result = workflow.handle(message)
        assert result.is_success  # Should succeed with default implementations
        assert result.data is not None

    def test_handle_multi_domain_synchronization(self) -> None:
        """Test handling multi-domain synchronization workflow."""
        config = FlextModels.CqrsConfig.Handler.create_handler_config(
            handler_type="command",
            default_name="TestWorkflow",
            default_id="test-workflow",
        )
        client = FlextLdapClient()
        workflow = FlextLdapWorkflowOrchestrator(config, client)

        message: dict[str, Any] = {
            "workflow_type": "multi_domain_synchronization",
            "sync_data": {},
        }
        result = workflow.handle(message)
        assert result.is_success  # Should succeed with default implementations
        assert result.data is not None

    def test_handle_advanced_security_workflow(self) -> None:
        """Test handling advanced security workflow."""
        config = FlextModels.CqrsConfig.Handler.create_handler_config(
            handler_type="command",
            default_name="TestWorkflow",
            default_id="test-workflow",
        )
        client = FlextLdapClient()
        workflow = FlextLdapWorkflowOrchestrator(config, client)

        message: dict[str, Any] = {
            "workflow_type": "advanced_security_workflow",
            "security_data": {},
        }
        result = workflow.handle(message)
        assert result.is_success  # Should succeed with default implementations
        assert result.data is not None

    def test_handle_exception_during_processing(self) -> None:
        """Test handling exception during workflow processing."""
        config = FlextModels.CqrsConfig.Handler.create_handler_config(
            handler_type="command",
            default_name="TestWorkflow",
            default_id="test-workflow",
        )
        client = FlextLdapClient()
        workflow = FlextLdapWorkflowOrchestrator(config, client)

        # Create a message that will cause an exception
        message: dict[str, Any] = {"workflow_type": "enterprise_user_provisioning"}
        result = workflow.handle(message)
        assert result.is_failure
        assert result.error is not None
        assert "Missing required fields:" in result.error

    def test_enterprise_user_provisioning_validation_failure(self) -> None:
        """Test enterprise user provisioning with validation failure."""
        config = FlextModels.CqrsConfig.Handler.create_handler_config(
            handler_type="command",
            default_name="TestWorkflow",
            default_id="test-workflow",
        )
        client = FlextLdapClient()
        workflow = FlextLdapWorkflowOrchestrator(config, client)

        # Test validation failure through public interface
        message: dict[str, Any] = {
            "workflow_type": "enterprise_user_provisioning",
            "user_data": {},
        }
        result = workflow.handle(message)
        assert result.is_failure
        assert result.error is not None
        assert "Missing required fields:" in result.error

    def test_enterprise_user_provisioning_with_complete_data(self) -> None:
        """Test enterprise user provisioning with complete required data."""
        config = FlextModels.CqrsConfig.Handler.create_handler_config(
            handler_type="command",
            default_name="TestWorkflow",
            default_id="test-workflow",
        )
        client = FlextLdapClient()
        workflow = FlextLdapWorkflowOrchestrator(config, client)

        # Test with complete required data
        message: dict[str, Any] = {
            "workflow_type": "enterprise_user_provisioning",
            "user_data": {"username": "testuser", "email": "test@example.com"},
            "target_organizations": ["org1", "org2"],
            "security_requirements": {"level": "high"},
        }
        result = workflow.handle(message)
        assert result.is_success
        assert result.data is not None

    def test_workflow_orchestrator_comprehensive_testing(self) -> None:
        """Test workflow orchestrator with comprehensive scenarios."""
        config = FlextModels.CqrsConfig.Handler.create_handler_config(
            handler_type="command",
            default_name="TestWorkflow",
            default_id="test-workflow",
        )
        client = FlextLdapClient()
        workflow = FlextLdapWorkflowOrchestrator(config, client)

        # Test all workflow types through public interface
        workflows_to_test: list[tuple[str, dict[str, Any]]] = [
            ("organizational_restructure", {"restructure_data": {}}),
            ("compliance_audit_workflow", {"audit_data": {}}),
            ("multi_domain_synchronization", {"sync_data": {}}),
            ("advanced_security_workflow", {"security_data": {}}),
        ]

        for workflow_type, data in workflows_to_test:
            message: dict[str, Any] = {"workflow_type": workflow_type, **data}
            result = workflow.handle(message)
            assert result.is_success
            assert result.data is not None
            assert isinstance(result.data, dict)
