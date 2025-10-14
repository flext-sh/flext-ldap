"""Application services for flext-ldap with Clean Architecture.

This module contains application services that orchestrate domain logic
and coordinate with infrastructure layers. Services implement use cases
and maintain application state.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Callable
from typing import cast

from flext_core import FlextCore

from flext_ldap.constants import FlextLdapConstants
from flext_ldap.domain import FlextLdapDomain
from flext_ldap.models import FlextLdapModels

logger = FlextCore.Logger(__name__)


class FlextLdapServices(FlextCore.Service[None]):
    """Unified application services class for LDAP operations.

    This class implements the Application Services layer of Clean Architecture,
    orchestrating domain logic and coordinating with infrastructure. It provides
    high-level use cases for LDAP operations while maintaining domain purity.

    **UNIFIED CLASS PATTERN**: Single class with domain service methods.
    **APPLICATION LAYER**: Orchestrates domain objects and infrastructure.
    **CLEAN ARCHITECTURE**: No infrastructure dependencies in this layer.
    """

    def __init__(self) -> None:
        """Initialize the LDAP application services with Phase 1 context enrichment."""
        super().__init__()
        # Logger and container inherited from FlextCore.Service via FlextCore.Mixins

    # =============================================================================
    # USER MANAGEMENT SERVICES
    # =============================================================================

    def validate_user_creation_request(
        self,
        request: FlextLdapModels.CreateUserRequest,
    ) -> FlextCore.Result[bool]:
        """Validate user creation request against domain business rules.

        Args:
            request: User creation request to validate

        Returns:
            FlextCore.Result indicating validation success/failure

        """
        try:
            # Domain validation: username format
            if not FlextLdapDomain.UserSpecification.is_valid_username(request.uid):
                return FlextCore.Result[bool].fail("Invalid username format")

            # Domain validation: email format (use flext-core validation directly)
            if request.mail:
                email_result = FlextCore.Utilities.Validation.validate_email(
                    request.mail
                )
                if email_result.is_failure:
                    return FlextCore.Result[bool].fail("Invalid email format")

            # Domain validation: password policy
            if request.user_password:
                # Convert SecretStr to str if needed
                password_str = (
                    str(request.user_password)
                    if isinstance(request.user_password, object)
                    else request.user_password
                )
                password_result = (
                    FlextLdapDomain.UserSpecification.meets_password_policy(
                        password_str,
                    )
                )
                if password_result.is_failure:
                    return FlextCore.Result[bool].fail(
                        password_result.error or "Password policy violation",
                    )

            # Domain validation: DN consistency
            if f"uid={request.uid}" not in request.dn:
                return FlextCore.Result[bool].fail("DN must contain the specified UID")

            logger.info(
                "User creation request validated",
                uid=request.uid,
                dn=request.dn,
            )

            return FlextCore.Result[bool].ok(True)

        except Exception as e:
            logger.exception("User creation validation failed", error=str(e))
            return FlextCore.Result[bool].fail(f"Validation failed: {e}")

    def enrich_user_for_creation(
        self,
        request: FlextLdapModels.CreateUserRequest,
    ) -> FlextCore.Result[FlextLdapModels.CreateUserRequest]:
        """Enrich user creation request with domain defaults and business logic.

        Args:
            request: Base user creation request

        Returns:
            FlextCore.Result with enriched creation request

        """
        try:
            # Domain enrichment: ensure required object classes
            required_classes = ["person", "organizationalPerson", "inetOrgPerson"]
            for cls in required_classes:
                if cls not in request.object_classes:
                    request.object_classes.append(cls)

            # Domain enrichment: generate display name if not provided
            # This would typically use domain service logic
            if request.given_name and request.sn:
                # Could set display name, but request object might not have it
                pass

            logger.info(
                "User creation request enriched",
                uid=request.uid,
                object_classes=request.object_classes,
            )

            return FlextCore.Result[FlextLdapModels.CreateUserRequest].ok(request)

        except Exception as e:
            logger.exception("User creation enrichment failed", error=str(e))
            return FlextCore.Result[FlextLdapModels.CreateUserRequest].fail(
                f"Enrichment failed: {e}",
            )

    def validate_user_search_request(
        self,
        request: FlextLdapModels.SearchRequest,
    ) -> FlextCore.Result[bool]:
        """Validate user search request against domain rules.

        Args:
            request: Search request to validate

        Returns:
            FlextCore.Result indicating validation success/failure

        """
        try:
            # Domain validation: safe filter
            filter_check = FlextLdapDomain.SearchSpecification.is_safe_search_filter(
                request.filter_str,
            )
            if filter_check.is_failure:
                return FlextCore.Result[bool].fail(
                    filter_check.error or "Unsafe search filter",
                )

            # Domain validation: search scope
            try:
                scope_obj = FlextLdapModels.Scope(value=request.scope)
            except Exception as e:
                return FlextCore.Result[bool].fail(
                    f"Invalid search scope: {e}",
                )
            scope_check = FlextLdapDomain.SearchSpecification.validate_search_scope(
                request.base_dn,
                scope_obj,
            )
            if scope_check.is_failure:
                return FlextCore.Result[bool].fail(
                    scope_check.error or "Invalid search scope",
                )

            logger.info(
                "User search request validated",
                base_dn=request.base_dn,
                filter=request.filter_str,
                scope=request.scope,
            )

            return FlextCore.Result[bool].ok(True)

        except Exception as e:
            logger.exception("User search validation failed", error=str(e))
            return FlextCore.Result[bool].fail(f"Validation failed: {e}")

    def process_user_search_results(
        self,
        results: FlextLdapModels.SearchResponse,
    ) -> FlextCore.Result[FlextLdapModels.SearchResponse]:
        """Process and enrich user search results with domain logic.

        Args:
            results: Raw search results

        Returns:
            FlextCore.Result with enriched search results

        """
        try:
            # Domain processing: convert entries to User entities
            # Note: SearchResponse accepts mixed Entry/User/Group in entries list
            user_entries: list[FlextLdapModels.Entry | FlextLdapModels.LdapUser] = []
            for entry in results.entries:
                try:
                    # Try to create User entity from entry
                    user = FlextLdapModels.LdapUser(**entry.model_dump())
                    user_entries.append(user)
                except Exception as e:
                    logger.warning(
                        "Failed to convert entry to User entity",
                        dn=entry.dn,
                        error=str(e),
                    )
                    # Keep as generic entry if conversion fails
                    user_entries.append(entry)

            # Create enriched response

            enriched_results = FlextLdapModels.SearchResponse(
                entries=cast("list[FlextLdapModels.Entry]", user_entries),
                total_count=len(user_entries),
                result_code=0,
                time_elapsed=results.time_elapsed,
                has_more_pages=results.has_more_pages,
                next_cookie=results.next_cookie,
            )

            logger.info(
                "User search results processed",
                total_entries=len(user_entries),
                time_elapsed=results.time_elapsed,
            )

            return FlextCore.Result[FlextLdapModels.SearchResponse].ok(enriched_results)

        except Exception as e:
            logger.exception("User search results processing failed", error=str(e))
            return FlextCore.Result[FlextLdapModels.SearchResponse].fail(
                f"Processing failed: {e}",
            )

    # =============================================================================
    # GROUP MANAGEMENT SERVICES
    # =============================================================================

    def validate_group_creation_request(
        self,
        group_data: dict,
    ) -> FlextCore.Result[FlextCore.Types.Dict]:
        """Validate group creation data against domain business rules.

        Args:
            group_data: Group creation data dictionary

        Returns:
            FlextCore.Result with validated group data

        """
        try:
            cn = group_data.get(FlextLdapConstants.DictKeys.CN)
            if not cn:
                return FlextCore.Result[FlextCore.Types.Dict].fail(
                    "Group CN is required"
                )

            dn = group_data.get(FlextLdapConstants.DictKeys.DN, "")
            # Domain validation: DN must contain CN
            if dn and f"cn={cn}" not in dn.lower():
                return FlextCore.Result[FlextCore.Types.Dict].fail(
                    "DN must contain the specified CN",
                )

            # Domain validation: group name format
            if not FlextLdapDomain.GroupSpecification.is_valid_group_name(cn):
                return FlextCore.Result[FlextCore.Types.Dict].fail(
                    "Invalid group name format"
                )

            # Domain validation: description (basic check)
            description = group_data.get(FlextLdapConstants.DictKeys.DESCRIPTION, "")
            if len(description) > FlextLdapConstants.Protocol.MAX_DESCRIPTION_LENGTH:
                return FlextCore.Result[FlextCore.Types.Dict].fail(
                    "Group description too long"
                )

            logger.info("Group creation request validated", cn=cn)

            return FlextCore.Result[FlextCore.Types.Dict].ok(group_data)

        except Exception as e:
            logger.exception("Group creation validation failed", error=str(e))
            return FlextCore.Result[FlextCore.Types.Dict].fail(
                f"Validation failed: {e}"
            )

    def validate_group_membership_operation(
        self,
        group: FlextLdapModels.Group,
        member_dn: str,
        operation: str,
    ) -> FlextCore.Result[bool]:
        """Validate group membership operations against domain rules.

        Args:
            group: Group entity
            member_dn: Member DN
            operation: Operation type ('add' or 'remove')

        Returns:
            FlextCore.Result indicating validation success/failure

        """
        try:
            if operation not in {"add", "remove"}:
                return FlextCore.Result[bool].fail("Invalid operation type")

            if operation == FlextLdapConstants.LiteralTypes.OPERATION_ADD:
                # Domain validation: can add member
                add_check = FlextLdapDomain.GroupSpecification.can_add_member_to_group(
                    group,
                    member_dn,
                )
                if add_check.is_failure:
                    return FlextCore.Result[bool].fail(
                        add_check.error or "Cannot add member to group",
                    )

            elif operation == "remove":
                # Domain validation: member exists
                if not group.has_member(member_dn):
                    return FlextCore.Result[bool].fail("Member not found in group")

            logger.info(
                "Group membership operation validated",
                operation=operation,
                group_cn=group.cn,
                member_dn=member_dn,
            )

            return FlextCore.Result[bool].ok(True)

        except Exception as e:
            logger.exception("Group membership validation failed", error=str(e))
            return FlextCore.Result[bool].fail(f"Validation failed: {e}")

    def process_group_search_results(
        self,
        results: FlextLdapModels.SearchResponse,
    ) -> FlextCore.Result[FlextLdapModels.SearchResponse]:
        """Process and enrich group search results with domain logic.

        Args:
            results: Raw search results

        Returns:
            FlextCore.Result with enriched search results

        """
        try:
            # Domain processing: convert entries to Group entities
            # Note: SearchResponse accepts mixed Entry/User/Group in entries list
            group_entries: list[FlextLdapModels.Entry | FlextLdapModels.Group] = []
            for entry in results.entries:
                try:
                    # Try to create Group entity from entry
                    group = FlextLdapModels.Group(**entry.model_dump())
                    group_entries.append(group)
                except Exception as e:
                    logger.warning(
                        "Failed to convert entry to Group entity",
                        dn=entry.dn,
                        error=str(e),
                    )
                    # Keep as generic entry if conversion fails
                    group_entries.append(entry)

            # Create enriched response

            enriched_results = FlextLdapModels.SearchResponse(
                entries=cast("list[FlextLdapModels.Entry]", group_entries),
                total_count=len(group_entries),
                result_code=0,
                time_elapsed=results.time_elapsed,
                has_more_pages=results.has_more_pages,
                next_cookie=results.next_cookie,
            )

            logger.info(
                "Group search results processed",
                total_entries=len(group_entries),
                time_elapsed=results.time_elapsed,
            )

            return FlextCore.Result[FlextLdapModels.SearchResponse].ok(enriched_results)

        except Exception as e:
            logger.exception("Group search results processing failed", error=str(e))
            return FlextCore.Result[FlextLdapModels.SearchResponse].fail(
                f"Processing failed: {e}",
            )

    # =============================================================================
    # SEARCH COORDINATION SERVICES
    # =============================================================================

    def coordinate_search_operation(
        self,
        search_request: FlextLdapModels.SearchRequest,
        result_processor: Callable | None = None,
    ) -> FlextCore.Result[FlextLdapModels.SearchResponse]:
        """Coordinate search operation with domain validation and processing.

        This is the main orchestration method for searches that:
        1. Validates the search request against domain rules
        2. Applies domain-specific search logic
        3. Processes results through domain services

        Args:
            search_request: Search request to execute
            result_processor: Optional custom result processor

        Returns:
            FlextCore.Result with processed search results

        """
        try:
            # Step 1: Domain validation
            validation_result = self.validate_user_search_request(search_request)
            if validation_result.is_failure:
                return FlextCore.Result[FlextLdapModels.SearchResponse].fail(
                    validation_result.error or "Search validation failed",
                )

            # Step 2: Domain enrichment (could modify search parameters)
            # For now, pass through - could add domain-specific filters

            # Step 3: Simulate infrastructure call (in real implementation, this would
            # call the infrastructure layer through dependency injection)
            # For this optimization, we'll create mock results
            mock_results = FlextLdapModels.SearchResponse(
                entries=[],  # Would be populated by infrastructure
                total_count=0,
                result_code=0,
                time_elapsed=0.1,
                has_more_pages=False,
            )

            # Step 4: Domain processing of results
            if result_processor:
                processed_results = result_processor(mock_results)
            # Default processing based on search type
            elif "person" in search_request.filter_str:
                processed_results = self.process_user_search_results(mock_results)
            elif "group" in search_request.filter_str:
                processed_results = self.process_group_search_results(mock_results)
            else:
                processed_results = FlextCore.Result[FlextLdapModels.SearchResponse].ok(
                    mock_results,
                )

            if processed_results.is_failure:
                return FlextCore.Result[FlextLdapModels.SearchResponse].fail(
                    processed_results.error or "Result processing failed",
                )

            final_results = processed_results.unwrap()

            logger.info(
                "Search operation coordinated",
                base_dn=search_request.base_dn,
                filter=search_request.filter_str,
                result_count=final_results.total_count,
            )

            return FlextCore.Result[FlextLdapModels.SearchResponse].ok(final_results)

        except Exception as e:
            logger.exception("Search coordination failed", error=str(e))
            return FlextCore.Result[FlextLdapModels.SearchResponse].fail(
                f"Coordination failed: {e}",
            )

    # =============================================================================
    # BUSINESS WORKFLOW SERVICES
    # =============================================================================

    def execute_user_provisioning_workflow(
        self,
        user_request: FlextLdapModels.CreateUserRequest,
    ) -> FlextCore.Result[FlextLdapModels.LdapUser]:
        """Execute complete user provisioning workflow with domain orchestration.

        This method orchestrates the entire user provisioning process:
        1. Domain validation of request
        2. Domain enrichment with business rules
        3. Infrastructure coordination (mocked here)
        4. Domain post-processing

        Args:
            user_request: User creation request

        Returns:
            FlextCore.Result with created User entity

        """
        try:
            # Step 1: Domain validation
            validation_result = self.validate_user_creation_request(user_request)
            if validation_result.is_failure:
                return FlextCore.Result[FlextLdapModels.LdapUser].fail(
                    validation_result.error or "User validation failed",
                )

            # Step 2: Domain enrichment
            enrichment_result = self.enrich_user_for_creation(user_request)
            if enrichment_result.is_failure:
                return FlextCore.Result[FlextLdapModels.LdapUser].fail(
                    enrichment_result.error or "User enrichment failed",
                )

            enriched_request = enrichment_result.unwrap()

            # Step 3: Business logic application
            # Apply domain-specific business rules before creation
            # (This would coordinate with infrastructure in real implementation)

            # Step 4: Create user entity (infrastructure layer)
            # In real implementation, this would call repository to persist to LDAP
            created_user = FlextLdapModels.LdapUser(
                dn=enriched_request.dn,
                uid=enriched_request.uid,
                cn=enriched_request.cn,
                sn=enriched_request.sn,
                mail=enriched_request.mail,
                given_name=enriched_request.given_name,
            )

            # Step 5: Domain post-processing
            # Apply domain services for enrichment
            display_name = FlextLdapDomain.DomainServices.calculate_user_display_name(
                created_user,
            )
            logger.debug(
                "Calculated user display name",
                display_name=display_name,
                uid=created_user.uid,
            )

            logger.info(
                "User provisioning workflow completed",
                uid=created_user.uid,
                dn=created_user.dn,
            )

            # Return LdapUser as-is - it IS a User type

            return FlextCore.Result[FlextLdapModels.LdapUser].ok(created_user)

        except Exception as e:
            logger.exception("User provisioning workflow failed", error=str(e))
            return FlextCore.Result[FlextLdapModels.LdapUser].fail(
                f"Workflow failed: {e}"
            )

    # =============================================================================
    # UTILITY SERVICES
    # =============================================================================

    def validate_ldap_configuration(
        self,
        config_data: dict,
    ) -> FlextCore.Result[FlextCore.Types.Dict]:
        """Validate LDAP configuration against domain requirements.

        Args:
            config_data: Configuration data to validate

        Returns:
            FlextCore.Result with validated configuration

        """
        try:
            # Domain validation: required fields
            required_fields = ["ldap_server", "ldap_port", "base_dn"]
            for field in required_fields:
                if field not in config_data:
                    return FlextCore.Result[FlextCore.Types.Dict].fail(
                        f"Missing required field: {field}",
                    )

            # Domain validation: server format
            server = config_data.get(FlextLdapConstants.DictKeys.LDAP_SERVER)
            if not server or not isinstance(server, str):
                return FlextCore.Result[FlextCore.Types.Dict].fail(
                    "Invalid LDAP server"
                )

            # Domain validation: port range
            port = config_data.get(FlextLdapConstants.DictKeys.LDAP_PORT)
            if not isinstance(port, int) or not (
                1 <= port <= FlextCore.Constants.Network.MAX_PORT
            ):
                return FlextCore.Result[FlextCore.Types.Dict].fail("Invalid LDAP port")

            # Domain validation: base DN format
            base_dn = config_data.get(FlextLdapConstants.DictKeys.BASE_DN)
            if not base_dn:
                return FlextCore.Result[FlextCore.Types.Dict].fail(
                    "Base DN cannot be empty"
                )

            # Try to create DN value object for validation
            try:
                FlextLdapModels.DistinguishedName.from_string(base_dn)
            except Exception as e:
                return FlextCore.Result[FlextCore.Types.Dict].fail(
                    f"Invalid base DN format: {e}"
                )

            logger.info("LDAP configuration validated", server=server, port=port)

            return FlextCore.Result[FlextCore.Types.Dict].ok(config_data)

        except Exception as e:
            logger.exception("LDAP configuration validation failed", error=str(e))
            return FlextCore.Result[FlextCore.Types.Dict].fail(
                f"Validation failed: {e}"
            )

    def generate_ldap_operation_report(
        self,
        operations: list[FlextCore.Types.Dict],
    ) -> FlextCore.Result[FlextCore.Types.Dict]:
        """Generate domain-level report for LDAP operations.

        Args:
            operations: List of operation records

        Returns:
            FlextCore.Result with operation report

        """
        try:
            # Domain analysis: categorize operations
            operation_counts: dict[str, int] = {}
            success_count = 0
            failure_count = 0

            for op in operations:
                op_type_raw = op.get(FlextLdapConstants.DictKeys.TYPE, "unknown")
                op_type = str(op_type_raw) if op_type_raw is not None else "unknown"
                operation_counts[op_type] = operation_counts.get(op_type, 0) + 1

                if op.get(FlextLdapConstants.DictKeys.SUCCESS, False):
                    success_count += 1
                else:
                    failure_count += 1

            # Domain insights
            total_ops = len(operations)
            success_rate = (success_count / total_ops * 100) if total_ops > 0 else 0

            report = {
                "total_operations": total_ops,
                "successful_operations": success_count,
                "failed_operations": failure_count,
                "success_rate": round(float(success_rate), 2),
                "operation_breakdown": operation_counts,
                "generated_at": "2025-01-08T00:00:00Z",  # Would use datetime.utcnow()
            }

            logger.info(
                "LDAP operation report generated",
                total_operations=total_ops,
                success_rate=success_rate,
            )

            return FlextCore.Result[FlextCore.Types.Dict].ok(report)

        except Exception as e:
            logger.exception("LDAP operation report generation failed", error=str(e))
            return FlextCore.Result[FlextCore.Types.Dict].fail(
                f"Report generation failed: {e}"
            )

    def execute(self) -> FlextCore.Result[None]:
        """Execute the main domain operation (required by FlextCore.Service)."""
        return FlextCore.Result[None].ok(None)


__all__ = [
    "FlextLdapServices",
]
