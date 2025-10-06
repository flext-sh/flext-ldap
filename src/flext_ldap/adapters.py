"""Infrastructure adapters for flext-ldap.

This module contains adapters that interface between the domain layer
and external infrastructure (ldap3 library). Adapters implement domain
interfaces using infrastructure-specific code.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import time
from typing import Any, Callable, Literal

from flext_core import FlextLogger, FlextResult, FlextTypes
from flext_ldap.models import FlextLdapModels

logger = FlextLogger(__name__)


class FlextLdapAdapters:
    """Namespace class for all LDAP infrastructure adapters.

    Adapters implement the interface between domain models and external
    infrastructure (ldap3). They translate domain objects to infrastructure
    calls and infrastructure responses back to domain objects.
    """

    class Ldap3EntryAdapter:
        """Adapter for converting between ldap3 entries and domain entities."""

        @staticmethod
        def entry_to_domain(entry: Any) -> FlextResult[FlextLdapModels.Entry]:
            """Convert ldap3 Entry to domain Entry entity.

            Args:
                entry: ldap3 Entry object

            Returns:
                FlextResult with domain Entry entity

            """
            try:
                # Extract DN
                dn = str(getattr(entry, "entry_dn", ""))

                # Extract attributes
                attributes = {}

                if hasattr(entry, "entry_attributes"):
                    attributes = dict(entry.entry_attributes)

                # Create domain entity
                domain_entry = FlextLdapModels.Entry(dn=dn, attributes=attributes)

                return FlextResult[FlextLdapModels.Entry].ok(domain_entry)

            except Exception as e:
                logger.error("Failed to convert ldap3 entry to domain", error=str(e))
                return FlextResult[FlextLdapModels.Entry].fail(
                    f"Entry conversion failed: {e}"
                )

        @staticmethod
        def entries_to_domain(
            entries: list[Any],
        ) -> FlextResult[list[FlextLdapModels.Entry]]:
            """Convert list of ldap3 entries to domain entries.

            Args:
                entries: List of ldap3 Entry objects

            Returns:
                FlextResult with list of domain Entry entities

            """
            try:
                domain_entries = []
                for entry in entries:
                    conversion_result = (
                        FlextLdapAdapters.Ldap3EntryAdapter.entry_to_domain(entry)
                    )
                    if conversion_result.is_failure:
                        logger.warning(
                            "Failed to convert entry, skipping",
                            error=conversion_result.error,
                        )
                        continue
                    domain_entries.append(conversion_result.unwrap())

                return FlextResult[list[FlextLdapModels.Entry]].ok(domain_entries)

            except Exception as e:
                logger.error("Failed to convert ldap3 entries to domain", error=str(e))
                return FlextResult[list[FlextLdapModels.Entry]].fail(
                    f"Entries conversion failed: {e}"
                )

        @staticmethod
        def domain_to_ldap3_attributes(attributes: FlextTypes.Dict) -> FlextTypes.Dict:
            """Convert domain attributes to ldap3 format.

            Args:
                attributes: Domain attribute dictionary

            Returns:
                ldap3-compatible attribute dictionary

            """
            # For now, pass through - ldap3 accepts standard dict format
            # In more complex cases, this might need type conversions
            return attributes.copy()

    class Ldap3SearchAdapter:
        """Adapter for converting search requests/responses between domain and ldap3."""

        @staticmethod
        def domain_request_to_ldap3(
            request: FlextLdapModels.SearchRequest,
        ) -> FlextTypes.Dict:
            """Convert domain SearchRequest to ldap3 search parameters.

            Args:
                request: Domain search request

            Returns:
                ldap3 search parameters dictionary

            """
            # Map domain scope to ldap3 scope
            scope_map: dict[str, Literal["BASE", "LEVEL", "SUBTREE"]] = {
                "base": "BASE",
                "one": "LEVEL",
                "subtree": "SUBTREE",
            }

            ldap3_params = {
                "search_base": request.base_dn,
                "search_filter": request.filter_str,
                "search_scope": scope_map.get(request.scope, "SUBTREE"),
                "attributes": request.attributes,
                "size_limit": request.size_limit,
                "time_limit": request.time_limit,
            }

            return dict(ldap3_params)  # Cast to dict[str, object]

        @staticmethod
        def ldap3_response_to_domain(
            entries: list[Any], search_time: float = 0.0
        ) -> FlextResult[FlextLdapModels.SearchResponse]:
            """Convert ldap3 search response to domain SearchResponse.

            Args:
                entries: ldap3 search result entries
                search_time: Time taken for search

            Returns:
                FlextResult with domain SearchResponse

            """
            try:
                # Convert entries
                entries_result = FlextLdapAdapters.Ldap3EntryAdapter.entries_to_domain(
                    entries
                )
                if entries_result.is_failure:
                    return FlextResult[FlextLdapModels.SearchResponse].fail(
                        entries_result.error or "Entry conversion failed"
                    )

                domain_entries = entries_result.unwrap()

                # Create response
                response = FlextLdapModels.SearchResponse(
                    entries=domain_entries,
                    total_count=len(domain_entries),
                    result_code=0,  # Success
                    time_elapsed=search_time,
                )

                return FlextResult[FlextLdapModels.SearchResponse].ok(response)

            except Exception as e:
                logger.error("Failed to convert ldap3 response to domain", error=str(e))
                return FlextResult[FlextLdapModels.SearchResponse].fail(
                    f"Response conversion failed: {e}"
                )

    class Ldap3ConnectionAdapter:
        """Adapter for LDAP connection management with ldap3."""

        @staticmethod
        def validate_connection_params(
            server: str,
            port: int,
            use_ssl: bool = False,
            user: str | None = None,
            password: str | None = None,
        ) -> FlextResult[FlextTypes.Dict]:
            """Validate and prepare connection parameters for ldap3.

            Args:
                server: LDAP server hostname/IP
                port: LDAP server port
                use_ssl: Whether to use SSL/TLS
                user: Bind username
                password: Bind password

            Returns:
                FlextResult with validated connection parameters

            """
            try:
                # Validate server
                if not server or not server.strip():
                    return FlextResult[FlextTypes.Dict].fail("Server cannot be empty")

                # Validate port
                if not isinstance(port, int) or not (1 <= port <= 65535):
                    return FlextResult[FlextTypes.Dict].fail("Invalid port number")

                # Prepare connection parameters
                params = {
                    "server": server.strip(),
                    "port": port,
                    "use_ssl": use_ssl,
                }

                # Add authentication if provided
                if user and password:
                    params["user"] = user
                    params["password"] = password
                    params["authentication"] = "SIMPLE"
                elif user or password:
                    return FlextResult[FlextTypes.Dict].fail(
                        "Both user and password must be provided for authentication"
                    )

                return FlextResult[FlextTypes.Dict].ok(dict(params))

            except Exception as e:
                logger.error("Connection parameter validation failed", error=str(e))
                return FlextResult[FlextTypes.Dict].fail(
                    f"Parameter validation failed: {e}"
                )

        @staticmethod
        def create_connection_config(
            server: str,
            port: int,
            base_dn: str,
            use_ssl: bool = False,
            timeout: int = 30,
        ) -> FlextResult[FlextTypes.Dict]:
            """Create complete ldap3 connection configuration.

            Args:
                server: LDAP server
                port: LDAP port
                base_dn: Base DN
                use_ssl: Use SSL/TLS
                timeout: Connection timeout

            Returns:
                FlextResult with ldap3 connection configuration

            """
            try:
                # Validate base DN
                dn_result = FlextLdapModels.DistinguishedName.create(base_dn)
                if dn_result.is_failure:
                    return FlextResult[FlextTypes.Dict].fail(
                        f"Invalid base DN: {dn_result.error}"
                    )

                config = {
                    "server": server,
                    "port": port,
                    "base_dn": base_dn,
                    "use_ssl": use_ssl,
                    "timeout": timeout,
                    "client_strategy": "SYNC",  # Synchronous operations
                    "auto_bind": False,  # Manual bind control
                    "pool_name": "flext-ldap-pool",
                    "pool_size": 5,
                    "pool_lifetime": 3600,  # 1 hour
                }

                return FlextResult[FlextTypes.Dict].ok(dict(config))

            except Exception as e:
                logger.error("Connection config creation failed", error=str(e))
                return FlextResult[FlextTypes.Dict].fail(f"Config creation failed: {e}")

    class Ldap3ModifyAdapter:
        """Adapter for LDAP modify operations with ldap3."""

        @staticmethod
        def prepare_add_operation(
            dn: str, attributes: FlextTypes.Dict
        ) -> FlextResult[FlextTypes.Dict]:
            """Prepare add operation parameters for ldap3.

            Args:
                dn: DN of entry to add
                attributes: Entry attributes

            Returns:
                FlextResult with ldap3 add operation parameters

            """
            try:
                # Validate DN
                dn_result = FlextLdapModels.DistinguishedName.create(dn)
                if dn_result.is_failure:
                    return FlextResult[FlextTypes.Dict].fail(
                        f"Invalid DN: {dn_result.error}"
                    )

                # Convert attributes to ldap3 format
                ldap3_attrs = (
                    FlextLdapAdapters.Ldap3EntryAdapter.domain_to_ldap3_attributes(
                        attributes
                    )
                )

                params = {
                    "dn": dn,
                    "attributes": ldap3_attrs,
                }

                return FlextResult[FlextTypes.Dict].ok(dict(params))

            except Exception as e:
                logger.error("Add operation preparation failed", error=str(e))
                return FlextResult[FlextTypes.Dict].fail(f"Preparation failed: {e}")

        @staticmethod
        def prepare_modify_operation(
            dn: str, changes: FlextTypes.Dict
        ) -> FlextResult[FlextTypes.Dict]:
            """Prepare modify operation parameters for ldap3.

            Args:
                dn: DN of entry to modify
                changes: Attribute changes

            Returns:
                FlextResult with ldap3 modify operation parameters

            """
            try:
                # Validate DN
                dn_result = FlextLdapModels.DistinguishedName.create(dn)
                if dn_result.is_failure:
                    return FlextResult[FlextTypes.Dict].fail(
                        f"Invalid DN: {dn_result.error}"
                    )

                # Convert changes to ldap3 modify format
                # ldap3 expects: {'attribute': [(MODIFY_ADD/MODIFY_REPLACE/MODIFY_DELETE, [values])]}
                ldap3_changes = {}

                for attr, change_spec in changes.items():
                    if isinstance(change_spec, dict):
                        operation = change_spec.get("operation", "replace")
                        values = change_spec.get("values", [])

                        # Map operations
                        op_map = {
                            "add": "MODIFY_ADD",
                            "replace": "MODIFY_REPLACE",
                            "delete": "MODIFY_DELETE",
                        }

                        ldap3_op = op_map.get(operation, "MODIFY_REPLACE")
                        ldap3_changes[attr] = [(ldap3_op, values)]
                    else:
                        # Simple replace
                        ldap3_changes[attr] = [("MODIFY_REPLACE", [change_spec])]

                params = {
                    "dn": dn,
                    "changes": ldap3_changes,
                }

                return FlextResult[FlextTypes.Dict].ok(dict(params))

            except Exception as e:
                logger.error("Modify operation preparation failed", error=str(e))
                return FlextResult[FlextTypes.Dict].fail(f"Preparation failed: {e}")

        @staticmethod
        def prepare_delete_operation(dn: str) -> FlextResult[FlextTypes.Dict]:
            """Prepare delete operation parameters for ldap3.

            Args:
                dn: DN of entry to delete

            Returns:
                FlextResult with ldap3 delete operation parameters

            """
            try:
                # Validate DN
                dn_result = FlextLdapModels.DistinguishedName.create(dn)
                if dn_result.is_failure:
                    return FlextResult[FlextTypes.Dict].fail(
                        f"Invalid DN: {dn_result.error}"
                    )

                params: FlextTypes.Dict = {"dn": dn}

                return FlextResult[FlextTypes.Dict].ok(dict(params))

            except Exception as e:
                logger.error("Delete operation preparation failed", error=str(e))
                return FlextResult[FlextTypes.Dict].fail(f"Preparation failed: {e}")

    class Ldap3ErrorAdapter:
        """Adapter for converting ldap3 errors to domain-friendly formats."""

        @staticmethod
        def adapt_ldap3_error(exception: Exception) -> str:
            """Convert ldap3 exception to user-friendly error message.

            Args:
                exception: ldap3 exception

            Returns:
                User-friendly error message

            """
            try:
                # Get exception type and message
                exc_type = type(exception).__name__
                exc_msg = str(exception)

                # Map common ldap3 errors to user-friendly messages
                error_mappings = {
                    "LDAPSocketOpenError": "Cannot connect to LDAP server - check server address and port",
                    "LDAPBindError": "LDAP authentication failed - check credentials",
                    "LDAPInvalidCredentialsResult": "Invalid username or password",
                    "LDAPNoSuchObjectResult": "Entry not found in directory",
                    "LDAPAttributeOrValueExistsResult": "Attribute or value already exists",
                    "LDAPConstraintViolationResult": "Operation violates directory constraints",
                    "LDAPSizeLimitExceededResult": "Search results exceed size limit",
                    "LDAPTimeLimitExceededResult": "Search operation timed out",
                }

                # Check for known error types
                for ldap3_error, friendly_msg in error_mappings.items():
                    if ldap3_error in exc_type:
                        return friendly_msg

                # Generic ldap3 error
                if "LDAP" in exc_type:
                    return f"LDAP operation failed: {exc_msg}"

                # Fallback to generic message
                return f"Directory operation failed: {exc_msg}"

            except Exception as e:
                logger.error("Error adaptation failed", error=str(e))
                return "An unexpected error occurred during directory operation"

        @staticmethod
        def is_retryable_error(exception: Exception) -> bool:
            """Determine if an ldap3 error is retryable.

            Args:
                exception: ldap3 exception

            Returns:
                True if error is retryable

            """
            retryable_errors = [
                "LDAPSocketOpenError",
                "LDAPSessionTerminatedByServerError",
                "LDAPMaximumRetriesError",
                "LDAPBusyResult",
                "LDAPUnavailableResult",
            ]

            exc_type = type(exception).__name__
            return any(err in exc_type for err in retryable_errors)

        @staticmethod
        def get_error_category(exception: Exception) -> str:
            """Categorize ldap3 error for logging and handling.

            Args:
                exception: ldap3 exception

            Returns:
                Error category string

            """
            exc_type = type(exception).__name__

            if "LDAPBindError" in exc_type or "LDAPInvalidCredentials" in exc_type:
                return "authentication"
            if "LDAPSocketOpenError" in exc_type or "LDAPSessionTerminated" in exc_type:
                return "connection"
            if "LDAPNoSuchObject" in exc_type:
                return "not_found"
            if (
                "LDAPSizeLimitExceeded" in exc_type
                or "LDAPTimeLimitExceeded" in exc_type
            ):
                return "limits"
            if (
                "LDAPConstraintViolation" in exc_type
                or "LDAPAttributeOrValueExists" in exc_type
            ):
                return "constraint"
            return "unknown"

    class Ldap3PerformanceAdapter:
        """Adapter for monitoring ldap3 operation performance."""

        @staticmethod
        def measure_operation_time(operation_func: Callable, *args, **kwargs) -> tuple:
            """Measure execution time of an ldap3 operation.

            Args:
                operation_func: Function to measure
                *args: Positional arguments for function
                **kwargs: Keyword arguments for function

            Returns:
                Tuple of (result, execution_time)

            """
            start_time = time.time()

            try:
                result = operation_func(*args, **kwargs)
                execution_time = time.time() - start_time
                return result, execution_time
            except Exception as e:
                execution_time = time.time() - start_time
                raise e

        @staticmethod
        def log_operation_metrics(
            operation: str,
            execution_time: float,
            success: bool,
            result_count: int | None = None,
        ) -> None:
            """Log performance metrics for LDAP operations.

            Args:
                operation: Operation name
                execution_time: Time taken in seconds
                success: Whether operation succeeded
                result_count: Number of results (for searches)

            """
            log_data = {
                "operation": operation,
                "execution_time": round(execution_time, 3),
                "success": success,
            }

            if result_count is not None:
                log_data["result_count"] = result_count

            if success:
                logger.info("LDAP operation completed", **log_data)
            else:
                logger.warning("LDAP operation failed", **log_data)


__all__ = [
    "FlextLdapAdapters",
]
