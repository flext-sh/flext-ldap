#!/usr/bin/env python3
"""Validation Helpers - Shared utilities for comprehensive LDAP validation.

This module provides helper functions and utilities for validating
flext-ldap API functionality across different LDAP servers.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from flext_core import FlextLogger, FlextTypes

from flext_ldap import FlextLdap, FlextLdapConstants, FlextLdapModels

logger: FlextLogger = FlextLogger(__name__)


class ValidationMetrics:
    """Track validation metrics and results."""

    def __init__(self) -> None:
        """Initialize validation metrics."""
        self.total_tests = 0
        self.passed_tests = 0
        self.failed_tests = 0
        self.skipped_tests = 0
        self.test_results: list[dict[str, Any]] = []

    def add_result(
        self,
        test_name: str,
        status: str,
        message: str,
        duration: float | None = None,
    ) -> None:
        """Add a test result.

        Args:
            test_name: Name of the test
            status: Test status (pass, fail, skip)
            message: Result message
            duration: Test duration in seconds

        """
        self.total_tests += 1

        if status == "pass":
            self.passed_tests += 1
        elif status == "fail":
            self.failed_tests += 1
        elif status == "skip":
            self.skipped_tests += 1

        self.test_results.append({
            "test_name": test_name,
            "status": status,
            "message": message,
            "duration": duration,
        })

    def print_summary(self) -> None:
        """Print validation summary."""
        separator = "=" * 80
        logger.info(f"\n{separator}")
        logger.info("VALIDATION SUMMARY")
        logger.info(separator)
        logger.info(f"Total Tests: {self.total_tests}")
        logger.info(f"Passed: {self.passed_tests} ✅")
        logger.info(f"Failed: {self.failed_tests} ❌")
        logger.info(f"Skipped: {self.skipped_tests} ⏭️")

        success_rate = (self.passed_tests / self.total_tests * 100) if self.total_tests > 0 else 0
        logger.info(f"Success Rate: {success_rate:.1f}%")
        logger.info("=" * 80)

        # Print failed tests
        failed = [r for r in self.test_results if r["status"] == "fail"]
        if failed:
            logger.info("\nFAILED TESTS:")
            for result in failed:
                logger.info(f"  ❌ {result['test_name']}: {result['message']}")

    def get_summary(self) -> dict[str, Any]:
        """Get validation summary as dictionary.

        Returns:
            Dictionary with validation results

        """
        return {
            "total_tests": self.total_tests,
            "passed_tests": self.passed_tests,
            "failed_tests": self.failed_tests,
            "skipped_tests": self.skipped_tests,
            "success_rate": (self.passed_tests / self.total_tests * 100) if self.total_tests > 0 else 0,
            "test_results": self.test_results,
        }


def measure_time(func: Callable[..., Any]) -> Callable[..., tuple[Any, float]]:
    """Decorator to measure function execution time.

    Args:
        func: Function to measure

    Returns:
        Decorated function that returns (result, duration)

    """
    def wrapper(*args: Any, **kwargs: Any) -> tuple[Any, float]:
        start_time = time.time()
        result = func(*args, **kwargs)
        duration = time.time() - start_time
        return result, duration

    return wrapper


def validate_connection(
    api: FlextLdap,
    metrics: ValidationMetrics,
) -> bool:
    """Validate LDAP connection.

    Args:
        api: FlextLdap instance
        metrics: ValidationMetrics to track results

    Returns:
        True if connection is valid

    """
    test_name = "Connection Validation"
    logger.info(f"\n=== {test_name} ===")

    try:
        start_time = time.time()

        if not api.is_connected():
            duration = time.time() - start_time
            metrics.add_result(test_name, "fail", "Not connected to LDAP server", duration)
            return False

        test_result = api.test_connection()
        duration = time.time() - start_time

        if test_result.is_failure:
            metrics.add_result(test_name, "fail", f"Connection test failed: {test_result.error}", duration)
            return False

        metrics.add_result(test_name, "pass", "Connection validated successfully", duration)
        logger.info(f"✅ {test_name} passed ({duration:.2f}s)")
        return True

    except Exception as e:
        duration = time.time() - start_time
        metrics.add_result(test_name, "fail", f"Exception: {e}", duration)
        logger.exception(f"❌ {test_name} failed")
        return False


def validate_search_operations(
    api: FlextLdap,
    base_dn: str,
    metrics: ValidationMetrics,
) -> bool:
    """Validate search operations.

    Args:
        api: FlextLdap instance
        base_dn: Base DN for searches
        metrics: ValidationMetrics to track results

    Returns:
        True if all search operations are valid

    """
    test_name = "Search Operations"
    logger.info(f"\n=== {test_name} ===")

    all_passed = True

    # Test 1: Basic search with filter
    try:
        start_time = time.time()
        search_request = FlextLdapModels.SearchRequest(
            base_dn=base_dn,
            filter_str="(objectClass=*)",
            scope=FlextLdapConstants.Scopes.SUBTREE,
            attributes=["*"],
        )
        result = api.search(search_request)
        duration = time.time() - start_time

        if result.is_failure:
            metrics.add_result(f"{test_name} - Basic Search", "fail", result.error or "Unknown error", duration)
            all_passed = False
        else:
            entries = result.unwrap()
            metrics.add_result(f"{test_name} - Basic Search", "pass", f"Found {len(entries)} entries", duration)
            logger.info(f"✅ Basic search: {len(entries)} entries ({duration:.2f}s)")

    except Exception as e:
        duration = time.time() - start_time
        metrics.add_result(f"{test_name} - Basic Search", "fail", f"Exception: {e}", duration)
        all_passed = False

    # Test 2: Search with different scopes
    for scope, scope_name in [
        (FlextLdapConstants.Scopes.BASE, "BASE"),
        (FlextLdapConstants.Scopes.ONELEVEL, "ONELEVEL"),
        (FlextLdapConstants.Scopes.SUBTREE, "SUBTREE"),
    ]:
        try:
            start_time = time.time()
            search_request = FlextLdapModels.SearchRequest(
                base_dn=base_dn,
                filter_str="(objectClass=*)",
                scope=scope,
                attributes=["dn"],
            )
            result = api.search(search_request)
            duration = time.time() - start_time

            if result.is_failure:
                metrics.add_result(f"{test_name} - Scope {scope_name}", "fail", result.error or "Unknown error", duration)
                all_passed = False
            else:
                entries = result.unwrap()
                metrics.add_result(f"{test_name} - Scope {scope_name}", "pass", f"Found {len(entries)} entries", duration)
                logger.info(f"✅ Search scope {scope_name}: {len(entries)} entries ({duration:.2f}s)")

        except Exception as e:
            duration = time.time() - start_time
            metrics.add_result(f"{test_name} - Scope {scope_name}", "fail", f"Exception: {e}", duration)
            all_passed = False

    # Test 3: Search users
    try:
        start_time = time.time()
        users_dn = f"ou=users,{base_dn}"
        result = api.search_users(users_dn)
        duration = time.time() - start_time

        if result.is_failure:
            metrics.add_result(f"{test_name} - Search Users", "fail", result.error or "Unknown error", duration)
            all_passed = False
        else:
            users = result.unwrap()
            metrics.add_result(f"{test_name} - Search Users", "pass", f"Found {len(users)} users", duration)
            logger.info(f"✅ Search users: {len(users)} users ({duration:.2f}s)")

    except Exception as e:
        duration = time.time() - start_time
        metrics.add_result(f"{test_name} - Search Users", "fail", f"Exception: {e}", duration)
        all_passed = False

    # Test 4: Search groups
    try:
        start_time = time.time()
        groups_dn = f"ou=groups,{base_dn}"
        result = api.search_groups(groups_dn)
        duration = time.time() - start_time

        if result.is_failure:
            metrics.add_result(f"{test_name} - Search Groups", "fail", result.error or "Unknown error", duration)
            all_passed = False
        else:
            groups = result.unwrap()
            metrics.add_result(f"{test_name} - Search Groups", "pass", f"Found {len(groups)} groups", duration)
            logger.info(f"✅ Search groups: {len(groups)} groups ({duration:.2f}s)")

    except Exception as e:
        duration = time.time() - start_time
        metrics.add_result(f"{test_name} - Search Groups", "fail", f"Exception: {e}", duration)
        all_passed = False

    return all_passed


def validate_crud_operations(
    api: FlextLdap,
    base_dn: str,
    metrics: ValidationMetrics,
) -> bool:
    """Validate CRUD operations.

    Args:
        api: FlextLdap instance
        base_dn: Base DN for operations
        metrics: ValidationMetrics to track results

    Returns:
        True if all CRUD operations are valid

    """
    test_name = "CRUD Operations"
    logger.info(f"\n=== {test_name} ===")

    test_dn = f"cn=test-crud-user,ou=users,{base_dn}"
    all_passed = True

    # Test 0: Ensure parent OU exists (create if needed)
    try:
        start_time = time.time()
        parent_ou_dn = f"ou=users,{base_dn}"

        # Check if parent OU exists
        search_result = api.search(
            FlextLdapModels.SearchRequest(
                base_dn=parent_ou_dn,
                filter_str="(objectClass=*)",
                scope=FlextLdapConstants.Scopes.BASE,
            )
        )

        # Create parent OU if it doesn't exist
        if search_result.is_failure or not search_result.unwrap():
            ou_attributes: dict[str, str | FlextTypes.StringList] = {
                FlextLdapConstants.LdapAttributeNames.OBJECT_CLASS: [
                    FlextLdapConstants.ObjectClasses.ORGANIZATIONAL_UNIT,
                    FlextLdapConstants.ObjectClasses.TOP,
                ],
                FlextLdapConstants.LdapAttributeNames.OU: "users",
            }
            create_ou_result = api.add_entry(parent_ou_dn, ou_attributes)
            if create_ou_result.is_failure:
                logger.warning(f"Could not create parent OU {parent_ou_dn}: {create_ou_result.error}")

        duration = time.time() - start_time
    except Exception as e:
        logger.warning(f"Parent OU check failed: {e}")

    # Test 1: Create entry
    try:
        start_time = time.time()
        attributes: dict[str, str | FlextTypes.StringList] = {
            FlextLdapConstants.LdapAttributeNames.OBJECT_CLASS: [
                FlextLdapConstants.ObjectClasses.INET_ORG_PERSON,
                FlextLdapConstants.ObjectClasses.ORGANIZATIONAL_PERSON,
                FlextLdapConstants.ObjectClasses.PERSON,
                FlextLdapConstants.ObjectClasses.TOP,
            ],
            FlextLdapConstants.LdapAttributeNames.CN: "test-crud-user",
            FlextLdapConstants.LdapAttributeNames.SN: "CrudUser",
            FlextLdapConstants.LdapAttributeNames.GIVEN_NAME: "Test",
            FlextLdapConstants.LdapAttributeNames.UID: "testcrud",
            FlextLdapConstants.LdapAttributeNames.MAIL: "testcrud@internal.invalid",
        }

        result = api.add_entry(test_dn, attributes)
        duration = time.time() - start_time

        if result.is_failure:
            metrics.add_result(f"{test_name} - Create Entry", "fail", result.error or "Unknown error", duration)
            return False  # Can't continue if create fails
        metrics.add_result(f"{test_name} - Create Entry", "pass", "Entry created successfully", duration)
        logger.info(f"✅ Create entry: {test_dn} ({duration:.2f}s)")

    except Exception as e:
        duration = time.time() - start_time
        metrics.add_result(f"{test_name} - Create Entry", "fail", f"Exception: {e}", duration)
        return False

    # Test 2: Read entry
    try:
        start_time = time.time()
        result = api.search_one(
            FlextLdapModels.SearchRequest(
                base_dn=test_dn,
                filter_str="(objectClass=*)",
                scope=FlextLdapConstants.Scopes.BASE,
                attributes=["*"],
            )
        )
        duration = time.time() - start_time

        if result.is_failure:
            metrics.add_result(f"{test_name} - Read Entry", "fail", result.error or "Unknown error", duration)
            all_passed = False
        else:
            entry = result.unwrap()
            if entry:
                metrics.add_result(f"{test_name} - Read Entry", "pass", f"Entry read: {entry.dn}", duration)
                logger.info(f"✅ Read entry: {entry.dn} ({duration:.2f}s)")
            else:
                metrics.add_result(f"{test_name} - Read Entry", "fail", "Entry not found after creation", duration)
                all_passed = False

    except Exception as e:
        duration = time.time() - start_time
        metrics.add_result(f"{test_name} - Read Entry", "fail", f"Exception: {e}", duration)
        all_passed = False

    # Test 3: Update entry
    try:
        start_time = time.time()
        changes: FlextTypes.Dict = {
            FlextLdapConstants.LdapAttributeNames.DESCRIPTION: [
                ("MODIFY_REPLACE", ["Updated test entry"])
            ]
        }
        result = api.modify_entry(test_dn, changes)
        duration = time.time() - start_time

        if result.is_failure:
            metrics.add_result(f"{test_name} - Update Entry", "fail", result.error or "Unknown error", duration)
            all_passed = False
        else:
            metrics.add_result(f"{test_name} - Update Entry", "pass", "Entry updated successfully", duration)
            logger.info(f"✅ Update entry: {test_dn} ({duration:.2f}s)")

    except Exception as e:
        duration = time.time() - start_time
        metrics.add_result(f"{test_name} - Update Entry", "fail", f"Exception: {e}", duration)
        all_passed = False

    # Test 4: Delete entry
    try:
        start_time = time.time()
        result = api.delete_entry(test_dn)
        duration = time.time() - start_time

        if result.is_failure:
            metrics.add_result(f"{test_name} - Delete Entry", "fail", result.error or "Unknown error", duration)
            all_passed = False
        else:
            metrics.add_result(f"{test_name} - Delete Entry", "pass", "Entry deleted successfully", duration)
            logger.info(f"✅ Delete entry: {test_dn} ({duration:.2f}s)")

    except Exception as e:
        duration = time.time() - start_time
        metrics.add_result(f"{test_name} - Delete Entry", "fail", f"Exception: {e}", duration)
        all_passed = False

    return all_passed


def validate_batch_operations(
    api: FlextLdap,
    base_dn: str,
    metrics: ValidationMetrics,
    batch_size: int = 10,
) -> bool:
    """Validate batch operations.

    Args:
        api: FlextLdap instance
        base_dn: Base DN for operations
        metrics: ValidationMetrics to track results
        batch_size: Number of entries to create in batch

    Returns:
        True if batch operations are valid

    """
    test_name = "Batch Operations"
    logger.info(f"\n=== {test_name} ===")

    all_passed = True

    # Test 1: Batch add entries
    try:
        start_time = time.time()
        entries: list[tuple[str, dict[str, str | FlextTypes.StringList]]] = []

        for i in range(batch_size):
            dn = f"cn=batch-test-{i},ou=users,{base_dn}"
            attributes: dict[str, str | FlextTypes.StringList] = {
                FlextLdapConstants.LdapAttributeNames.OBJECT_CLASS: [
                    FlextLdapConstants.ObjectClasses.INET_ORG_PERSON,
                    FlextLdapConstants.ObjectClasses.ORGANIZATIONAL_PERSON,
                    FlextLdapConstants.ObjectClasses.PERSON,
                    FlextLdapConstants.ObjectClasses.TOP,
                ],
                FlextLdapConstants.LdapAttributeNames.CN: f"batch-test-{i}",
                FlextLdapConstants.LdapAttributeNames.SN: f"BatchTest{i}",
                FlextLdapConstants.LdapAttributeNames.UID: f"batchtest{i}",
                FlextLdapConstants.LdapAttributeNames.MAIL: f"batchtest{i}@internal.invalid",
            }
            entries.append((dn, attributes))

        result = api.add_entries_batch(entries)
        duration = time.time() - start_time

        if result.is_failure:
            metrics.add_result(f"{test_name} - Batch Add", "fail", result.error or "Unknown error", duration)
            all_passed = False
        else:
            results = result.unwrap()
            success_count = sum(1 for r in results if r)
            metrics.add_result(f"{test_name} - Batch Add", "pass", f"{success_count}/{batch_size} entries created", duration)
            logger.info(f"✅ Batch add: {success_count}/{batch_size} entries ({duration:.2f}s)")

            # Clean up created entries
            for dn, _ in entries:
                api.delete_entry(dn)

    except Exception as e:
        duration = time.time() - start_time
        metrics.add_result(f"{test_name} - Batch Add", "fail", f"Exception: {e}", duration)
        all_passed = False

    return all_passed


def validate_server_operations(
    api: FlextLdap,
    metrics: ValidationMetrics,
) -> bool:
    """Validate server-specific operations.

    Args:
        api: FlextLdap instance
        metrics: ValidationMetrics to track results

    Returns:
        True if server operations are valid

    """
    test_name = "Server Operations"
    logger.info(f"\n=== {test_name} ===")

    all_passed = True

    # Test 1: Get server capabilities
    try:
        start_time = time.time()
        result = api.get_server_capabilities()
        duration = time.time() - start_time

        if result.is_failure:
            metrics.add_result(f"{test_name} - Get Capabilities", "fail", result.error or "Unknown error", duration)
            all_passed = False
        else:
            capabilities = result.unwrap()
            metrics.add_result(f"{test_name} - Get Capabilities", "pass", f"Got {len(capabilities)} capabilities", duration)
            logger.info(f"✅ Server capabilities: {len(capabilities)} items ({duration:.2f}s)")

    except Exception as e:
        duration = time.time() - start_time
        metrics.add_result(f"{test_name} - Get Capabilities", "fail", f"Exception: {e}", duration)
        all_passed = False

    # Test 2: Get supported operations
    try:
        start_time = time.time()
        result = api.get_server_operations()
        duration = time.time() - start_time

        if result.is_failure:
            metrics.add_result(f"{test_name} - Get Operations", "fail", result.error or "Unknown error", duration)
            all_passed = False
        else:
            operations = result.unwrap()
            metrics.add_result(f"{test_name} - Get Operations", "pass", f"Got {len(operations)} operations", duration)
            logger.info(f"✅ Supported operations: {len(operations)} operations ({duration:.2f}s)")

    except Exception as e:
        duration = time.time() - start_time
        metrics.add_result(f"{test_name} - Get Operations", "fail", f"Exception: {e}", duration)
        all_passed = False

    return all_passed


def print_test_header(title: str) -> None:
    """Print formatted test header.

    Args:
        title: Header title

    """
    separator = "=" * 80
    logger.info(f"\n{separator}")
    logger.info(title)
    logger.info(separator)


def print_test_section(section: str) -> None:
    """Print formatted test section.

    Args:
        section: Section name

    """
    logger.info(f"\n--- {section} ---")
