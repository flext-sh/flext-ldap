"""User domain service for LDAP operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextDomainService, FlextResult
from flext_ldap.clients import FlextLdapClient
from flext_ldap.models import FlextLdapModels
from flext_ldap.typings import FlextLdapTypes
from flext_ldap.validations import FlextLdapValidations


class FlextLdapUserService(FlextDomainService):
    """Domain service for LDAP user operations.

    This service encapsulates all user-related business logic and operations
    following Domain-Driven Design patterns. It provides a clean interface
    for user management operations while maintaining proper separation of concerns.

    Attributes:
        _client: LDAP client for infrastructure operations.

    """

    def __init__(self, client: FlextLdapClient) -> None:
        """Initialize user service with LDAP client.

        Args:
            client: LDAP client for performing infrastructure operations.

        """
        super().__init__()
        self._client = client

    def execute(self) -> FlextResult[dict[str, str]]:
        """Execute the main domain service operation.

        Returns basic service information for the user service.
        """
        return FlextResult[dict[str, str]].ok({
            "service": "FlextLdapUserService",
            "status": "ready",
            "operations": "create_user,get_user,update_user,delete_user,search_users_by_filter"
        })

    async def create_user(
        self,
        user_request_or_dn: FlextLdapModels.CreateUserRequest | str,
        uid: str | None = None,
        cn: str | None = None,
        sn: str | None = None,
        mail: str | None = None,
    ) -> FlextResult[FlextLdapModels.User]:
        """Create user using proper service layer - supports both request object and individual parameters."""
        # Handle both request object and individual parameters
        if isinstance(user_request_or_dn, FlextLdapModels.CreateUserRequest):
            # First overload: request object only - validate no extra params provided
            request = user_request_or_dn
        else:
            # Second overload: individual parameters (uid, cn, sn are required)
            dn = user_request_or_dn
            if uid is None or cn is None or sn is None:
                return FlextResult[FlextLdapModels.User].fail(
                    "uid, cn, and sn are required when using individual parameters",
                )
            request = FlextLdapModels.CreateUserRequest(
                dn=dn,
                uid=uid,
                cn=cn,
                sn=sn,
                mail=mail,
                object_classes=["person", "organizationalPerson"],
            )

        # Validate DN format
        dn_validation = FlextLdapValidations.validate_dn(request.dn)
        if dn_validation.is_failure:
            return FlextResult[FlextLdapModels.User].fail(f"Invalid DN: {dn_validation.error}")

        # Create LDAP attributes from the request
        attributes: dict[str, list[str] | list[bytes] | str | bytes] = {
            "uid": [request.uid],
            "cn": [request.cn],
            "sn": [request.sn],
            "objectClass": request.object_classes,
        }
        if request.mail:
            attributes["mail"] = [request.mail]

        # Railway pattern: add entry >> create user object
        add_result = await self._client.add_entry(request.dn, attributes)
        return (
            add_result >> (lambda _: self._create_user_object(request))
        ).with_context(lambda err: f"Failed to create user {request.dn}: {err}")

    def _create_user_object(
        self, request: FlextLdapModels.CreateUserRequest
    ) -> FlextResult[FlextLdapModels.User]:
        """Create user object from request - railway helper method."""
        created_user = FlextLdapModels.User(
            id=f"user_{request.uid}",
            dn=request.dn,
            uid=request.uid,
            cn=request.cn,
            sn=request.sn,
            mail=request.mail,
            modified_at=None,
            given_name=None,
            user_password=None,
        )
        return FlextResult[FlextLdapModels.User].ok(created_user)

    async def get_user(self, dn: str) -> FlextResult[FlextLdapModels.User | None]:
        """Get user by DN."""
        # Validate DN format
        dn_validation = FlextLdapValidations.validate_dn(dn)
        if dn_validation.is_failure:
            return FlextResult[FlextLdapModels.User | None].fail(f"Invalid DN: {dn_validation.error}")

        # Search for the user by DN
        search_request = FlextLdapModels.SearchRequest(
            base_dn=dn,
            filter_str="(objectClass=person)",
            scope="base",
            attributes=["uid", "cn", "sn", "mail", "givenName"],
            size_limit=1,
            time_limit=30,
        )

        # Railway pattern: search >> process entries >> convert to user
        search_result = await self._client.search_with_request(search_request)
        return (
            search_result
            >> (lambda response: self._process_user_search_entries(response, dn))
        ).with_context(lambda err: f"Failed to get user {dn}: {err}")

    def _process_user_search_entries(
        self, search_response: FlextLdapModels.SearchResponse, dn: str
    ) -> FlextResult[FlextLdapModels.User | None]:
        """Process search response entries for user retrieval - railway helper method."""
        if not search_response.entries:
            return FlextResult[FlextLdapModels.User | None].ok(None)

        # Convert the first entry to a User object
        entry = search_response.entries[0]
        uid = self._get_entry_attribute(entry, "uid", "unknown")
        user = FlextLdapModels.User(
            id=f"user_{uid}",
            dn=dn,
            uid=uid,
            cn=self._get_entry_attribute(entry, "cn"),
            sn=self._get_entry_attribute(entry, "sn"),
            mail=self._get_entry_attribute(entry, "mail"),
            given_name=self._get_entry_attribute(entry, "givenName"),
            modified_at=None,
            user_password=None,
        )
        return FlextResult[FlextLdapModels.User | None].ok(user)

    async def update_user(
        self,
        dn: str,
        attributes: FlextLdapTypes.Entry.AttributeDict,
    ) -> FlextResult[None]:
        """Update user attributes using railway pattern."""
        # Validate DN format
        dn_validation = FlextLdapValidations.validate_dn(dn)
        if dn_validation.is_failure:
            return FlextResult[None].fail(f"Invalid DN: {dn_validation.error}")

        # Railway pattern: modify entry with context
        modify_result = await self._client.modify_entry(dn, attributes)
        return modify_result.with_context(
            lambda err: f"Failed to update user {dn}: {err}"
        )

    async def delete_user(self, dn: str) -> FlextResult[None]:
        """Delete user using railway pattern."""
        # Validate DN format
        dn_validation = FlextLdapValidations.validate_dn(dn)
        if dn_validation.is_failure:
            return FlextResult[None].fail(f"Invalid DN: {dn_validation.error}")

        # Railway pattern: delete entry with context
        delete_result = await self._client.delete(dn)
        return delete_result.with_context(
            lambda err: f"Failed to delete user {dn}: {err}"
        )

    async def search_users_by_filter(
        self,
        filter_str: str,
        base_dn: str,
        scope: str = "subtree",
    ) -> FlextResult[list[FlextLdapModels.User]]:
        """Search users with filter using railway pattern."""
        # Validate filter
        filter_validation = FlextLdapValidations.validate_filter(filter_str)
        if filter_validation.is_failure:
            return FlextResult[list[FlextLdapModels.User]].fail(f"Invalid filter: {filter_validation.error}")

        # Validate base DN
        dn_validation = FlextLdapValidations.validate_dn(base_dn)
        if dn_validation.is_failure:
            return FlextResult[list[FlextLdapModels.User]].fail(f"Invalid base DN: {dn_validation.error}")

        # Use the generic search method with user-specific filter
        search_request = FlextLdapModels.SearchRequest(
            base_dn=base_dn,
            filter_str=f"(&(objectClass=person){filter_str})",
            scope=scope,
            attributes=["uid", "cn", "mail", "objectClass"],
            size_limit=1000,
            time_limit=30,
        )

        # Railway pattern: search >> convert to users
        search_result = await self._client.search_with_request(search_request)
        return (search_result >> self._convert_search_entries_to_users).with_context(
            lambda err: f"Failed to search users with filter '{filter_str}': {err}"
        )

    def _convert_search_entries_to_users(
        self, search_response: FlextLdapModels.SearchResponse
    ) -> FlextResult[list[FlextLdapModels.User]]:
        """Convert search response entries to users - railway helper method."""
        users: list[FlextLdapModels.User] = []
        for entry in search_response.entries:
            # Create user from entry - simplified mapping
            uid = self._get_entry_attribute(entry, "uid", "unknown")
            user = FlextLdapModels.User(
                id=f"user_{uid}",
                dn=self._get_entry_attribute(entry, "dn"),
                uid=uid,
                cn=self._get_entry_attribute(entry, "cn"),
                modified_at=None,
                sn=None,
                given_name=None,
                mail=None,
                user_password=None,
            )
            users.append(user)
        return FlextResult[list[FlextLdapModels.User]].ok(users)

    async def user_exists(self, dn: str) -> FlextResult[bool]:
        """Check if user exists at DN using railway pattern."""
        # Railway pattern: get user >> check existence
        user_result = await self.get_user(dn)
        return (
            user_result >> (lambda user: FlextResult[bool].ok(user is not None))
        ).with_context(lambda err: f"Failed to check if user exists at {dn}: {err}")

    def _get_entry_attribute(
        self,
        entry: FlextLdapTypes.Core.Dict | FlextLdapModels.Entry,
        key: str,
        default: str = "",
    ) -> str:
        """Extract string attribute from entry using FlextResult monadic pipeline."""
        # Railway pattern: extract value >> convert to string >> unwrap with default
        extract_result = self._extract_entry_value(entry, key)
        return (
            extract_result >> self._convert_to_safe_string
        ).unwrap_or(default)

    def _extract_entry_value(
        self, entry: FlextLdapTypes.Core.Dict | FlextLdapModels.Entry, key: str
    ) -> FlextResult[object]:
        """Extract value from entry using type checking."""
        # Handle FlextLdapModels.Entry type
        if isinstance(entry, FlextLdapModels.Entry):
            attr_values = entry.attributes.get(key, [])
            value = attr_values[0] if attr_values else None
            return (
                FlextResult[object].ok(value)
                if value is not None
                else FlextResult[object].fail("No value found")
            )

        # Handle dict type (covers all remaining cases based on type annotation)
        dict_value: object = entry.get(key)
        return (
            FlextResult[object].ok(dict_value)
            if dict_value is not None
            else FlextResult[object].fail("No value found")
        )

    def _convert_to_safe_string(self, raw_value: object) -> FlextResult[str]:
        """Convert value to string using FlextResult railway pattern."""
        # Railway pattern: process through type handlers >> convert to string
        result = (
            FlextResult[object].ok(raw_value)
            >> self._handle_string_type
            >> self._handle_bytes_type
            >> self._handle_list_type
            >> self._handle_numeric_type
            >> (lambda value: FlextResult[str].ok(str(value)))
        )

        return result.with_context(lambda err: f"String conversion failed: {err}")

    def _handle_string_type(self, value: object) -> FlextResult[object]:
        """Handle string type conversion."""
        if isinstance(value, str):
            return (
                FlextResult[object].ok(value)
                if value
                else FlextResult[object].fail("Empty string")
            )
        return FlextResult[object].ok(value)  # Pass through for next handler

    def _handle_bytes_type(self, value: object) -> FlextResult[object]:
        """Handle bytes type conversion."""
        if isinstance(value, bytes):
            return FlextResult[object].ok(value.decode("utf-8", errors="replace"))
        return FlextResult[object].ok(value)  # Pass through for next handler

    def _handle_list_type(self, value: object) -> FlextResult[object]:
        """Handle list type conversion."""
        if isinstance(value, list):
            if not value:
                return FlextResult[object].fail("Empty list")
            first_element = value[0]
            if first_element is None or first_element == "":
                return FlextResult[object].fail("List contains None or empty first element")
            return FlextResult[object].ok(str(first_element))
        return FlextResult[object].ok(value)  # Pass through for next handler

    def _handle_numeric_type(self, value: object) -> FlextResult[object]:
        """Handle numeric type conversion."""
        if isinstance(value, (int, float, bool)):
            return FlextResult[object].ok(str(value))
        return FlextResult[object].ok(value)  # Pass through for next handler

    async def batch_create_users(
        self, user_requests: list[FlextLdapModels.CreateUserRequest]
    ) -> FlextResult[list[FlextLdapModels.User]]:
        """Create multiple users using monadic traverse pattern."""
        results: list[FlextLdapModels.User] = []
        for request in user_requests:
            result = await self.create_user(request)
            if result.is_failure:
                return FlextResult[list[FlextLdapModels.User]].fail(
                    f"User creation failed: {result.error}"
                )
            results.append(result.unwrap())
        return FlextResult[list[FlextLdapModels.User]].ok(results)

    async def batch_delete_users(self, dns: list[str]) -> FlextResult[list[None]]:
        """Delete multiple users using monadic traverse pattern."""
        results: list[None] = []
        for dn in dns:
            result = await self.delete_user(dn)
            if result.is_failure:
                return FlextResult[list[None]].fail(
                    f"User deletion failed: {result.error}"
                )
            results.append(result.unwrap())
        return FlextResult[list[None]].ok(results)

    async def batch_get_users(self, dns: list[str]) -> FlextResult[list[FlextLdapModels.User | None]]:
        """Get multiple users using monadic traverse pattern."""
        results: list[FlextLdapModels.User | None] = []
        for dn in dns:
            result = await self.get_user(dn)
            if result.is_failure:
                return FlextResult[list[FlextLdapModels.User | None]].fail(
                    f"Failed to get user {dn}: {result.error}"
                )
            results.append(result.unwrap())
        return FlextResult[list[FlextLdapModels.User | None]].ok(results)
