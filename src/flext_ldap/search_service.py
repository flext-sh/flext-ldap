"""Search domain service for LDAP operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextDomainService, FlextResult
from flext_ldap.clients import FlextLdapClient
from flext_ldap.models import FlextLdapModels
from flext_ldap.typings import FlextLdapTypes
from flext_ldap.validations import FlextLdapValidations


class FlextLdapSearchService(FlextDomainService):
    """Domain service for LDAP search operations.

    This service encapsulates all search-related business logic and operations
    following Domain-Driven Design patterns. It provides a clean interface
    for search operations while maintaining proper separation of concerns.

    Attributes:
        _client: LDAP client for infrastructure operations.

    """

    def __init__(self, client: FlextLdapClient) -> None:
        """Initialize search service with LDAP client.

        Args:
            client: LDAP client for performing infrastructure operations.

        """
        super().__init__()
        self._client = client

    def execute(self) -> FlextResult[dict[str, str]]:
        """Execute the main domain service operation.

        Returns basic service information for the search service.
        """
        return FlextResult[dict[str, str]].ok({
            "service": "FlextLdapSearchService",
            "status": "ready",
            "operations": "search,search_simple,search_users,search_groups,count_entries"
        })

    async def search(
        self,
        search_request: FlextLdapModels.SearchRequest,
    ) -> FlextResult[list[FlextLdapModels.Entry]]:
        """Execute LDAP search using validated request entity with railway pattern.

        Performs LDAP search operation using the provided search request.
        The request is validated and processed through the service layer
        to ensure proper error handling and result formatting.

        Args:
            search_request: Encapsulated search parameters with validation.

        Returns:
            FlextResult[list[FlextLdapModels.Entry]]: Search results or error.

        """
        # Validate search request parameters
        validation_result = self._validate_search_request(search_request)
        if validation_result.is_failure:
            return FlextResult[list[FlextLdapModels.Entry]].fail(
                f"Search validation failed: {validation_result.error}"
            )

        # Railway pattern: search >> convert entries
        search_result = await self._client.search_with_request(search_request)
        return (search_result >> self._convert_search_response_to_entries).with_context(
            lambda err: f"Search operation failed: {err}"
        )

    def _validate_search_request(
        self, search_request: FlextLdapModels.SearchRequest
    ) -> FlextResult[None]:
        """Validate search request parameters."""
        # Validate base DN
        dn_validation = FlextLdapValidations.validate_dn(search_request.base_dn)
        if dn_validation.is_failure:
            return FlextResult[None].fail(f"Invalid base DN: {dn_validation.error}")

        # Validate filter
        filter_validation = FlextLdapValidations.validate_filter(search_request.filter_str)
        if filter_validation.is_failure:
            return FlextResult[None].fail(f"Invalid filter: {filter_validation.error}")

        # Validate scope
        valid_scopes = ["base", "onelevel", "subtree"]
        if search_request.scope not in valid_scopes:
            return FlextResult[None].fail(
                f"Invalid scope '{search_request.scope}'. Must be one of: {valid_scopes}"
            )

        # Validate limits
        if search_request.size_limit < 0:
            return FlextResult[None].fail("Size limit cannot be negative")
        if search_request.time_limit < 0:
            return FlextResult[None].fail("Time limit cannot be negative")

        return FlextResult[None].ok(None)

    def _convert_search_response_to_entries(
        self, search_response: FlextLdapModels.SearchResponse
    ) -> FlextResult[list[FlextLdapModels.Entry]]:
        """Convert search response to entries - railway helper method."""
        try:
            entries: list[FlextLdapModels.Entry] = []
            for raw_entry in search_response.entries:
                # Convert raw entry to FlextLdapModels.Entry
                # First check if it's already an Entry (unlikely but defensive)
                if hasattr(raw_entry, "dn") and hasattr(raw_entry, "attributes") and hasattr(raw_entry, "id"):
                    # Already a properly structured Entry
                    entries.append(raw_entry)  # type: ignore[arg-type]
                else:
                    # Assume dict-like structure and extract safely
                    entry_dict = self._extract_entry_attributes(raw_entry)
                    dn = str(entry_dict.get("dn", ""))

                    # Safe extraction of attributes with proper typing
                    raw_attributes = entry_dict.get("attributes", {})
                    attributes = raw_attributes if isinstance(raw_attributes, dict) else {}

                    # Safe extraction of object classes
                    raw_object_classes = entry_dict.get("objectClass", [])
                    object_classes = (
                        raw_object_classes if isinstance(raw_object_classes, list)
                        else [str(raw_object_classes)] if raw_object_classes
                        else []
                    )

                    entry = FlextLdapModels.Entry(
                        id=dn,  # Use DN as ID
                        dn=dn,
                        attributes=attributes,
                        object_classes=object_classes,
                    )
                    entries.append(entry)

            return FlextResult[list[FlextLdapModels.Entry]].ok(entries)

        except Exception as e:
            return FlextResult[list[FlextLdapModels.Entry]].fail(
                f"Failed to convert search response: {e}"
            )

    def _extract_entry_attributes(self, raw_entry: object) -> dict[str, object]:
        """Extract attributes from raw entry object."""
        try:
            if hasattr(raw_entry, "entry_dn") and hasattr(raw_entry, "entry_attributes"):
                # ldap3 Entry object
                return {
                    "dn": str(getattr(raw_entry, "entry_dn")),
                    "attributes": dict(getattr(raw_entry, "entry_attributes")),
                }
            if hasattr(raw_entry, "dn") and hasattr(raw_entry, "attributes"):
                # Already structured entry
                return {
                    "dn": str(getattr(raw_entry, "dn")),
                    "attributes": dict(getattr(raw_entry, "attributes")),
                }
            # Fallback for unknown entry types
            return {
                "dn": str(getattr(raw_entry, "dn", "")),
                "attributes": getattr(raw_entry, "attributes", {}),
            }
        except Exception:
            return {"dn": "", "attributes": {}}

    async def search_simple(
        self,
        base_dn: str,
        search_filter: str = "(objectClass=*)",
        *,
        scope: str = "subtree",
        attributes: list[str] | None = None,
    ) -> FlextResult[list[FlextLdapModels.Entry]]:
        """Simplified search interface using factory method pattern."""
        # Use factory method from SearchRequest for convenience
        search_request = FlextLdapModels.SearchRequest(
            base_dn=base_dn,
            filter_str=search_filter,
            scope=scope,
            attributes=attributes,
            size_limit=1000,
            time_limit=30,
        )
        return await self.search(search_request)

    async def search_users(
        self,
        base_dn: str,
        uid: str | None = None,
        cn: str | None = None,
        mail: str | None = None,
    ) -> FlextResult[list[FlextLdapModels.User]]:
        """Search for users with optional filters."""
        # Build filter based on provided parameters
        filter_parts = ["(objectClass=person)"]

        if uid:
            filter_parts.append(f"(uid={uid})")
        if cn:
            filter_parts.append(f"(cn={cn})")
        if mail:
            filter_parts.append(f"(mail={mail})")

        # Combine filters
        if len(filter_parts) == 1:
            search_filter = filter_parts[0]
        else:
            search_filter = f"(&{''.join(filter_parts)})"

        # Create search request
        search_request = FlextLdapModels.SearchRequest(
            base_dn=base_dn,
            filter_str=search_filter,
            scope="subtree",
            attributes=["uid", "cn", "sn", "mail", "givenName"],
            size_limit=1000,
            time_limit=30,
        )

        # Railway pattern: search >> convert to users
        search_result = await self.search(search_request)
        return (search_result >> self._convert_entries_to_users).with_context(
            lambda err: f"Failed to search users: {err}"
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
        search_result = await self.search(search_request)
        return (search_result >> self._convert_entries_to_users).with_context(
            lambda err: f"Failed to search users with filter '{filter_str}': {err}"
        )

    def _convert_entries_to_users(
        self, entries: list[FlextLdapModels.Entry]
    ) -> FlextResult[list[FlextLdapModels.User]]:
        """Convert entries to users - railway helper method."""
        try:
            users: list[FlextLdapModels.User] = []
            for entry in entries:
                # Create user from entry - simplified mapping
                uid = self._get_entry_attribute(entry, "uid", "unknown")
                user = FlextLdapModels.User(
                    id=f"user_{uid}",
                    dn=self._get_entry_attribute(entry, "dn", entry.dn),
                    uid=uid,
                    cn=self._get_entry_attribute(entry, "cn"),
                    sn=self._get_entry_attribute(entry, "sn"),
                    mail=self._get_entry_attribute(entry, "mail"),
                    given_name=self._get_entry_attribute(entry, "givenName"),
                    modified_at=None,
                    user_password=None,
                )
                users.append(user)
            return FlextResult[list[FlextLdapModels.User]].ok(users)

        except Exception as e:
            return FlextResult[list[FlextLdapModels.User]].fail(
                f"Failed to convert entries to users: {e}"
            )

    async def search_groups(
        self,
        base_dn: str,
        cn: str | None = None,
        description: str | None = None,
    ) -> FlextResult[list[FlextLdapModels.Group]]:
        """Search for groups with optional filters."""
        # Build filter based on provided parameters
        filter_parts = ["(objectClass=groupOfNames)"]

        if cn:
            filter_parts.append(f"(cn={cn})")
        if description:
            filter_parts.append(f"(description={description})")

        # Combine filters
        if len(filter_parts) == 1:
            search_filter = filter_parts[0]
        else:
            search_filter = f"(&{''.join(filter_parts)})"

        # Create search request
        search_request = FlextLdapModels.SearchRequest(
            base_dn=base_dn,
            filter_str=search_filter,
            scope="subtree",
            attributes=["cn", "description", "member"],
            size_limit=1000,
            time_limit=30,
        )

        # Railway pattern: search >> convert to groups
        search_result = await self.search(search_request)
        return (search_result >> self._convert_entries_to_groups).with_context(
            lambda err: f"Failed to search groups: {err}"
        )

    def _convert_entries_to_groups(
        self, entries: list[FlextLdapModels.Entry]
    ) -> FlextResult[list[FlextLdapModels.Group]]:
        """Convert entries to groups - railway helper method."""
        try:
            groups: list[FlextLdapModels.Group] = []
            for entry in entries:
                # Create group from entry
                cn = self._get_entry_attribute(entry, "cn", "unknown")
                description = self._get_entry_attribute(entry, "description")
                members = self._get_entry_attribute_list(entry, "member")

                group = FlextLdapModels.Group(
                    id=f"group_{cn}",
                    dn=entry.dn,
                    cn=cn,
                    description=description if description else None,
                    members=members,
                    modified_at=None,
                )
                groups.append(group)
            return FlextResult[list[FlextLdapModels.Group]].ok(groups)

        except Exception as e:
            return FlextResult[list[FlextLdapModels.Group]].fail(
                f"Failed to convert entries to groups: {e}"
            )

    async def search_by_object_class(
        self,
        base_dn: str,
        object_class: str,
        scope: str = "subtree",
        attributes: list[str] | None = None,
    ) -> FlextResult[list[FlextLdapModels.Entry]]:
        """Search entries by object class."""
        search_filter = f"(objectClass={object_class})"
        return await self.search_simple(
            base_dn=base_dn,
            search_filter=search_filter,
            scope=scope,
            attributes=attributes,
        )

    async def count_entries(
        self,
        base_dn: str,
        search_filter: str = "(objectClass=*)",
        scope: str = "subtree",
    ) -> FlextResult[int]:
        """Count entries matching the search criteria."""
        # Use search with minimal attributes for efficiency
        search_result = await self.search_simple(
            base_dn=base_dn,
            search_filter=search_filter,
            scope=scope,
            attributes=["dn"],  # Only DN needed for counting
        )

        return (search_result >> (lambda entries: FlextResult[int].ok(len(entries)))).with_context(
            lambda err: f"Failed to count entries: {err}"
        )

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

    def _get_entry_attribute_list(
        self,
        entry: FlextLdapTypes.Core.Dict | FlextLdapModels.Entry,
        key: str,
    ) -> list[str]:
        """Extract list attribute from entry."""
        # Handle FlextLdapModels.Entry type
        if isinstance(entry, FlextLdapModels.Entry):
            attr_values = entry.attributes.get(key, [])
            return [str(value) for value in attr_values if value]

        # Handle dict type
        dict_value: object = entry.get(key, [])
        if isinstance(dict_value, list):
            return [str(value) for value in dict_value if value]
        if dict_value:
            return [str(dict_value)]
        return []

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
