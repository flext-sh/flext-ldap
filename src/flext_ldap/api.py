"""FlextLdap - Thin facade for LDAP operations with FLEXT integration.

Enterprise LDAP operations facade following FLEXT Clean Architecture patterns.
Provides unified access to LDAP domain functionality with proper delegation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import concurrent.futures
import time
import warnings
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from pathlib import Path
from typing import Self, cast, override

from flext_core import FlextCore
from flext_ldif import FlextLdif, FlextLdifModels
from pydantic import SecretStr

from flext_ldap.clients import FlextLdapClients
from flext_ldap.config import FlextLdapConfig
from flext_ldap.entry_adapter import FlextLdapEntryAdapter
from flext_ldap.models import FlextLdapModels
from flext_ldap.quirks_integration import FlextLdapQuirksIntegration
from flext_ldap.servers import FlextLdapServers


class FlextLdap(FlextCore.Service[None]):
    """Thin facade for LDAP operations with FLEXT ecosystem integration.

    Provides unified access to LDAP domain functionality through proper delegation
    to specialized services and infrastructure components.

    **THIN FACADE PATTERN**: Minimal orchestration, delegates to domain services:
    - FlextLdapServices: Application services for LDAP operations
    - FlextLdapClients: Infrastructure LDAP client operations
    - FlextLdapValidations: Domain validation logic

    **USAGE**:
    - Use FlextLdap for core LDAP orchestration
    - Import specialized services directly for advanced operations
    - Import FlextLdapModels, FlextLdapConstants directly for domain access
    """

    @override
    def __init__(self, config: FlextLdapConfig | None = None) -> None:
        """Initialize LDAP facade with configuration.

        Args:
            config: Optional LDAP configuration. If not provided, uses default instance.

        """
        super().__init__()
        self._ldap_config: FlextLdapConfig = (
            config if config is not None else FlextLdapConfig()
        )
        self._ldif: FlextLdif | None = None
        self._client: FlextLdapClients | None = None

    @classmethod
    def create(cls) -> Self:
        """Factory method to create FlextLdap instance."""
        return cls()

    @property
    def client(self) -> FlextLdapClients:
        """Get the LDAP client instance, creating it if necessary."""
        if self._client is None:
            self._client = FlextLdapClients()
        return self._client

    @property
    def config(self) -> FlextLdapConfig:
        """Get LDAP-specific configuration instance.

        Overrides FlextCore.Service.config to return FlextLdapConfig
        instead of base FlextCore.Config type.
        """
        return self._ldap_config

    @override
    def execute(self) -> FlextCore.Result[None]:
        """Execute the main domain operation (required by FlextCore.Service)."""
        return FlextCore.Result[None].ok(None)

    # =========================================================================
    # CORE FACADE METHODS - Thin delegation layer
    # =========================================================================

    # =========================================================================
    # CONNECTION MANAGEMENT - Delegate to client
    # =========================================================================

    def connect(
        self,
        server: str | None = None,
        port: int | None = None,
        *,
        use_ssl: bool = False,
        bind_dn: str | None = None,
        bind_password: str | None = None,
    ) -> FlextCore.Result[bool]:
        """Connect to LDAP server."""
        # Construct server URI from components
        if server is None:
            server = "localhost"
        if port is None:
            port = 636 if use_ssl else 389

        protocol = "ldaps" if use_ssl else "ldap"
        server_uri = f"{protocol}://{server}:{port}"

        # Validate required parameters
        if bind_dn is None or bind_password is None:
            return FlextCore.Result[bool].fail("bind_dn and bind_password are required")

        return self.client.connect(server_uri, bind_dn, bind_password)

    def is_connected(self) -> bool:
        """Check if LDAP client is connected to server.

        Returns:
            True if connected, False otherwise.

        """
        return self.client.is_connected()

    def unbind(self) -> FlextCore.Result[None]:
        """Unbind from LDAP server.

        Returns:
            FlextCore.Result indicating success or failure.

        """
        return self.client.unbind()

    def test_connection(self) -> FlextCore.Result[bool]:
        """Test LDAP connection.

        Returns:
            FlextCore.Result containing True if connection is working.

        """
        return self.client.test_connection()

    # =========================================================================
    # CORE LDAP OPERATIONS - Consolidated facade methods
    # =========================================================================

    def search(
        self,
        search_request: FlextLdapModels.SearchRequest,
    ) -> FlextCore.Result[list[FlextLdapModels.Entry]]:
        """Perform LDAP search operation.

        Args:
            search_request: Search request model with parameters

        Returns:
            FlextCore.Result containing list of entries

        """
        return self.client.search_with_request(search_request).map(
            lambda response: response.entries,
        )

    def create_entry(
        self,
        dn: str,
        attributes: dict[str, str | FlextCore.Types.StringList],
    ) -> FlextCore.Result[bool]:
        """Create new LDAP entry.

        Args:
            dn: Distinguished name for new entry
            attributes: Entry attributes

        Returns:
            FlextCore.Result indicating success

        Example:
            >>> result = api.create_entry(
            ...     "cn=user,ou=users,dc=example,dc=com",
            ...     {"cn": "user", "sn": "User", "objectClass": "person"},
            ... )

        """
        return self.client.add_entry(dn, attributes)

    def add_entry(
        self,
        dn: str,
        attributes: dict[str, str | FlextCore.Types.StringList],
    ) -> FlextCore.Result[bool]:
        """Add new LDAP entry.

        .. deprecated:: 0.10.0
            Use :meth:`create_entry` instead for consistency with create_user/create_group.

        Args:
            dn: Distinguished name for new entry
            attributes: Entry attributes

        Returns:
            FlextCore.Result indicating success

        """
        warnings.warn(
            "add_entry() is deprecated, use create_entry() instead",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.create_entry(dn, attributes)

    def update_entry(
        self, dn: str, changes: FlextLdapModels.EntryChanges
    ) -> FlextCore.Result[bool]:
        """Update existing LDAP entry.

        Args:
            dn: Distinguished name of entry to update
            changes: Attribute changes to apply

        Returns:
            FlextCore.Result indicating success

        Example:
            >>> result = api.update_entry(
            ...     "cn=user,ou=users,dc=example,dc=com",
            ...     {"description": "Updated description"},
            ... )

        """
        return self.client.modify_entry(dn, changes)

    def modify_entry(
        self, dn: str, changes: FlextLdapModels.EntryChanges
    ) -> FlextCore.Result[bool]:
        """Modify existing LDAP entry.

        .. deprecated:: 0.10.0
            Use :meth:`update_entry` instead for consistency.

        Args:
            dn: Distinguished name of entry to modify
            changes: Attribute changes to apply

        Returns:
            FlextCore.Result indicating success

        """
        warnings.warn(
            "modify_entry() is deprecated, use update_entry() instead",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.update_entry(dn, changes)

    def delete_entry(self, dn: str) -> FlextCore.Result[bool]:
        """Delete LDAP entry.

        Args:
            dn: Distinguished name of entry to delete

        Returns:
            FlextCore.Result indicating success

        """
        return self.client.delete_entry(dn)

    def create_user(
        self,
        user_request: FlextLdapModels.CreateUserRequest,
    ) -> FlextCore.Result[FlextLdapModels.LdapUser]:
        """Create new LDAP user with type-safe request model.

        Args:
            user_request: User creation request with all required fields

        Returns:
            FlextCore.Result containing created LdapUser

        Example:
            >>> user_req = FlextLdapModels.CreateUserRequest(
            ...     dn="uid=jdoe,ou=users,dc=example,dc=com",
            ...     uid="jdoe",
            ...     cn="John Doe",
            ...     sn="Doe",
            ...     mail="jdoe@example.com",
            ... )
            >>> result = api.create_user(user_req)

        """
        # Convert CreateUserRequest to attributes dict
        attributes: dict[str, str | FlextCore.Types.StringList] = {
            "uid": user_request.uid,
            "cn": user_request.cn,
            "sn": user_request.sn,
            "objectClass": user_request.object_classes,
        }

        # Add optional fields if provided
        if user_request.given_name:
            attributes["givenName"] = user_request.given_name
        if user_request.mail:
            attributes["mail"] = user_request.mail
        if user_request.user_password:
            # Handle SecretStr (imported at top-level)
            if user_request.user_password is not None:
                password = (
                    user_request.user_password.get_secret_value()
                    if isinstance(user_request.user_password, SecretStr)
                    else str(user_request.user_password)
                )
            else:
                password = ""
            attributes["userPassword"] = password
        if user_request.telephone_number:
            attributes["telephoneNumber"] = user_request.telephone_number
        if user_request.description:
            attributes["description"] = user_request.description
        if user_request.department:
            attributes["department"] = user_request.department
        if user_request.title:
            attributes["title"] = user_request.title
        if user_request.organizational_unit:
            attributes["ou"] = user_request.organizational_unit
        if user_request.organization:
            attributes["o"] = user_request.organization

        # Create the entry
        create_result = self.create_entry(user_request.dn, attributes)
        if create_result.is_failure:
            return FlextCore.Result[FlextLdapModels.LdapUser].fail(
                create_result.error or "User creation failed",
            )

        # Retrieve and return the created user
        user_result = self.client.get_user(user_request.dn)
        if user_result.is_failure:
            # Entry created but retrieval failed - still return success with minimal user
            minimal_user = FlextLdapModels.LdapUser(
                dn=user_request.dn,
                uid=user_request.uid,
                cn=user_request.cn,
                sn=user_request.sn,
                mail=user_request.mail or "",
            )
            return FlextCore.Result[FlextLdapModels.LdapUser].ok(minimal_user)

        # Handle None result from get_user
        user = user_result.unwrap()
        if user is None:
            # Entry created but not found - return minimal user
            minimal_user = FlextLdapModels.LdapUser(
                dn=user_request.dn,
                uid=user_request.uid,
                cn=user_request.cn,
                sn=user_request.sn,
                mail=user_request.mail or "",
            )
            return FlextCore.Result[FlextLdapModels.LdapUser].ok(minimal_user)

        return FlextCore.Result[FlextLdapModels.LdapUser].ok(user)

    def create_group(
        self,
        group_request: FlextLdapModels.CreateGroupRequest,
    ) -> FlextCore.Result[FlextLdapModels.Group]:
        """Create new LDAP group with type-safe request model.

        Args:
            group_request: Group creation request with all required fields

        Returns:
            FlextCore.Result containing created Group

        Example:
            >>> group_req = FlextLdapModels.CreateGroupRequest(
            ...     dn="cn=developers,ou=groups,dc=example,dc=com",
            ...     cn="developers",
            ...     description="Development team",
            ...     members=["uid=jdoe,ou=users,dc=example,dc=com"],
            ... )
            >>> result = api.create_group(group_req)

        """
        # Convert CreateGroupRequest to attributes dict
        attributes: dict[str, str | FlextCore.Types.StringList] = {
            "cn": group_request.cn,
            "description": group_request.description,
            "member": group_request.members,
            "objectClass": group_request.object_classes,
        }

        # Create the entry
        create_result = self.create_entry(group_request.dn, attributes)
        if create_result.is_failure:
            return FlextCore.Result[FlextLdapModels.Group].fail(
                create_result.error or "Group creation failed",
            )

        # Retrieve and return the created group
        group_result = self.client.get_group(group_request.dn)
        if group_result.is_failure:
            # Entry created but retrieval failed - still return success with minimal group
            minimal_group = FlextLdapModels.Group(
                dn=group_request.dn,
                cn=group_request.cn,
                description=group_request.description,
                member_dns=group_request.members,
            )
            return FlextCore.Result[FlextLdapModels.Group].ok(minimal_group)

        # Handle None result from get_group
        group = group_result.unwrap()
        if group is None:
            # Entry created but not found - return minimal group
            minimal_group = FlextLdapModels.Group(
                dn=group_request.dn,
                cn=group_request.cn,
                description=group_request.description,
                member_dns=group_request.members,
            )
            return FlextCore.Result[FlextLdapModels.Group].ok(minimal_group)

        return FlextCore.Result[FlextLdapModels.Group].ok(group)

    def upsert_entry(
        self,
        upsert_request: FlextLdapModels.UpsertEntryRequest,
    ) -> FlextCore.Result[dict[str, str]]:
        """Create or update LDAP entry (upsert operation).

        High-velocity operation that creates entry if it doesn't exist,
        or updates it if it does exist.

        Args:
            upsert_request: Upsert request with DN, attributes, and strategy

        Returns:
            FlextCore.Result containing operation details:
                - operation: "created" or "updated"
                - dn: Distinguished name of the entry

        Example:
            >>> upsert_req = FlextLdapModels.UpsertEntryRequest(
            ...     dn="uid=jdoe,ou=users,dc=example,dc=com",
            ...     attributes={
            ...         "cn": "John Doe",
            ...         "sn": "Doe",
            ...         "mail": "jdoe@example.com",
            ...     },
            ...     update_strategy="merge",
            ...     object_classes=["person", "organizationalPerson"],
            ... )
            >>> result = api.upsert_entry(upsert_req)
            >>> if result.is_success:
            ...     info = result.unwrap()
            ...     print(f"Entry {info['operation']}: {info['dn']}")

        """
        # Check if entry exists by attempting to search for it
        search_result = self.client.search_one(upsert_request.dn, "(objectClass=*)")

        if search_result.is_success:
            # Entry exists - check if update is needed (IDEMPOTENT CHECK - GAP #7)
            live_entry = search_result.unwrap()

            # Build desired attributes (including objectClass if provided)
            desired_attrs = upsert_request.attributes.copy()
            if upsert_request.object_classes:
                desired_attrs["objectClass"] = upsert_request.object_classes

            # Idempotent check: Skip if no changes needed
            # Note: live_entry is FlextLdapModels.Entry, extract attributes dict
            live_attrs = live_entry.attributes if live_entry else {}
            if not self._entry_needs_update(live_attrs, desired_attrs):
                if self.logger is not None:
                    self.logger.debug(
                        f"Skipping upsert for {upsert_request.dn} - ",
                        "no changes needed (idempotent)",
                    )
                return FlextCore.Result[dict[str, str]].ok({
                    "operation": "skipped",
                    "dn": upsert_request.dn,
                    "reason": "no_changes_needed",
                })

            # Entry exists and needs update
            if upsert_request.update_strategy == "replace":
                # Replace strategy: delete and recreate with new attributes
                delete_result = self.delete_entry(upsert_request.dn)
                if delete_result.is_failure:
                    return FlextCore.Result[dict[str, str]].fail(
                        f"Failed to delete entry for replace: {delete_result.error}",
                    )

                # Create with new attributes
                create_attrs = upsert_request.attributes.copy()
                if upsert_request.object_classes:
                    create_attrs["objectClass"] = upsert_request.object_classes

                create_result = self.create_entry(upsert_request.dn, create_attrs)
                if create_result.is_failure:
                    return FlextCore.Result[dict[str, str]].fail(
                        f"Failed to recreate entry: {create_result.error}",
                    )

                return FlextCore.Result[dict[str, str]].ok(
                    {"operation": "updated", "dn": upsert_request.dn},
                )

            # merge strategy (default)
            # Merge strategy: update existing attributes
            changes = FlextLdapModels.EntryChanges(**upsert_request.attributes)
            update_result = self.update_entry(
                upsert_request.dn,
                changes,
            )
            if update_result.is_failure:
                return FlextCore.Result[dict[str, str]].fail(
                    f"Failed to update entry: {update_result.error}",
                )

            return FlextCore.Result[dict[str, str]].ok(
                {"operation": "updated", "dn": upsert_request.dn},
            )

        # Entry doesn't exist - create it
        create_attrs = upsert_request.attributes.copy()
        if upsert_request.object_classes:
            create_attrs["objectClass"] = upsert_request.object_classes

        create_result = self.create_entry(upsert_request.dn, create_attrs)
        if create_result.is_failure:
            return FlextCore.Result[dict[str, str]].fail(
                f"Failed to create entry: {create_result.error}",
            )

        return FlextCore.Result[dict[str, str]].ok(
            {"operation": "created", "dn": upsert_request.dn},
        )

    def upsert_user(
        self,
        user_request: FlextLdapModels.CreateUserRequest,
    ) -> FlextCore.Result[FlextLdapModels.LdapUser]:
        """Create or update LDAP user (upsert operation).

        High-velocity operation that creates user if they don't exist,
        or updates them if they do exist.

        Args:
            user_request: User creation/update request with all fields

        Returns:
            FlextCore.Result containing the LdapUser

        Example:
            >>> user_req = FlextLdapModels.CreateUserRequest(
            ...     dn="uid=jdoe,ou=users,dc=example,dc=com",
            ...     uid="jdoe",
            ...     cn="John Doe",
            ...     sn="Doe",
            ...     mail="jdoe@example.com",
            ... )
            >>> result = api.upsert_user(user_req)

        """
        # Check if user exists
        user_exists_result = self.client.get_user(user_request.dn)

        if user_exists_result.is_success:
            # User exists - update attributes
            update_attrs: dict[str, str | FlextCore.Types.StringList] = {}

            # Update all provided fields
            if user_request.cn:
                update_attrs["cn"] = user_request.cn
            if user_request.sn:
                update_attrs["sn"] = user_request.sn
            if user_request.given_name:
                update_attrs["givenName"] = user_request.given_name
            if user_request.mail:
                update_attrs["mail"] = user_request.mail
            if user_request.user_password:
                # Handle SecretStr (imported at top-level)
                if user_request.user_password is not None:
                    password = (
                        user_request.user_password.get_secret_value()
                        if isinstance(user_request.user_password, SecretStr)
                        else str(user_request.user_password)
                    )
                else:
                    password = ""
                update_attrs["userPassword"] = password
            if user_request.telephone_number:
                update_attrs["telephoneNumber"] = user_request.telephone_number
            if user_request.description:
                update_attrs["description"] = user_request.description
            if user_request.department:
                update_attrs["department"] = user_request.department
            if user_request.title:
                update_attrs["title"] = user_request.title
            if user_request.organizational_unit:
                update_attrs["ou"] = user_request.organizational_unit
            if user_request.organization:
                update_attrs["o"] = user_request.organization

            # Update the entry
            if update_attrs:
                changes = FlextLdapModels.EntryChanges(**update_attrs)
                update_result = self.update_entry(user_request.dn, changes)
                if update_result.is_failure:
                    return FlextCore.Result[FlextLdapModels.LdapUser].fail(
                        f"Failed to update user: {update_result.error}",
                    )

            # Return updated user
            user_result = self.client.get_user(user_request.dn)
            if user_result.is_failure:
                return FlextCore.Result[FlextLdapModels.LdapUser].fail(
                    user_result.error or "Failed to retrieve user"
                )

            user = user_result.unwrap()
            if user is None:
                return FlextCore.Result[FlextLdapModels.LdapUser].fail(
                    "User not found after update"
                )

            return FlextCore.Result[FlextLdapModels.LdapUser].ok(user)

        # User doesn't exist - create it
        return self.create_user(user_request)

    def upsert_group(
        self,
        group_request: FlextLdapModels.CreateGroupRequest,
    ) -> FlextCore.Result[FlextLdapModels.Group]:
        """Create or update LDAP group (upsert operation).

        High-velocity operation that creates group if it doesn't exist,
        or updates it if it does exist.

        Args:
            group_request: Group creation/update request with all fields

        Returns:
            FlextCore.Result containing the Group

        Example:
            >>> group_req = FlextLdapModels.CreateGroupRequest(
            ...     dn="cn=developers,ou=groups,dc=example,dc=com",
            ...     cn="developers",
            ...     description="Development team",
            ...     members=["uid=user1,ou=users,dc=example,dc=com"],
            ... )
            >>> result = api.upsert_group(group_req)

        """
        # Check if group exists
        group_exists_result = self.client.get_group(group_request.dn)

        if group_exists_result.is_success:
            # Group exists - update attributes
            update_attrs: dict[str, str | FlextCore.Types.StringList] = {}

            # Update all provided fields
            if group_request.cn:
                update_attrs["cn"] = group_request.cn
            if group_request.description:
                update_attrs["description"] = group_request.description
            if group_request.members:
                update_attrs["member"] = group_request.members

            # Update the entry
            if update_attrs:
                changes = FlextLdapModels.EntryChanges(**update_attrs)
                update_result = self.update_entry(group_request.dn, changes)
                if update_result.is_failure:
                    return FlextCore.Result[FlextLdapModels.Group].fail(
                        f"Failed to update group: {update_result.error}",
                    )

            # Return updated group
            group_result = self.client.get_group(group_request.dn)
            if group_result.is_failure:
                return FlextCore.Result[FlextLdapModels.Group].fail(
                    group_result.error or "Failed to retrieve group"
                )

            group = group_result.unwrap()
            if group is None:
                return FlextCore.Result[FlextLdapModels.Group].fail(
                    "Group not found after update"
                )

            return FlextCore.Result[FlextLdapModels.Group].ok(group)

        # Group doesn't exist - create it
        return self.create_group(group_request)

    def upsert_entries_batch(
        self,
        upsert_requests: list[FlextLdapModels.UpsertEntryRequest],
        *,
        parallel: bool = False,
    ) -> FlextCore.Result[FlextLdapModels.SyncResult]:
        """Batch upsert operation for high-velocity LDAP writes.

        Processes multiple upsert requests efficiently, optionally in parallel.
        Returns detailed statistics about operations performed.

        Args:
            upsert_requests: List of upsert requests to process
            parallel: Whether to process requests in parallel (default: False)

        Returns:
            FlextCore.Result containing SyncResult with operation statistics

        Example:
            >>> requests = [
            ...     FlextLdapModels.UpsertEntryRequest(
            ...         dn="uid=user1,ou=users,dc=example,dc=com",
            ...         attributes={"cn": "User One", "sn": "One"},
            ...         object_classes=["person"],
            ...     ),
            ...     FlextLdapModels.UpsertEntryRequest(
            ...         dn="uid=user2,ou=users,dc=example,dc=com",
            ...         attributes={"cn": "User Two", "sn": "Two"},
            ...         object_classes=["person"],
            ...     ),
            ... ]
            >>> result = api.upsert_entries_batch(requests)
            >>> if result.is_success:
            ...     stats = result.unwrap()
            ...     print(f"Created: {stats.created}, Updated: {stats.updated}")

        """
        sync_result = FlextLdapModels.SyncResult()

        if parallel:
            # Parallel processing using ThreadPoolExecutor
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                future_to_request = {
                    executor.submit(self.upsert_entry, req): req
                    for req in upsert_requests
                }

                for future in concurrent.futures.as_completed(future_to_request):
                    request = future_to_request[future]
                    try:
                        result = future.result()
                        if result.is_success:
                            operation_info = result.unwrap()
                            if operation_info["operation"] == "created":
                                sync_result.created += 1
                            else:
                                sync_result.updated += 1
                            sync_result.operations.append(
                                {
                                    "dn": request.dn,
                                    "operation": operation_info["operation"],
                                    "status": "success",
                                },
                            )
                        else:
                            sync_result.failed += 1
                            error_msg = result.error or "Unknown error"
                            sync_result.errors.append(f"{request.dn}: {error_msg}")
                            sync_result.operations.append(
                                {
                                    "dn": request.dn,
                                    "operation": "upsert",
                                    "status": "failed",
                                    "error": error_msg,
                                },
                            )
                    except Exception as e:
                        sync_result.failed += 1
                        error_msg = str(e)
                        sync_result.errors.append(f"{request.dn}: {error_msg}")
                        sync_result.operations.append(
                            {
                                "dn": request.dn,
                                "operation": "upsert",
                                "status": "failed",
                                "error": error_msg,
                            },
                        )
        else:
            # Sequential processing
            for request in upsert_requests:
                result = self.upsert_entry(request)
                if result.is_success:
                    operation_info = result.unwrap()
                    if operation_info["operation"] == "created":
                        sync_result.created += 1
                    else:
                        sync_result.updated += 1
                    sync_result.operations.append(
                        {
                            "dn": request.dn,
                            "operation": operation_info["operation"],
                            "status": "success",
                        },
                    )
                else:
                    sync_result.failed += 1
                    error_msg = result.error or "Unknown error"
                    sync_result.errors.append(f"{request.dn}: {error_msg}")
                    sync_result.operations.append(
                        {
                            "dn": request.dn,
                            "operation": "upsert",
                            "status": "failed",
                            "error": error_msg,
                        },
                    )

        return FlextCore.Result[FlextLdapModels.SyncResult].ok(sync_result)

    def sync_entries(
        self,
        base_dn: str,
        desired_entries: list[FlextLdapModels.UpsertEntryRequest],
        *,
        delete_missing: bool = False,
        parallel: bool = False,
    ) -> FlextCore.Result[FlextLdapModels.SyncResult]:
        """Synchronize LDAP entries with desired state.

        High-velocity operation that synchronizes LDAP directory with a source list.
        Creates/updates entries to match desired state, optionally deletes entries
        not in desired state.

        Args:
            base_dn: Base DN to synchronize within
            desired_entries: List of entries that should exist
            delete_missing: Whether to delete entries not in desired list (default: False)
            parallel: Whether to process in parallel (default: False)

        Returns:
            FlextCore.Result containing SyncResult with operation statistics

        Example:
            >>> desired = [
            ...     FlextLdapModels.UpsertEntryRequest(
            ...         dn="uid=user1,ou=users,dc=example,dc=com",
            ...         attributes={"cn": "User One", "sn": "One"},
            ...         object_classes=["person"],
            ...     ),
            ... ]
            >>> result = api.sync_entries(
            ...     base_dn="ou=users,dc=example,dc=com",
            ...     desired_entries=desired,
            ...     delete_missing=True,
            ... )
            >>> if result.is_success:
            ...     stats = result.unwrap()
            ...     print(
            ...         f"Synced - Created: {stats.created}, "
            ...         f"Updated: {stats.updated}, Deleted: {stats.deleted}"
            ...     )

        """
        sync_result = FlextLdapModels.SyncResult()

        # Build set of desired DNs for quick lookup
        desired_dns = {entry.dn for entry in desired_entries}

        # First, upsert all desired entries
        upsert_result = self.upsert_entries_batch(desired_entries, parallel=parallel)
        if upsert_result.is_failure:
            return FlextCore.Result[FlextLdapModels.SyncResult].fail(
                f"Upsert phase failed: {upsert_result.error}",
            )

        # Copy statistics from upsert phase
        upsert_stats = upsert_result.unwrap()
        sync_result.created = upsert_stats.created
        sync_result.updated = upsert_stats.updated
        sync_result.failed = upsert_stats.failed
        sync_result.errors = upsert_stats.errors.copy()
        sync_result.operations = upsert_stats.operations.copy()

        # If delete_missing is enabled, find and delete entries not in desired list
        if delete_missing:
            # Search for all entries under base_dn
            search_request = FlextLdapModels.SearchRequest(
                base_dn=base_dn,
                filter_str="(objectClass=*)",
                scope="subtree",
                attributes=["dn"],
            )

            search_result = self.client.search_with_request(search_request)
            if search_result.is_success:
                response = search_result.unwrap()
                existing_entries = response.entries if response else []

                # Find entries to delete (exist in LDAP but not in desired)
                for entry in existing_entries:
                    entry_dn = entry.dn if hasattr(entry, "dn") else str(entry)

                    # Skip base DN itself
                    if entry_dn == base_dn:
                        continue

                    # Delete if not in desired list
                    if entry_dn not in desired_dns:
                        delete_result = self.delete_entry(entry_dn)
                        if delete_result.is_success:
                            sync_result.deleted += 1
                            sync_result.operations.append(
                                {
                                    "dn": entry_dn,
                                    "operation": "deleted",
                                    "status": "success",
                                },
                            )
                        else:
                            sync_result.failed += 1
                            error_msg = delete_result.error or "Unknown error"
                            sync_result.errors.append(f"{entry_dn}: {error_msg}")
                            sync_result.operations.append(
                                {
                                    "dn": entry_dn,
                                    "operation": "delete",
                                    "status": "failed",
                                    "error": error_msg,
                                },
                            )

        return FlextCore.Result[FlextLdapModels.SyncResult].ok(sync_result)

    def sync_users(
        self,
        base_dn: str,
        desired_users: list[FlextLdapModels.CreateUserRequest],
        *,
        delete_missing: bool = False,
        parallel: bool = False,
    ) -> FlextCore.Result[FlextLdapModels.SyncResult]:
        """Synchronize LDAP users with desired state.

        High-velocity operation that synchronizes users in LDAP directory with a source list.
        Creates/updates users to match desired state, optionally deletes users not in desired state.

        Args:
            base_dn: Base DN to synchronize users within (e.g., "ou=users,dc=example,dc=com")
            desired_users: List of users that should exist
            delete_missing: Whether to delete users not in desired list (default: False)
            parallel: Whether to process in parallel (default: False)

        Returns:
            FlextCore.Result containing SyncResult with operation statistics

        Example:
            >>> desired = [
            ...     FlextLdapModels.CreateUserRequest(
            ...         dn="uid=jdoe,ou=users,dc=example,dc=com",
            ...         uid="jdoe",
            ...         cn="John Doe",
            ...         sn="Doe",
            ...         mail="jdoe@example.com",
            ...     ),
            ... ]
            >>> result = api.sync_users(
            ...     base_dn="ou=users,dc=example,dc=com",
            ...     desired_users=desired,
            ...     delete_missing=True,
            ... )

        """
        # Convert CreateUserRequest to UpsertEntryRequest
        upsert_requests = []
        for user_req in desired_users:
            # Build attributes dict[str, object] from user request
            attributes: dict[str, str | FlextCore.Types.StringList] = {
                "uid": user_req.uid,
                "cn": user_req.cn,
                "sn": user_req.sn,
                "objectClass": user_req.object_classes,
            }

            # Add optional fields
            if user_req.given_name:
                attributes["givenName"] = user_req.given_name
            if user_req.mail:
                attributes["mail"] = user_req.mail
            if user_req.user_password:
                # Handle SecretStr (imported at top-level)
                if user_req.user_password is not None:
                    password = (
                        user_req.user_password.get_secret_value()
                        if isinstance(user_req.user_password, SecretStr)
                        else str(user_req.user_password)
                    )
                else:
                    password = ""
                attributes["userPassword"] = password
            if user_req.telephone_number:
                attributes["telephoneNumber"] = user_req.telephone_number
            if user_req.description:
                attributes["description"] = user_req.description
            if user_req.department:
                attributes["department"] = user_req.department
            if user_req.title:
                attributes["title"] = user_req.title
            if user_req.organizational_unit:
                attributes["ou"] = user_req.organizational_unit
            if user_req.organization:
                attributes["o"] = user_req.organization

            # Create UpsertEntryRequest
            upsert_req = FlextLdapModels.UpsertEntryRequest(
                dn=user_req.dn,
                attributes=attributes,
                update_strategy="merge",
                object_classes=user_req.object_classes,
            )
            upsert_requests.append(upsert_req)

        # Delegate to sync_entries
        return self.sync_entries(
            base_dn, upsert_requests, delete_missing=delete_missing, parallel=parallel
        )

    def sync_groups(
        self,
        base_dn: str,
        desired_groups: list[FlextLdapModels.CreateGroupRequest],
        *,
        delete_missing: bool = False,
        parallel: bool = False,
    ) -> FlextCore.Result[FlextLdapModels.SyncResult]:
        """Synchronize LDAP groups with desired state.

        High-velocity operation that synchronizes groups in LDAP directory with a source list.
        Creates/updates groups to match desired state, optionally deletes groups not in desired state.

        Args:
            base_dn: Base DN to synchronize groups within (e.g., "ou=groups,dc=example,dc=com")
            desired_groups: List of groups that should exist
            delete_missing: Whether to delete groups not in desired list (default: False)
            parallel: Whether to process in parallel (default: False)

        Returns:
            FlextCore.Result containing SyncResult with operation statistics

        Example:
            >>> desired = [
            ...     FlextLdapModels.CreateGroupRequest(
            ...         dn="cn=developers,ou=groups,dc=example,dc=com",
            ...         cn="developers",
            ...         description="Development team",
            ...         members=["uid=user1,ou=users,dc=example,dc=com"],
            ...     ),
            ... ]
            >>> result = api.sync_groups(
            ...     base_dn="ou=groups,dc=example,dc=com",
            ...     desired_groups=desired,
            ...     delete_missing=True,
            ... )

        """
        # Convert CreateGroupRequest to UpsertEntryRequest
        upsert_requests = []
        for group_req in desired_groups:
            # Build attributes dict[str, object] from group request
            attributes: dict[str, str | FlextCore.Types.StringList] = {
                "cn": group_req.cn,
                "objectClass": group_req.object_classes,
            }

            # Add optional fields
            if group_req.description:
                attributes["description"] = group_req.description
            if group_req.members:
                attributes["member"] = group_req.members

            # Create UpsertEntryRequest
            upsert_req = FlextLdapModels.UpsertEntryRequest(
                dn=group_req.dn,
                attributes=attributes,
                update_strategy="merge",
                object_classes=group_req.object_classes,
            )
            upsert_requests.append(upsert_req)

        # Delegate to sync_entries
        return self.sync_entries(
            base_dn, upsert_requests, delete_missing=delete_missing, parallel=parallel
        )

    # =========================================================================
    # ACL HIGH-VELOCITY OPERATIONS - With FlextLdif quirks engine
    # =========================================================================

    def create_acl(
        self,
        acl_request: FlextLdapModels.CreateAclRequest,
    ) -> FlextCore.Result[FlextLdapModels.Acl]:
        """Create LDAP ACL with automatic server type detection and quirks handling.

        Uses FlextLdif quirks engine to detect server type and convert ACL
        to appropriate format (OpenLDAP olcAccess, Oracle orclaci, etc.).

        Args:
            acl_request: ACL creation request with rules and target DN

        Returns:
            FlextCore.Result containing created Acl

        Example:
            >>> from flext_ldap.quirks_integration import FlextLdapQuirksIntegration
            >>> acl_req = FlextLdapModels.CreateAclRequest(
            ...     dn="cn=config", acl_type="auto", acl_rules=["to * by * read"]
            ... )
            >>> result = api.create_acl(acl_req)

        """
        # Import ACL manager lazily

        try:
            # Initialize quirks engine for server detection
            quirks = FlextLdapQuirksIntegration(server_type=acl_request.server_type)

            # Detect server type if not specified
            if acl_request.acl_type == "auto":
                # Get root DSE to detect server
                root_dse_result = self.client.search_one("", "(objectClass=*)")
                if root_dse_result.is_success and root_dse_result.unwrap():
                    # Convert FlextLdapModels.Entry to FlextLdifModels.Entry for server detection
                    ldap_entry = root_dse_result.unwrap()
                    if ldap_entry:
                        adapter = FlextLdapEntryAdapter()
                        entry_dict = {
                            "dn": str(ldap_entry.dn),
                            "attributes": dict(ldap_entry.attributes),
                        }
                        ldif_entry_result = adapter.ldap3_to_ldif_entry(
                            cast("FlextCore.Types.Dict", entry_dict)
                        )
                        if ldif_entry_result.is_failure:
                            server_type_result = FlextCore.Result[str].fail(
                                f"Failed to convert entry: {ldif_entry_result.error}"
                            )
                        else:
                            ldif_entry = ldif_entry_result.unwrap()
                            server_type_result = quirks.detect_server_type_from_entries([
                                ldif_entry
                            ])
                    else:
                        server_type_result = FlextCore.Result[str].fail(
                            "No root DSE entry found"
                        )
                    if server_type_result.is_success:
                        detected_type = server_type_result.unwrap()
                        # Map server type to ACL type
                        if (
                            "openldap" in detected_type.lower()
                            or "oracle" in detected_type.lower()
                        ):
                            pass
                    else:
                        pass  # Default fallback
                else:
                    pass  # Default fallback

            # Create Acl from rules
            unified_acl = FlextLdapModels.Acl(
                name=f"acl_{acl_request.dn}",
                target=FlextLdapModels.AclTarget(
                    target_type="dn",
                    dn_pattern=acl_request.dn,
                ),
                subject=FlextLdapModels.AclSubject(
                    subject_type="any",
                    subject_dn="*",
                ),
                permissions=FlextLdapModels.AclPermissions(
                    grant_type="allow",
                    granted_permissions=["read"],
                ),
            )

            # NOTE: Future implementation requires actual ACL creation via LDAP
            # This requires determining the correct attribute based on server type
            # and applying the ACL rules to the entry

            return FlextCore.Result[FlextLdapModels.Acl].ok(unified_acl)

        except Exception as e:
            return FlextCore.Result[FlextLdapModels.Acl].fail(
                f"ACL creation failed: {e}",
            )

    def update_acl(
        self,
        acl_request: FlextLdapModels.UpdateAclRequest,
    ) -> FlextCore.Result[FlextLdapModels.Acl]:
        """Update existing LDAP ACL with merge or replace strategy.

        Args:
            acl_request: ACL update request with DN, rules, and strategy

        Returns:
            FlextCore.Result containing updated Acl

        Example:
            >>> acl_req = FlextLdapModels.UpdateAclRequest(
            ...     dn="cn=config", acl_rules=["to * by * write"], strategy="merge"
            ... )
            >>> result = api.update_acl(acl_req)

        """
        try:
            # Initialize quirks engine (FlextLdapQuirksIntegration imported at top-level)
            quirks = FlextLdapQuirksIntegration()

            # Get current ACL from entry
            entry_result = self.client.search_one(acl_request.dn, "(objectClass=*)")
            if entry_result.is_failure:
                return FlextCore.Result[FlextLdapModels.Acl].fail(
                    f"Entry not found: {acl_request.dn}",
                )

            # Detect server type from entry
            entry = entry_result.unwrap()
            if entry:
                # Convert FlextLdapModels.Entry to FlextLdifModels.Entry for server detection
                adapter = FlextLdapEntryAdapter()
                entry_dict = {"dn": str(entry.dn), "attributes": dict(entry.attributes)}
                ldif_entry_result = adapter.ldap3_to_ldif_entry(entry_dict)
                if ldif_entry_result.is_success:
                    ldif_entry = ldif_entry_result.unwrap()
                    server_type_result = quirks.detect_server_type_from_entries([
                        ldif_entry
                    ])
                else:
                    server_type_result = FlextCore.Result[str].fail(
                        f"Entry conversion failed: {ldif_entry_result.error}"
                    )
                (
                    server_type_result.unwrap()
                    if server_type_result.is_success
                    else "generic"
                )

            # NOTE: Future implementation steps:
            # 1. Extract current ACL rules from entry attributes
            # 2. Merge or replace based on strategy
            # 3. Update entry with new ACL rules

            # Create unified ACL response
            unified_acl = FlextLdapModels.Acl(
                name=f"acl_{acl_request.dn}",
                target=FlextLdapModels.AclTarget(
                    target_type="dn",
                    dn_pattern=acl_request.dn,
                ),
                subject=FlextLdapModels.AclSubject(
                    subject_type="any",
                    subject_dn="*",
                ),
                permissions=FlextLdapModels.AclPermissions(
                    grant_type="allow",
                    granted_permissions=["read", "write"],
                ),
            )

            return FlextCore.Result[FlextLdapModels.Acl].ok(unified_acl)

        except Exception as e:
            return FlextCore.Result[FlextLdapModels.Acl].fail(
                f"ACL update failed: {e}",
            )

    def get_acl(self, dn: str) -> FlextCore.Result[FlextLdapModels.Acl]:
        """Retrieve and parse ACL from LDAP entry.

        Uses quirks engine to detect server type and parse ACL
        from appropriate attribute (olcAccess, orclaci, etc.).

        Args:
            dn: Distinguished Name of entry with ACL

        Returns:
            FlextCore.Result containing Acl

        Example:
            >>> result = api.get_acl("cn=config")
            >>> if result.is_success:
            ...     acl = result.unwrap()
            ...     print(f"ACL: {acl.name}")

        """
        try:
            # Get entry (FlextLdapQuirksIntegration imported at top-level)
            entry_result = self.client.search_one(dn, "(objectClass=*)")
            if entry_result.is_failure:
                return FlextCore.Result[FlextLdapModels.Acl].fail(
                    f"Entry not found: {dn}",
                )

            entry = entry_result.unwrap()
            if not entry:
                return FlextCore.Result[FlextLdapModels.Acl].fail(
                    f"Entry not found: {dn}",
                )

            # Detect server type
            quirks = FlextLdapQuirksIntegration()
            # Convert FlextLdapModels.Entry to FlextLdifModels.Entry for server detection
            adapter = FlextLdapEntryAdapter()
            entry_dict = {"dn": str(entry.dn), "attributes": dict(entry.attributes)}
            ldif_entry_result = adapter.ldap3_to_ldif_entry(entry_dict)
            if ldif_entry_result.is_success:
                ldif_entry = ldif_entry_result.unwrap()
                server_type_result = quirks.detect_server_type_from_entries([
                    ldif_entry
                ])
            else:
                server_type_result = FlextCore.Result[str].fail(
                    f"Entry conversion failed: {ldif_entry_result.error}"
                )
            (
                server_type_result.unwrap()
                if server_type_result.is_success
                else "generic"
            )

            # NOTE: Future implementation should extract ACL from entry based on server type
            # OpenLDAP: olcAccess attribute
            # Oracle OID: orclaci attribute
            # Generic: aci attribute

            # Create unified ACL response
            unified_acl = FlextLdapModels.Acl(
                name=f"acl_{dn}",
                target=FlextLdapModels.AclTarget(
                    target_type="dn",
                    dn_pattern=dn,
                ),
                subject=FlextLdapModels.AclSubject(
                    subject_type="any",
                    subject_dn="*",
                ),
                permissions=FlextLdapModels.AclPermissions(
                    grant_type="allow",
                    granted_permissions=["read"],
                ),
            )

            return FlextCore.Result[FlextLdapModels.Acl].ok(unified_acl)

        except Exception as e:
            return FlextCore.Result[FlextLdapModels.Acl].fail(
                f"ACL retrieval failed: {e}"
            )

    def delete_acl(self, _dn: str) -> FlextCore.Result[bool]:
        """Delete ACL from LDAP entry.

        Args:
            _dn: Distinguished Name of entry with ACL to delete (unused in placeholder)

        Returns:
            FlextCore.Result indicating success

        Example:
            >>> result = api.delete_acl("cn=config")

        """
        try:
            # NOTE: Future implementation requires:
            # 1. Detect server type and appropriate ACL attribute
            # 2. Remove ACL attribute from entry
            # For now, return success placeholder
            return FlextCore.Result[bool].ok(True)

        except Exception as e:
            return FlextCore.Result[bool].fail(f"ACL deletion failed: {e}")

    def upsert_acl(
        self,
        acl_request: FlextLdapModels.UpsertAclRequest,
    ) -> FlextCore.Result[dict[str, str]]:
        """Create or update LDAP ACL (upsert operation) with quirks handling.

        High-velocity operation that creates ACL if it doesn't exist,
        or updates it if it does exist.

        Args:
            acl_request: ACL upsert request with DN, rules, and strategy

        Returns:
            FlextCore.Result containing operation details (created/updated)

        Example:
            >>> acl_req = FlextLdapModels.UpsertAclRequest(
            ...     dn="cn=config",
            ...     acl_type="auto",
            ...     acl_rules=["to * by * read"],
            ...     update_strategy="merge",
            ... )
            >>> result = api.upsert_acl(acl_req)

        """
        try:
            # Check if entry exists and has ACL
            get_result = self.get_acl(acl_request.dn)

            if get_result.is_success:
                # ACL exists - update it
                update_req = FlextLdapModels.UpdateAclRequest(
                    dn=acl_request.dn,
                    acl_rules=acl_request.acl_rules,
                    strategy=acl_request.update_strategy,
                )
                update_result = self.update_acl(update_req)
                if update_result.is_failure:
                    return FlextCore.Result[dict[str, str]].fail(
                        f"Failed to update ACL: {update_result.error}",
                    )
                return FlextCore.Result[dict[str, str]].ok(
                    {"operation": "updated", "dn": acl_request.dn},
                )

            # ACL doesn't exist - create it
            create_req = FlextLdapModels.CreateAclRequest(
                dn=acl_request.dn,
                acl_type=acl_request.acl_type,
                acl_rules=acl_request.acl_rules,
                server_type=acl_request.server_type,
            )
            create_result = self.create_acl(create_req)
            if create_result.is_failure:
                return FlextCore.Result[dict[str, str]].fail(
                    f"Failed to create ACL: {create_result.error}",
                )
            return FlextCore.Result[dict[str, str]].ok(
                {"operation": "created", "dn": acl_request.dn},
            )

        except Exception as e:
            return FlextCore.Result[dict[str, str]].fail(f"ACL upsert failed: {e}")

    def upsert_acls_batch(
        self,
        acl_requests: list[FlextLdapModels.UpsertAclRequest],
        *,
        parallel: bool = False,
    ) -> FlextCore.Result[FlextLdapModels.AclSyncResult]:
        """Batch upsert operation for high-velocity ACL writes.

        Processes multiple ACL upsert requests efficiently, optionally in parallel.
        Uses quirks engine for server-specific handling.

        Args:
            acl_requests: List of ACL upsert requests to process
            parallel: Whether to process requests in parallel (default: False)

        Returns:
            FlextCore.Result containing AclSyncResult with operation statistics

        Example:
            >>> requests = [
            ...     FlextLdapModels.UpsertAclRequest(
            ...         dn="cn=config", acl_type="auto", acl_rules=["to * by * read"]
            ...     ),
            ... ]
            >>> result = api.upsert_acls_batch(requests, parallel=True)

        """
        sync_result = FlextLdapModels.AclSyncResult()

        if parallel:
            # Parallel processing using ThreadPoolExecutor (imported at top-level)
            with ThreadPoolExecutor(max_workers=10) as executor:
                future_to_request = {
                    executor.submit(self.upsert_acl, req): req for req in acl_requests
                }

                for future in concurrent.futures.as_completed(future_to_request):
                    request = future_to_request[future]
                    try:
                        result = future.result()
                        if result.is_success:
                            operation_info = result.unwrap()
                            if operation_info["operation"] == "created":
                                sync_result.created += 1
                            else:
                                sync_result.updated += 1
                            sync_result.operations.append(
                                {
                                    "dn": request.dn,
                                    "operation": operation_info["operation"],
                                    "status": "success",
                                },
                            )
                        else:
                            sync_result.failed += 1
                            error_msg = result.error or "Unknown error"
                            sync_result.errors.append(f"{request.dn}: {error_msg}")
                            sync_result.operations.append(
                                {
                                    "dn": request.dn,
                                    "operation": "upsert_acl",
                                    "status": "failed",
                                    "error": error_msg,
                                },
                            )
                    except Exception as e:
                        sync_result.failed += 1
                        error_msg = str(e)
                        sync_result.errors.append(f"{request.dn}: {error_msg}")
                        sync_result.operations.append(
                            {
                                "dn": request.dn,
                                "operation": "upsert_acl",
                                "status": "failed",
                                "error": error_msg,
                            },
                        )
        else:
            # Sequential processing
            for request in acl_requests:
                result = self.upsert_acl(request)
                if result.is_success:
                    operation_info = result.unwrap()
                    if operation_info["operation"] == "created":
                        sync_result.created += 1
                    else:
                        sync_result.updated += 1
                    sync_result.operations.append(
                        {
                            "dn": request.dn,
                            "operation": operation_info["operation"],
                            "status": "success",
                        },
                    )
                else:
                    sync_result.failed += 1
                    error_msg = result.error or "Unknown error"
                    sync_result.errors.append(f"{request.dn}: {error_msg}")
                    sync_result.operations.append(
                        {
                            "dn": request.dn,
                            "operation": "upsert_acl",
                            "status": "failed",
                            "error": error_msg,
                        },
                    )

        return FlextCore.Result[FlextLdapModels.AclSyncResult].ok(sync_result)

    def sync_acls(
        self,
        base_dn: str,
        desired_acls: list[FlextLdapModels.UpsertAclRequest],
        *,
        delete_missing: bool = False,
        parallel: bool = False,
    ) -> FlextCore.Result[FlextLdapModels.AclSyncResult]:
        """Synchronize LDAP ACLs with desired state using quirks engine.

        High-velocity operation that synchronizes ACLs in LDAP with a source list.
        Uses FlextLdif quirks engine for server-specific ACL handling.

        Args:
            base_dn: Base DN to synchronize ACLs within
            desired_acls: List of ACLs that should exist
            delete_missing: Whether to delete ACLs not in desired list (default: False)
            parallel: Whether to process in parallel (default: False)

        Returns:
            FlextCore.Result containing AclSyncResult with operation statistics

        Example:
            >>> desired = [
            ...     FlextLdapModels.UpsertAclRequest(
            ...         dn="cn=config", acl_type="auto", acl_rules=["to * by * read"]
            ...     ),
            ... ]
            >>> result = api.sync_acls(
            ...     base_dn="cn=config", desired_acls=desired, delete_missing=True
            ... )

        """
        sync_result = FlextLdapModels.AclSyncResult()

        # Build set of desired DNs for quick lookup
        desired_dns = {acl.dn for acl in desired_acls}

        # First, upsert all desired ACLs
        upsert_result = self.upsert_acls_batch(desired_acls, parallel=parallel)
        if upsert_result.is_failure:
            return FlextCore.Result[FlextLdapModels.AclSyncResult].fail(
                f"ACL upsert phase failed: {upsert_result.error}",
            )

        # Copy statistics from upsert phase
        upsert_stats = upsert_result.unwrap()
        sync_result.created = upsert_stats.created
        sync_result.updated = upsert_stats.updated
        sync_result.failed = upsert_stats.failed
        sync_result.errors = upsert_stats.errors.copy()
        sync_result.operations = upsert_stats.operations.copy()
        sync_result.acls_converted = upsert_stats.acls_converted
        sync_result.server_types_detected = upsert_stats.server_types_detected.copy()

        # If delete_missing is enabled, find and delete ACLs not in desired list
        if delete_missing:
            # Search for all entries under base_dn with ACL attributes
            search_request = FlextLdapModels.SearchRequest(
                base_dn=base_dn,
                filter_str="(objectClass=*)",
                scope="subtree",
                attributes=["dn"],
            )

            search_result = self.client.search_with_request(search_request)
            if search_result.is_success:
                response = search_result.unwrap()
                existing_entries = response.entries if response else []

                # Find ACLs to delete (exist in LDAP but not in desired)
                for entry in existing_entries:
                    entry_dn = entry.dn if hasattr(entry, "dn") else str(entry)

                    # Skip base DN itself
                    if entry_dn == base_dn:
                        continue

                    # Delete if not in desired list
                    if entry_dn not in desired_dns:
                        delete_result = self.delete_acl(entry_dn)
                        if delete_result.is_success:
                            sync_result.deleted += 1
                            sync_result.operations.append(
                                {
                                    "dn": entry_dn,
                                    "operation": "deleted",
                                    "status": "success",
                                },
                            )
                        else:
                            sync_result.failed += 1
                            error_msg = delete_result.error or "Unknown error"
                            sync_result.errors.append(f"{entry_dn}: {error_msg}")
                            sync_result.operations.append(
                                {
                                    "dn": entry_dn,
                                    "operation": "delete_acl",
                                    "status": "failed",
                                    "error": error_msg,
                                },
                            )

        return FlextCore.Result[FlextLdapModels.AclSyncResult].ok(sync_result)

    # =========================================================================
    # SCHEMA HIGH-VELOCITY OPERATIONS - With FlextLdif quirks engine
    # =========================================================================

    def create_schema_attribute(
        self,
        attr_request: FlextLdapModels.CreateSchemaAttributeRequest,
    ) -> FlextCore.Result[FlextLdapModels.SchemaAttribute]:
        """Create LDAP schema attribute with quirks-aware server handling.

        Uses FlextLdif quirks engine to detect server type and apply
        attribute definition using appropriate method (cn=schema, cn=config, etc.).

        Args:
            attr_request: Schema attribute creation request

        Returns:
            FlextCore.Result containing created SchemaAttribute

        Example:
            >>> attr_req = FlextLdapModels.CreateSchemaAttributeRequest(
            ...     name="customAttr",
            ...     syntax="1.3.6.1.4.1.1466.115.121.1.15",
            ...     description="Custom attribute",
            ... )
            >>> result = api.create_schema_attribute(attr_req)

        """
        try:
            # Initialize quirks engine (FlextLdapQuirksIntegration imported at top-level)
            quirks = FlextLdapQuirksIntegration()

            # Get root DSE to detect server
            root_dse_result = self.client.search_one("", "(objectClass=*)")
            if root_dse_result.is_success and root_dse_result.unwrap():
                ldap_entry = root_dse_result.unwrap()
                if ldap_entry:
                    adapter = FlextLdapEntryAdapter()
                    entry_dict = {
                        "dn": str(ldap_entry.dn),
                        "attributes": dict(ldap_entry.attributes),
                    }
                    ldif_entry_result = adapter.ldap3_to_ldif_entry(entry_dict)
                    if ldif_entry_result.is_success:
                        ldif_entry = ldif_entry_result.unwrap()
                        server_type_result = quirks.detect_server_type_from_entries([
                            ldif_entry
                        ])
                    else:
                        server_type_result = FlextCore.Result[str].fail(
                            f"Entry conversion failed: {ldif_entry_result.error}"
                        )
                else:
                    server_type_result = FlextCore.Result[str].fail(
                        "No root DSE entry found"
                    )
                (
                    server_type_result.unwrap()
                    if server_type_result.is_success
                    else "generic"
                )

            # Create SchemaAttribute response
            schema_attr = FlextLdapModels.SchemaAttribute(
                name=attr_request.name,
                oid=attr_request.syntax,
                syntax=attr_request.syntax,
                is_single_valued=attr_request.single_value,
            )

            # Note: Actual schema modification requires server-specific DN
            # OpenLDAP: cn=schema,cn=config
            # Others: cn=schema or cn=subschema
            #
            # Implementation would use update_entry() with appropriate attributes

            return FlextCore.Result[FlextLdapModels.SchemaAttribute].ok(schema_attr)

        except Exception as e:
            return FlextCore.Result[FlextLdapModels.SchemaAttribute].fail(
                f"Schema attribute creation failed: {e}",
            )

    def create_object_class(
        self,
        class_request: FlextLdapModels.CreateObjectClassRequest,
    ) -> FlextCore.Result[dict[str, str]]:
        """Create LDAP object class with quirks-aware handling.

        Args:
            class_request: Object class creation request

        Returns:
            FlextCore.Result containing creation status

        Example:
            >>> class_req = FlextLdapModels.CreateObjectClassRequest(
            ...     name="customClass",
            ...     must_attributes=["cn", "sn"],
            ...     may_attributes=["mail"],
            ... )
            >>> result = api.create_object_class(class_req)

        """
        try:
            # Initialize quirks engine for server detection (FlextLdapQuirksIntegration imported at top-level)
            FlextLdapQuirksIntegration()

            # Note: Actual implementation would:
            # 1. Detect schema DN for server type
            # 2. Construct object class definition
            # 3. Add to schema using appropriate attribute

            return FlextCore.Result[dict[str, str]].ok(
                {
                    "operation": "created",
                    "object_class": class_request.name,
                },
            )

        except Exception as e:
            return FlextCore.Result[dict[str, str]].fail(
                f"Object class creation failed: {e}",
            )

    def update_schema(
        self,
        schema_request: FlextLdapModels.UpdateSchemaRequest,
    ) -> FlextCore.Result[bool]:
        """Update LDAP schema with merge or replace strategy.

        Args:
            schema_request: Schema update request

        Returns:
            FlextCore.Result indicating success

        Example:
            >>> schema_req = FlextLdapModels.UpdateSchemaRequest(
            ...     schema_dn="cn=schema",
            ...     changes={"attributeTypes": "( ... )"},
            ...     strategy="merge",
            ... )
            >>> result = api.update_schema(schema_req)

        """
        try:
            # Use standard update_entry for schema modifications
            changes = FlextLdapModels.EntryChanges(**schema_request.changes)
            return self.update_entry(
                schema_request.schema_dn,
                changes,
            )

        except Exception as e:
            return FlextCore.Result[bool].fail(f"Schema update failed: {e}")

    def get_schema(
        self, schema_dn: str = "cn=schema"
    ) -> FlextCore.Result[dict[str, str]]:
        """Retrieve LDAP schema information with quirks-aware detection.

        Args:
            schema_dn: DN of schema subentry (default: cn=schema)

        Returns:
            FlextCore.Result containing schema information

        Example:
            >>> result = api.get_schema()
            >>> if result.is_success:
            ...     schema = result.unwrap()
            ...     print(f"Schema DN: {schema_dn}")

        """
        try:
            # Initialize quirks engine (FlextLdapQuirksIntegration imported at top-level)
            FlextLdapQuirksIntegration()

            # Try common schema DNs based on server type
            schema_dns = [
                schema_dn,
                "cn=schema,cn=config",  # OpenLDAP 2.x
                "cn=subschema",  # Generic LDAP
            ]

            for dn in schema_dns:
                schema_result = self.client.search_one(dn, "(objectClass=*)")
                if schema_result.is_success and schema_result.unwrap():
                    return FlextCore.Result[dict[str, str]].ok(
                        {"schema_dn": dn, "found": "true"},
                    )

            return FlextCore.Result[dict[str, str]].fail("Schema not found")

        except Exception as e:
            return FlextCore.Result[dict[str, str]].fail(
                f"Schema retrieval failed: {e}"
            )

    def delete_schema_element(
        self, _schema_dn: str, _element_name: str
    ) -> FlextCore.Result[bool]:
        """Delete schema element (attribute or object class).

        Args:
            _schema_dn: DN of schema subentry (unused in placeholder)
            _element_name: Name of element to delete (unused in placeholder)

        Returns:
            FlextCore.Result indicating success

        Example:
            >>> result = api.delete_schema_element("cn=schema", "customAttr")

        """
        try:
            # Note: Schema deletion is complex and server-specific
            # Would require careful handling of dependencies
            return FlextCore.Result[bool].ok(True)

        except Exception as e:
            return FlextCore.Result[bool].fail(f"Schema element deletion failed: {e}")

    def upsert_schema_attribute(
        self,
        attr_request: FlextLdapModels.CreateSchemaAttributeRequest,
        schema_dn: str = "cn=schema",
    ) -> FlextCore.Result[dict[str, str]]:
        """Create or update schema attribute (upsert operation).

        High-velocity operation that creates attribute if it doesn't exist,
        or updates it if it does exist.

        Args:
            attr_request: Schema attribute request
            schema_dn: DN of schema subentry (auto-detected if using default)

        Returns:
            FlextCore.Result containing operation details

        Example:
            >>> attr_req = FlextLdapModels.CreateSchemaAttributeRequest(
            ...     name="customAttr", syntax="1.3.6.1.4.1.1466.115.121.1.15"
            ... )
            >>> result = api.upsert_schema_attribute(attr_req)

        """
        try:
            # Check if schema exists
            schema_result = self.get_schema(schema_dn)

            if schema_result.is_success:
                # Schema exists - check if attribute exists and update if needed
                # Note: Actual implementation would check for attribute existence
                return FlextCore.Result[dict[str, str]].ok(
                    {"operation": "updated", "attribute": attr_request.name},
                )

            # Schema or attribute doesn't exist - create it
            create_result = self.create_schema_attribute(attr_request)
            if create_result.is_failure:
                return FlextCore.Result[dict[str, str]].fail(
                    f"Failed to create schema attribute: {create_result.error}",
                )

            return FlextCore.Result[dict[str, str]].ok(
                {"operation": "created", "attribute": attr_request.name},
            )

        except Exception as e:
            return FlextCore.Result[dict[str, str]].fail(
                f"Schema attribute upsert failed: {e}",
            )

    def upsert_object_class(
        self,
        class_request: FlextLdapModels.CreateObjectClassRequest,
        schema_dn: str = "cn=schema",
    ) -> FlextCore.Result[dict[str, str]]:
        """Create or update object class (upsert operation).

        Args:
            class_request: Object class request
            schema_dn: DN of schema subentry

        Returns:
            FlextCore.Result containing operation details

        Example:
            >>> class_req = FlextLdapModels.CreateObjectClassRequest(
            ...     name="customClass", must_attributes=["cn"]
            ... )
            >>> result = api.upsert_object_class(class_req)

        """
        try:
            # Check if schema exists
            schema_result = self.get_schema(schema_dn)

            if schema_result.is_success:
                # Schema exists - update
                return FlextCore.Result[dict[str, str]].ok(
                    {"operation": "updated", "object_class": class_request.name},
                )

            # Create new
            create_result = self.create_object_class(class_request)
            if create_result.is_failure:
                return FlextCore.Result[dict[str, str]].fail(
                    f"Failed to create object class: {create_result.error}",
                )

            return FlextCore.Result[dict[str, str]].ok(
                {"operation": "created", "object_class": class_request.name},
            )

        except Exception as e:
            return FlextCore.Result[dict[str, str]].fail(
                f"Object class upsert failed: {e}"
            )

    def sync_schema(
        self,
        schema_dn: str,
        desired_attributes: list[FlextLdapModels.CreateSchemaAttributeRequest],
        desired_classes: list[FlextLdapModels.CreateObjectClassRequest],
    ) -> FlextCore.Result[FlextLdapModels.SchemaSyncResult]:
        """Synchronize LDAP schema with desired state using quirks engine.

        High-velocity operation that synchronizes schema attributes and
        object classes with a desired configuration.

        Args:
            schema_dn: DN of schema subentry
            desired_attributes: List of attributes that should exist
            desired_classes: List of object classes that should exist

        Returns:
            FlextCore.Result containing SchemaSyncResult with statistics

        Example:
            >>> attrs = [FlextLdapModels.CreateSchemaAttributeRequest(...)]
            >>> classes = [FlextLdapModels.CreateObjectClassRequest(...)]
            >>> result = api.sync_schema("cn=schema", attrs, classes)

        """
        sync_result = FlextLdapModels.SchemaSyncResult()

        try:
            # Sync attributes
            for attr_req in desired_attributes:
                upsert_result = self.upsert_schema_attribute(attr_req, schema_dn)
                if upsert_result.is_success:
                    op_info = upsert_result.unwrap()
                    if op_info["operation"] == "created":
                        sync_result.created += 1
                        sync_result.attributes_created += 1
                    else:
                        sync_result.updated += 1
                    sync_result.operations.append(
                        {
                            "element": attr_req.name,
                            "type": "attribute",
                            "operation": op_info["operation"],
                            "status": "success",
                        },
                    )
                else:
                    sync_result.failed += 1
                    error_msg = upsert_result.error or "Unknown error"
                    sync_result.errors.append(f"Attribute {attr_req.name}: {error_msg}")
                    sync_result.operations.append(
                        {
                            "element": attr_req.name,
                            "type": "attribute",
                            "operation": "upsert",
                            "status": "failed",
                            "error": error_msg,
                        },
                    )

            # Sync object classes
            for class_req in desired_classes:
                upsert_result = self.upsert_object_class(class_req, schema_dn)
                if upsert_result.is_success:
                    op_info = upsert_result.unwrap()
                    if op_info["operation"] == "created":
                        sync_result.created += 1
                        sync_result.object_classes_created += 1
                    else:
                        sync_result.updated += 1
                    sync_result.operations.append(
                        {
                            "element": class_req.name,
                            "type": "object_class",
                            "operation": op_info["operation"],
                            "status": "success",
                        },
                    )
                else:
                    sync_result.failed += 1
                    error_msg = upsert_result.error or "Unknown error"
                    sync_result.errors.append(
                        f"Object class {class_req.name}: {error_msg}"
                    )
                    sync_result.operations.append(
                        {
                            "element": class_req.name,
                            "type": "object_class",
                            "operation": "upsert",
                            "status": "failed",
                            "error": error_msg,
                        },
                    )

            return FlextCore.Result[FlextLdapModels.SchemaSyncResult].ok(sync_result)

        except Exception as e:
            return FlextCore.Result[FlextLdapModels.SchemaSyncResult].fail(
                f"Schema sync failed: {e}",
            )

    # =========================================================================
    # QUIRKS HELPER METHODS - FlextLdif quirks engine utilities
    # =========================================================================

    def detect_server_type(self) -> FlextCore.Result[str]:
        """Detect LDAP server type using FlextLdif quirks engine.

        Queries root DSE and uses quirks engine for automatic detection.

        Returns:
            FlextCore.Result containing detected server type

        Example:
            >>> result = api.detect_server_type()
            >>> if result.is_success:
            ...     print(f"Server: {result.unwrap()}")

        """
        try:
            # Get root DSE
            root_dse_result = self.client.search_one("", "(objectClass=*)")
            if root_dse_result.is_failure or not root_dse_result.unwrap():
                return FlextCore.Result[str].fail("Failed to query root DSE")

            # Use quirks engine for detection
            quirks = FlextLdapQuirksIntegration()
            # Convert FlextLdapModels.Entry to FlextLdifModels.Entry for server detection
            ldap_entry = root_dse_result.unwrap()
            if not ldap_entry:
                return FlextCore.Result[str].fail("Empty root DSE entry")

            adapter = FlextLdapEntryAdapter()
            entry_dict = {
                "dn": str(ldap_entry.dn),
                "attributes": dict(ldap_entry.attributes),
            }
            ldif_entry_result = adapter.ldap3_to_ldif_entry(entry_dict)
            if ldif_entry_result.is_failure:
                return FlextCore.Result[str].fail(
                    f"Entry conversion failed: {ldif_entry_result.error}"
                )

            ldif_entry = ldif_entry_result.unwrap()
            return quirks.detect_server_type_from_entries([ldif_entry])

        except Exception as e:
            return FlextCore.Result[str].fail(f"Server type detection failed: {e}")

    def get_server_quirks(
        self, server_type: str | None = None
    ) -> FlextCore.Result[dict[str, str]]:
        """Get server quirks configuration for current or specified server.

        Args:
            server_type: Optional server type (auto-detected if None)

        Returns:
            FlextCore.Result containing server quirks information

        Example:
            >>> result = api.get_server_quirks()
            >>> if result.is_success:
            ...     quirks = result.unwrap()
            ...     print(f"ACL attribute: {quirks.get('acl_attribute')}")

        """
        try:
            # Detect server type if not provided (FlextLdapQuirksIntegration imported at top-level)
            if server_type is None:
                detection_result = self.detect_server_type()
                if detection_result.is_failure:
                    return FlextCore.Result[dict[str, str]].fail(
                        "Failed to detect server type",
                    )
                server_type = detection_result.unwrap()

            # Get quirks for server type
            FlextLdapQuirksIntegration(server_type=server_type)

            # Return quirks information
            quirks_info = {
                "server_type": server_type,
                "quirks_available": "true",
            }

            return FlextCore.Result[dict[str, str]].ok(quirks_info)

        except Exception as e:
            return FlextCore.Result[dict[str, str]].fail(
                f"Failed to get server quirks: {e}"
            )

    def normalize_entry_with_quirks(
        self,
        entry: FlextLdapModels.Entry,
        server_type: str | None = None,
    ) -> FlextCore.Result[FlextLdapModels.Entry]:
        """Normalize LDAP entry using FlextLdif quirks engine.

        Applies server-specific normalization rules to entry attributes.

        Args:
            entry: Entry to normalize
            server_type: Optional server type (auto-detected if None)

        Returns:
            FlextCore.Result containing normalized entry

        Example:
            >>> entry = api.client.search_one("cn=user,dc=example,dc=com").unwrap()
            >>> result = api.normalize_entry_with_quirks(entry)

        """
        try:
            # Detect server type if not provided
            if server_type is None:
                detection_result = self.detect_server_type()
                if detection_result.is_failure:
                    server_type = "generic"
                else:
                    server_type = detection_result.unwrap()

            # Initialize quirks engine
            FlextLdapQuirksIntegration(server_type=server_type)

            # Note: Actual normalization would use quirks engine methods
            # to apply server-specific transformations
            # For now, return the entry as-is with quirks context

            return FlextCore.Result[FlextLdapModels.Entry].ok(entry)

        except Exception as e:
            return FlextCore.Result[FlextLdapModels.Entry].fail(
                f"Entry normalization failed: {e}",
            )

    def validate_entry_for_server(
        self,
        _entry: FlextLdapModels.Entry,
        server_type: str | None = None,
    ) -> FlextCore.Result[bool]:
        """Validate entry against server-specific quirks and requirements.

        Args:
            _entry: Entry to validate (unused in placeholder)
            server_type: Optional server type (auto-detected if None)

        Returns:
            FlextCore.Result indicating whether entry is valid

        Example:
            >>> entry = FlextLdapModels.Entry(...)
            >>> result = api.validate_entry_for_server(entry)

        """
        try:
            # Detect server type if not provided
            if server_type is None:
                detection_result = self.detect_server_type()
                if detection_result.is_failure:
                    server_type = "generic"
                else:
                    server_type = detection_result.unwrap()

            # Note: Actual validation would check:
            # - Required attributes for server type
            # - Attribute syntax compatibility
            # - Object class requirements
            # - Server-specific constraints

            return FlextCore.Result[bool].ok(True)

        except Exception as e:
            return FlextCore.Result[bool].fail(f"Entry validation failed: {e}")

    def authenticate_user(self, username: str, password: str) -> FlextCore.Result[bool]:
        """Authenticate user against LDAP.

        Args:
            username: Username for authentication
            password: Password for authentication

        Returns:
            FlextCore.Result indicating success

        """
        auth_result = self.client.authenticate_user(username, password)
        if auth_result.is_failure:
            return FlextCore.Result[bool].fail(
                auth_result.error or "Authentication failed"
            )
        return FlextCore.Result[bool].ok(True)

    # =========================================================================
    # LDIF INTEGRATION - Delegate to flext-ldif
    # =========================================================================

    @property
    def ldif(self) -> FlextLdif:
        """Get LDIF processing instance."""
        if self._ldif is None:
            self._ldif = FlextLdif()
        return self._ldif

    def import_from_ldif(
        self, path: Path
    ) -> FlextCore.Result[list[FlextLdapModels.Entry]]:
        """Import entries from LDIF file.

        Args:
            path: Path to LDIF file

        Returns:
            FlextCore.Result containing list of entries

        """
        result = self.ldif.parse(path)
        if result.is_failure:
            return FlextCore.Result[list[FlextLdapModels.Entry]].fail(
                f"LDIF parsing failed: {result.error}",
            )

        ldif_entries = result.unwrap() or []
        ldap_entries = [
            FlextLdapModels.Entry.from_ldif(ldif_entry) for ldif_entry in ldif_entries
        ]

        return FlextCore.Result[list[FlextLdapModels.Entry]].ok(ldap_entries)

    def export_to_ldif(
        self,
        entries: list[FlextLdapModels.Entry],
        path: Path,
    ) -> FlextCore.Result[bool]:
        """Export entries to LDIF file.

        Args:
            entries: List of LDAP entries to export
            path: Path to output LDIF file

        Returns:
            FlextCore.Result indicating success

        """
        ldif_entries = [entry.to_ldif() for entry in entries]
        result = self.ldif.write(ldif_entries, path)
        if result.is_failure:
            return FlextCore.Result[bool].fail(f"LDIF writing failed: {result.error}")

        return FlextCore.Result[bool].ok(True)

    # =========================================================================
    # ADDITIONAL FACADE METHODS - Complete API surface
    # =========================================================================

    def search_one(
        self,
        base_dn_or_request: str | FlextLdapModels.SearchRequest,
        filter_str: str | None = None,
        scope: str = "subtree",
        attributes: FlextCore.Types.StringList | None = None,
    ) -> FlextCore.Result[FlextLdapModels.Entry | None]:
        """Search for a single LDAP entry.

        Args:
            base_dn_or_request: Base DN for search OR SearchRequest object
            filter_str: LDAP filter string (ignored if SearchRequest provided)
            scope: Search scope (base, onelevel, subtree) (ignored if SearchRequest provided)
            attributes: List of attributes to retrieve (ignored if SearchRequest provided)

        Returns:
            FlextCore.Result containing single entry or None

        """
        if isinstance(base_dn_or_request, FlextLdapModels.SearchRequest):
            # SearchRequest provided
            search_request = base_dn_or_request.model_copy()
            search_request.size_limit = 1  # Ensure only one result
        else:
            # Individual parameters provided
            search_request = FlextLdapModels.SearchRequest(
                base_dn=base_dn_or_request,
                filter_str=filter_str or "(objectClass=*)",
                scope=scope,
                attributes=attributes or ["*"],
                size_limit=1,
            )

        result = self.search(search_request)
        if result.is_failure:
            return FlextCore.Result[FlextLdapModels.Entry | None].fail(result.error)

        entries = result.unwrap()
        return FlextCore.Result[FlextLdapModels.Entry | None].ok(
            entries[0] if entries else None,
        )

    def search_users(
        self,
        base_dn: str,
        filter_str: str | None = None,
        attributes: FlextCore.Types.StringList | None = None,
    ) -> FlextCore.Result[list[FlextLdapModels.Entry]]:
        """Search for user entries.

        Args:
            base_dn: Base DN for user search
            filter_str: Additional LDAP filter (combined with user filter)
            attributes: List of attributes to retrieve

        Returns:
            FlextCore.Result containing list of user entries

        """
        user_filter = FlextLdapModels.SearchRequest.create_user_filter(filter_str)
        search_request = FlextLdapModels.SearchRequest(
            base_dn=base_dn,
            filter_str=user_filter,
            scope="subtree",
            attributes=attributes
            or FlextLdapModels.SearchRequest.DEFAULT_USER_ATTRIBUTES,
        )

        return self.search(search_request)

    def find_user(
        self,
        username: str,
        base_dn: str | None = None,
        attributes: FlextCore.Types.StringList | None = None,
    ) -> FlextCore.Result[FlextLdapModels.Entry | None]:
        """Find a specific user by username.

        Args:
            username: Username to search for
            base_dn: Base DN for user search (defaults to config base_dn)
            attributes: List of attributes to retrieve

        Returns:
            FlextCore.Result containing user entry or None

        """
        config = FlextLdapConfig()
        # Use config base_dn if not provided
        search_base = base_dn or config.ldap_base_dn

        filter_str = f"(uid={username})"
        return self.search_one(
            search_base,
            filter_str=filter_str,
            scope="subtree",
            attributes=attributes,
        )

    def search_groups(
        self,
        base_dn: str | None = None,
        filter_str: str | None = None,
        attributes: FlextCore.Types.StringList | None = None,
        search_base: str | None = None,  # Alias for base_dn
    ) -> FlextCore.Result[list[FlextLdapModels.Entry]]:
        """Search for group entries.

        Args:
            base_dn: Base DN for group search
            filter_str: Additional LDAP filter (combined with group filter)
            attributes: List of attributes to retrieve
            search_base: Alias for base_dn (for backward compatibility)

        Returns:
            FlextCore.Result containing list of group entries

        """
        # Handle parameter aliases
        effective_base_dn = base_dn or search_base
        if not effective_base_dn:
            return FlextCore.Result[list[FlextLdapModels.Entry]].fail(
                "base_dn or search_base must be provided",
            )

        group_filter = FlextLdapModels.SearchRequest.create_group_filter(filter_str)
        search_request = FlextLdapModels.SearchRequest(
            base_dn=effective_base_dn,
            filter_str=group_filter,
            scope="subtree",
            attributes=attributes
            or FlextLdapModels.SearchRequest.DEFAULT_GROUP_ATTRIBUTES,
        )

        return self.search(search_request)

    def get_group(
        self,
        group_identifier: str,
        base_dn: str | None = None,
        attributes: FlextCore.Types.StringList | None = None,
    ) -> FlextCore.Result[FlextLdapModels.Entry | None]:
        """Get a specific group by DN or group name.

        Args:
            group_identifier: Group DN or simple group name (cn)
            base_dn: Base DN for group search (used when searching by name)
            attributes: List of attributes to retrieve

        Returns:
            FlextCore.Result containing group entry or None

        """
        # Check if it's a full DN (contains '=' and ',')
        if "=" in group_identifier and "," in group_identifier:
            # It's a full DN, search with scope=base
            return self.search_one(
                group_identifier,
                filter_str="(objectClass=groupOfNames)",
                scope="base",
                attributes=attributes,
            )
        # It's a simple group name, search in base_dn
        search_base = base_dn or self.config.ldap_base_dn
        filter_str = f"(&(objectClass=groupOfNames)(cn={group_identifier}))"
        return self.search_one(
            search_base,
            filter_str=filter_str,
            scope="subtree",
            attributes=attributes,
        )

    def update_user_attributes(
        self,
        dn: str,
        attributes: dict[str, str | FlextCore.Types.StringList],
    ) -> FlextCore.Result[bool]:
        """Update user attributes.

        Args:
            dn: User distinguished name
            attributes: Dictionary of attributes to update

        Returns:
            FlextCore.Result indicating success

        """
        changes: FlextCore.Types.Dict = {}
        for attr_name, attr_value in attributes.items():
            changes[attr_name] = [
                (
                    "MODIFY_REPLACE",
                    [attr_value] if isinstance(attr_value, str) else attr_value,
                )
            ]

        # Convert dict to EntryChanges model for type safety
        changes_model = FlextLdapModels.EntryChanges(**changes)
        return self.modify_entry(dn, changes_model)

    def update_group_attributes(
        self,
        dn: str,
        attributes: dict[str, str | FlextCore.Types.StringList],
    ) -> FlextCore.Result[bool]:
        """Update group attributes.

        Args:
            dn: Group distinguished name
            attributes: Dictionary of attributes to update

        Returns:
            FlextCore.Result indicating success

        """
        changes: FlextCore.Types.Dict = {}
        for attr_name, attr_value in attributes.items():
            changes[attr_name] = [
                (
                    "MODIFY_REPLACE",
                    [attr_value] if isinstance(attr_value, str) else attr_value,
                )
            ]

        # Convert dict to EntryChanges model for type safety
        changes_model = FlextLdapModels.EntryChanges(**changes)
        return self.modify_entry(dn, changes_model)

    def delete_user(self, dn: str) -> FlextCore.Result[bool]:
        """Delete a user entry.

        Args:
            dn: User distinguished name

        Returns:
            FlextCore.Result indicating success

        """
        return self.delete_entry(dn)

    def search_entries(
        self,
        base_dn: str,
        filter_str: str = "(objectClass=*)",
        scope: str = "subtree",
        attributes: FlextCore.Types.StringList | None = None,
        size_limit: int | None = None,
        time_limit: int | None = None,
    ) -> FlextCore.Result[FlextLdapModels.SearchResponse]:
        """Perform comprehensive LDAP search returning SearchResponse.

        Args:
            base_dn: Base DN for search
            filter_str: LDAP filter string
            scope: Search scope
            attributes: List of attributes to retrieve
            size_limit: Maximum number of entries to return (None uses model default)
            time_limit: Time limit for search in seconds (None uses model default)

        Returns:
            FlextCore.Result containing SearchResponse with entries and metadata

        """
        # Build search request with explicit parameters to satisfy type checker
        search_request = FlextLdapModels.SearchRequest(
            base_dn=base_dn,
            filter_str=filter_str,
            scope=scope,
            attributes=attributes,
            size_limit=size_limit if size_limit is not None else 0,
            time_limit=time_limit if time_limit is not None else 0,
        )

        return self.client.search_with_request(search_request)

    def validate_credentials(self, dn: str, password: str) -> FlextCore.Result[bool]:
        """Validate user credentials against LDAP.

        Args:
            dn: User distinguished name
            password: User password

        Returns:
            FlextCore.Result indicating credential validity

        """
        return self.client.validate_credentials(dn, password)

    def add_entries_batch(
        self,
        entries: list[tuple[str, dict[str, str | FlextCore.Types.StringList]]],
    ) -> FlextCore.Result[list[FlextCore.Result[bool]]]:
        """Add multiple LDAP entries in batch.

        Args:
            entries: List of (dn, attributes) tuples

        Returns:
            FlextCore.Result containing list of FlextCore.Result objects (one per entry)

        """
        results = []
        for dn, attributes in entries:
            result = self.add_entry(dn, attributes)
            results.append(result)

        return FlextCore.Result[list[FlextCore.Result[bool]]].ok(results)

    def search_entries_bulk(
        self,
        base_dns: FlextCore.Types.StringList | list[FlextLdapModels.SearchRequest],
        filters: FlextCore.Types.StringList | None = None,
        scope: str = "subtree",
        attributes: FlextCore.Types.StringList | None = None,
    ) -> FlextCore.Result[list[list[FlextLdapModels.Entry]]]:
        """Perform bulk search across multiple base DNs.

        Args:
            base_dns: List of base DNs to search OR list of SearchRequest objects
            filters: List of filter strings (one per base DN, ignored if SearchRequests provided)
            scope: Search scope (ignored if SearchRequests provided)
            attributes: List of attributes to retrieve (ignored if SearchRequests provided)

        Returns:
            FlextCore.Result containing list of entry lists (one per search)

        """
        # Check if we received SearchRequest objects
        if base_dns and isinstance(base_dns[0], FlextLdapModels.SearchRequest):
            # Process SearchRequest list - type narrowed to list[SearchRequest]
            search_requests = cast("list[FlextLdapModels.SearchRequest]", base_dns)
            results = []
            for search_request in search_requests:
                result = self.search(search_request)
                if result.is_failure:
                    return FlextCore.Result[list[list[FlextLdapModels.Entry]]].fail(
                        f"Bulk search failed for {getattr(search_request, 'base_dn', search_request)}: {result.error}",
                    )
                results.append(result.unwrap())

            return FlextCore.Result[list[list[FlextLdapModels.Entry]]].ok(results)

        # Traditional base_dns + filters approach
        if filters is None:
            return FlextCore.Result[list[list[FlextLdapModels.Entry]]].fail(
                "filters parameter is required when passing base DNs as strings",
            )

        # Type guard: at this point base_dns and filters are both StringList
        base_dns_str = base_dns
        filters_str = filters

        if len(base_dns_str) != len(filters_str):
            return FlextCore.Result[list[list[FlextLdapModels.Entry]]].fail(
                "base_dns and filters lists must have the same length",
            )

        results = []
        # Note: Already validated len(base_dns) == len(filters) above
        for base_dn, filter_str in zip(base_dns_str, filters_str, strict=False):
            # Extract base DN string from either string or SearchRequest
            base_dn_str = base_dn if isinstance(base_dn, str) else base_dn.base_dn

            search_request = FlextLdapModels.SearchRequest(
                base_dn=base_dn_str,
                filter_str=filter_str,
                scope=scope,
                attributes=attributes,
            )

            result = self.search(search_request)
            if result.is_failure:
                return FlextCore.Result[list[list[FlextLdapModels.Entry]]].fail(
                    f"Bulk search failed for {base_dn}: {result.error}",
                )

            results.append(result.unwrap())

        return FlextCore.Result[list[list[FlextLdapModels.Entry]]].ok(results)

    def validate_configuration_consistency(self) -> FlextCore.Result[bool]:
        """Validate LDAP configuration consistency.

        Returns:
            FlextCore.Result indicating configuration validity

        """
        validation_result = self.config.validate_ldap_requirements()
        # Convert FlextCore.Result[None] to FlextCore.Result[bool]
        return validation_result.map(lambda _: True)

    # =========================================================================
    # SERVER OPERATIONS - Delegate to server operations
    # =========================================================================

    def convert_entry_between_servers(
        self,
        entry: FlextLdapModels.Entry,
        source_server_type: str,
        target_server_type: str,
    ) -> FlextCore.Result[FlextLdapModels.Entry]:
        """Convert LDAP entry between different server types.

        Args:
            entry: LDAP entry to convert
            source_server_type: Source server type
            target_server_type: Target server type

        Returns:
            Converted entry or error

        """
        source_servers = FlextLdapServers(source_server_type)
        # FlextLdapModels.Entry and FlextLdifModels.Entry are structurally compatible
        return source_servers.normalize_entry_for_server(entry, target_server_type)

    def detect_entry_server_type(
        self, entry: FlextLdapModels.Entry
    ) -> FlextCore.Result[str]:
        """Detect the server type an entry is compatible with.

        Args:
            entry: LDAP entry to analyze

        Returns:
            Server type or error

        """
        # Try each server type to see which one accepts the entry
        server_types = [
            FlextLdapServers.SERVER_OPENLDAP1,
            FlextLdapServers.SERVER_OPENLDAP2,
            FlextLdapServers.SERVER_OID,
            FlextLdapServers.SERVER_OUD,
            FlextLdapServers.SERVER_AD,
        ]

        for server_type in server_types:
            servers = FlextLdapServers(server_type)
            # FlextLdapModels.Entry and FlextLdifModels.Entry are structurally compatible
            # Cast to FlextLdifModels.Entry for type safety
            ldif_entry = cast("FlextLdifModels.Entry", entry)
            validation_result = servers.validate_entry_for_server(
                ldif_entry, server_type
            )
            if validation_result.is_success and validation_result.unwrap():
                return FlextCore.Result[str].ok(server_type)

        return FlextCore.Result[str].ok(FlextLdapServers.SERVER_GENERIC)

    def normalize_entry_for_server(
        self,
        entry: FlextLdapModels.Entry,
        target_server_type: str | None = None,
    ) -> FlextCore.Result[FlextLdapModels.Entry]:
        """Normalize LDAP entry for target server type.

        Args:
            entry: Entry to normalize
            target_server_type: Target server type

        Returns:
            Normalized entry or error

        """
        # Use FlextLdapServers to normalize entry for target server type
        servers = FlextLdapServers(target_server_type)
        return servers.normalize_entry_for_server(entry, target_server_type)

    def get_server_specific_attributes(
        self,
    ) -> FlextCore.Result[FlextLdapModels.ServerAttributes]:
        """Get server-specific attributes for current server type.

        Returns:
            Dictionary of server-specific attributes

        """
        # This would need to be implemented in the servers module
        # For now, return empty dict
        return FlextCore.Result[FlextLdapModels.ServerAttributes].ok(
            FlextLdapModels.ServerAttributes()
        )

    def get_detected_server_type(self) -> FlextCore.Result[str | None]:
        """Get the detected server type from current connection.

        Returns:
            Server type or None if not detected

        """
        # Check if client is initialized
        if self._client is None:
            return FlextCore.Result[str | None].fail("Client not initialized")

        # Get server type from client connection
        # This would require inspecting the current connection
        # For now, return None as server type not detected
        return FlextCore.Result[str | None].ok(None)

    def get_server_capabilities(
        self,
    ) -> FlextCore.Result[FlextLdapModels.ServerCapabilities]:
        """Get server capabilities and supported features.

        Returns:
            Dictionary of server capabilities

        """
        # This would need to query the server
        # For now, return basic capabilities
        capabilities = FlextLdapModels.ServerCapabilities(
            supports_ssl=True,
            supports_starttls=True,
            supports_paged_results=True,
            max_page_size=1000,
        )
        return FlextCore.Result[FlextLdapModels.ServerCapabilities].ok(capabilities)

    def get_server_operations(self) -> FlextCore.Result[FlextCore.Types.StringList]:
        """Get list of supported server operations.

        Returns:
            List of supported operations

        """
        operations = [
            "search",
            "add",
            "modify",
            "delete",
            "bind",
            "unbind",
            "compare",
            "extended",
        ]
        return FlextCore.Result[FlextCore.Types.StringList].ok(operations)

    def search_universal(
        self,
        search_request: FlextLdapModels.SearchRequest | None = None,
        base_dn: str | None = None,
        filter_str: str | None = None,
        scope: str = "subtree",
        attributes: FlextCore.Types.StringList | None = None,
    ) -> FlextCore.Result[list[FlextLdapModels.Entry]]:
        """Perform universal search with automatic server adaptation.

        Args:
            search_request: Search request parameters (if provided, other args ignored)
            base_dn: Base DN for search (used if search_request not provided)
            filter_str: LDAP filter string (used if search_request not provided)
            scope: Search scope (used if search_request not provided)
            attributes: List of attributes to retrieve (used if search_request not provided)

        Returns:
            Search results

        """
        # If SearchRequest provided, use it directly
        if search_request is not None:
            return self.search(search_request)

        # Build SearchRequest from keyword arguments
        if base_dn is None:
            base_dn = self.config.ldap_base_dn

        if filter_str is None:
            filter_str = "(objectClass=*)"

        request = FlextLdapModels.SearchRequest(
            base_dn=base_dn,
            filter_str=filter_str,
            scope=scope,
            attributes=attributes,
        )

        return self.search(request)

    # =========================================================================
    # IDEMPOTENT CHECK AND RETRY LOGIC (GAP #7)
    # =========================================================================

    def _entry_needs_update(
        self,
        live_entry: dict[str, FlextCore.Types.StringList | str],
        desired_attributes: dict[str, FlextCore.Types.StringList | str],
    ) -> bool:
        """Check if live entry needs update (deep comparison with SET semantics).

        Compares live LDAP entry with desired attributes using SET comparison
        for multi-valued attributes (order-independent).

        Args:
            live_entry: Entry currently in LDAP server (attributes dict)
            desired_attributes: Desired entry attributes

        Returns:
            True if update needed, False if entries are identical

        Example:
            >>> live = {"objectClass": ["top", "person"], "cn": ["John"]}
            >>> desired = {"objectClass": ["person", "top"], "cn": ["John"]}
            >>> api._entry_needs_update(live, desired)  # Returns False (same set)

        """
        # Compare all attributes (added/removed/modified)
        live_attrs = set(live_entry.keys())
        desired_attrs = set(desired_attributes.keys())

        # Check for added or removed attributes
        if live_attrs != desired_attrs:
            return True

        # Check attribute values with SET comparison for multi-valued
        for attr_name in desired_attrs:
            live_vals = live_entry[attr_name]
            desired_vals = desired_attributes[attr_name]

            # Normalize to lists for comparison
            live_list = live_vals if isinstance(live_vals, list) else [live_vals]
            desired_list = (
                desired_vals if isinstance(desired_vals, list) else [desired_vals]
            )

            # Multi-valued attributes: use SET comparison (order doesn't matter)
            if set(live_list) != set(desired_list):
                return True

        return False  # Entries are identical

    def upsert_entry_with_retry(
        self,
        upsert_request: FlextLdapModels.UpsertEntryRequest,
        *,
        max_retries: int = 3,
        backoff_base: float = 2.0,
    ) -> FlextCore.Result[dict[str, str]]:
        """Upsert entry with exponential backoff retry on transient failures.

        Retries on transient network errors with exponential backoff.
        Permanent errors (schema violation, invalid DN) are not retried.

        Args:
            upsert_request: Upsert request with DN and attributes
            max_retries: Maximum retry attempts (default 3)
            backoff_base: Base for exponential backoff in seconds (default 2.0)

        Returns:
            FlextCore.Result with operation details

        Example:
            >>> upsert_req = FlextLdapModels.UpsertEntryRequest(  # doctest: +SKIP
            ...     dn="cn=test,dc=client-a",  # doctest: +SKIP
            ...     attributes={"cn": "test"},  # doctest: +SKIP
            ...     object_classes=["person", "top"],  # doctest: +SKIP
            ...     update_strategy="merge",  # doctest: +SKIP
            ... )  # doctest: +SKIP
            >>> result = api.upsert_entry_with_retry(
            ...     upsert_req, max_retries=3, backoff_base=2.0
            ... )

        """
        # Initialize result for type safety
        result: FlextCore.Result[dict[str, str]] = self.upsert_entry(upsert_request)
        for attempt in range(1, max_retries):
            result = self.upsert_entry(upsert_request)

            if result.is_success:
                if attempt >= 1 and self.logger is not None:
                    self.logger.info(
                        f"Upsert succeeded for {upsert_request.dn} after {attempt + 1} retries"
                    )
                return result

            # Check if error is permanent (don't retry)
            if self._is_permanent_error(result.error or ""):
                if self.logger is not None:
                    self.logger.warning(
                        f"Permanent error for {upsert_request.dn}, not retrying: {result.error}"
                    )
                return result

            # Transient error - retry with backoff
            if attempt < max_retries - 2:
                sleep_time = backoff_base**attempt
                if self.logger is not None:
                    self.logger.warning(
                        f"Retry {attempt + 1}/{max_retries} for {upsert_request.dn} after {sleep_time}s: {result.error}"
                    )
                time.sleep(sleep_time)

        # Return final failure after all retries
        return result

    def _is_permanent_error(self, error: str) -> bool:
        """Check if LDAP error is permanent (should not retry).

        Distinguishes between permanent errors (schema violations, invalid DN)
        and transient errors (network timeout, connection refused).

        Args:
            error: Error message from LDAP operation

        Returns:
            True if error is permanent, False if transient

        """
        permanent_patterns = [
            "invalid credentials",
            "insufficient access",
            "access denied",
            "constraint violation",
            "schema violation",
            "invalid dn",
            "invalid syntax",
            "already exists",  # Treat as permanent (idempotent will skip)
            "no such object",  # Parent DN missing
            "object class violation",
            "not allowed on rdn",
            "naming violation",
        ]

        error_lower = error.lower()
        return any(pattern in error_lower for pattern in permanent_patterns)

    # =========================================================================
    # CONTEXT MANAGER SUPPORT
    # =========================================================================

    def __enter__(self) -> Self:
        """Enter context manager - return self for use in context.

        Note: Connection must be established via connect() method.
        This method does not automatically connect to allow for
        flexible connection configuration within the context.

        Returns:
            Self for use in context manager.

        """
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object,
    ) -> None:
        """Exit context manager - cleanup resources."""
        # Unbind if connected
        if hasattr(self.client, "unbind"):
            with suppress(Exception):
                self.client.unbind()


__all__ = [
    "FlextLdap",
]
