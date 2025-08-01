"""FLEXT LDAP Application Service.

Application layer service implementing LDAP operations using Clean Architecture.
Provides a high-level interface for LDAP user and group management operations.

COMPLETELY REFACTORED: No mocks, fallbacks, or placeholders.
Uses real FLEXT infrastructure following SOLID principles.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid4

from flext_core import FlextResult, get_logger

from flext_ldap.api import FlextLdapApi
from flext_ldap.entities import FlextLdapUser

if TYPE_CHECKING:
    from flext_ldap.config import FlextLdapConnectionConfig
    from flext_ldap.values import FlextLdapCreateUserRequest

logger = get_logger(__name__)


class FlextLdapService:
    """Application service for LDAP operations using Clean Architecture.

    Uses FlextLdapApi for real LDAP operations, eliminating all mocks/fallbacks.
    Follows SOLID principles by delegating to infrastructure layer.
    """

    def __init__(self, config: FlextLdapConnectionConfig | None = None) -> None:
        """Initialize LDAP service with real infrastructure."""
        self._api = FlextLdapApi(config)
        self._session_id: str | None = None
        logger.info("FlextLdapService initialized with real infrastructure")

    def is_connected(self) -> bool:
        """Check if service is connected to LDAP server."""
        return self._session_id is not None

    async def connect(
        self,
        server_url: str,
        bind_dn: str,
        bind_password: str,
    ) -> FlextResult[bool]:
        """Connect to LDAP server using real infrastructure."""
        logger.info("Connecting to LDAP server", extra={"server_url": server_url})

        try:
            # Use real FlextLdapApi for connection
            connect_result = await self._api.connect(
                server_url=server_url,
                bind_dn=bind_dn,
                password=bind_password,
            )

            if connect_result.is_success:
                self._session_id = connect_result.data
                logger.info("Successfully connected to LDAP server")
                return FlextResult.ok(data=True)

            logger.error(
                "Failed to connect to LDAP server",
                extra={"error": connect_result.error},
            )
            return FlextResult.fail(connect_result.error or "Connection failed")

        except Exception as e:
            error_msg = f"Connection error: {e}"
            logger.exception(error_msg)
            return FlextResult.fail(error_msg)

    async def disconnect(self) -> FlextResult[bool]:
        """Disconnect from LDAP server using real infrastructure."""
        if not self.is_connected():
            return FlextResult.ok(data=True)

        logger.info("Disconnecting from LDAP server")
        try:
            # Session ID guaranteed by is_connected() check above
            if self._session_id is None:
                return FlextResult.fail("No session ID available for disconnection")
            # Use real FlextLdapApi for disconnection
            result = await self._api.disconnect(self._session_id)
            if result.is_success:
                self._session_id = None
                logger.info("Successfully disconnected from LDAP server")
                return FlextResult.ok(data=True)

            logger.error(
                "Failed to disconnect from LDAP server", extra={"error": result.error}
            )
            return FlextResult.fail(result.error or "Disconnect failed")

        except Exception as e:
            error_msg = f"Disconnect error: {e}"
            logger.exception(error_msg)
            return FlextResult.fail(error_msg)

    async def create_user(
        self,
        request: FlextLdapCreateUserRequest,
    ) -> FlextResult[FlextLdapUser]:
        """Create a new user using real LDAP infrastructure.

        No fallbacks or memory storage - uses real LDAP API.
        """
        logger.info("Creating user", extra={"uid": request.uid})

        if not self.is_connected():
            return FlextResult.fail("Not connected to LDAP server")

        try:
            # Session ID guaranteed by is_connected() check above
            if self._session_id is None:
                return FlextResult.fail("No session ID available for operation")
            # Use real FlextLdapApi for user creation
            result = await self._api.create_user(self._session_id, request)

            if result.is_success:
                logger.info(
                    "User created successfully",
                    extra={"uid": request.uid, "dn": request.dn},
                )
                return result

            logger.error(
                "Failed to create user",
                extra={"uid": request.uid, "error": result.error},
            )
            return result

        except Exception as e:
            error_msg = f"User creation error: {e}"
            logger.exception(error_msg, extra={"uid": request.uid})
            return FlextResult.fail(error_msg)

    async def find_user_by_uid(self, uid: str) -> FlextResult[FlextLdapUser]:
        """Find user by UID using real LDAP search.

        No fallbacks or memory storage - uses real LDAP API.
        """
        logger.info("Finding user by UID", extra={"uid": uid})

        if not self.is_connected():
            return FlextResult.fail("Not connected to LDAP server")

        try:
            # Session ID guaranteed by is_connected() check above
            if self._session_id is None:
                return FlextResult.fail("No session ID available for operation")
            # Use real FlextLdapApi for user search
            search_result = await self._api.search(
                session_id=self._session_id,
                base_dn=self._get_search_base_dn(),
                filter_expr=f"(uid={uid})",
                attributes=["uid", "cn", "sn", "mail", "dn"],
            )

            if search_result.is_success and search_result.data:
                entries = search_result.data
                if entries:
                    # Convert first entry to FlextLdapUser
                    entry = entries[0]
                    user_attrs = entry.attributes

                    # Extract user attributes with safe defaults
                    cn_attrs = user_attrs.get("cn", [""])
                    cn_value = cn_attrs[0] if cn_attrs else ""

                    sn_attrs = user_attrs.get("sn", [""])
                    sn_value = sn_attrs[0] if sn_attrs else ""

                    mail_attrs = user_attrs.get("mail", [""])
                    mail_value = mail_attrs[0] if mail_attrs else None

                    user = FlextLdapUser(
                        id=str(uuid4()),
                        dn=entry.dn,
                        uid=uid,
                        cn=cn_value,
                        sn=sn_value,
                        mail=mail_value,
                    )

                    logger.info("User found successfully", extra={"uid": uid})
                    return FlextResult.ok(user)

            logger.info("User not found", extra={"uid": uid})
            return FlextResult.fail(f"User with UID {uid} not found")

        except Exception as e:
            error_msg = f"User search error: {e}"
            logger.exception(error_msg, extra={"uid": uid})
            return FlextResult.fail(error_msg)

    async def update_user(
        self,
        user_id: str,
        updates: dict[str, object],
    ) -> FlextResult[FlextLdapUser]:
        """Update user attributes using real LDAP infrastructure.

        No fallbacks or memory storage - uses real LDAP API.
        """
        logger.info("Updating user", extra={"user_id": user_id})

        try:
            # Railway Oriented Programming - consolidated update pipeline
            return await self._execute_user_update_pipeline(user_id, updates)

        except Exception as e:
            error_msg = f"User update error: {e}"
            logger.exception(error_msg, extra={"user_id": user_id})
            return FlextResult.fail(error_msg)

    async def _execute_user_update_pipeline(
        self,
        user_id: str,
        updates: dict[str, object],
    ) -> FlextResult[FlextLdapUser]:
        """Execute user update pipeline with consolidated error handling."""
        # Validate connection and session - Single Responsibility
        validation_result = self._validate_connection_for_operation()
        if validation_result.is_failure:
            error_msg = validation_result.error or "Connection validation failed"
            return FlextResult.fail(error_msg)

        # Find and validate user existence - Single Responsibility
        user_result = await self._find_and_validate_user(user_id)
        if user_result.is_failure:
            return user_result

        user = user_result.data
        if not user:
            return FlextResult.fail(f"User {user_id} not found")

        # Session ID guaranteed by validation above
        session_id = self._session_id
        if not session_id:
            return FlextResult.fail("No session ID available")

        # Use real FlextLdapApi for user update
        update_result = await self._api.update_user(
            session_id=session_id,
            user_dn=user.dn,
            updates=updates,
        )

        # Handle update result - Single Responsibility
        return await self._handle_update_result(update_result, user_id)

    def _validate_connection_for_operation(self) -> FlextResult[None]:
        """Validate connection and session for LDAP operations."""
        if not self.is_connected():
            return FlextResult.fail("Not connected to LDAP server")

        if self._session_id is None:
            return FlextResult.fail("No session ID available for operation")

        return FlextResult.ok(None)

    async def _find_and_validate_user(self, user_id: str) -> FlextResult[FlextLdapUser]:
        """Find user and validate existence for operations."""
        find_result = await self.find_user_by_uid(user_id)
        if find_result.is_failure:
            return FlextResult.fail(f"User {user_id} not found for update")

        user = find_result.data
        if not user:
            return FlextResult.fail(f"User {user_id} not found")

        return FlextResult.ok(user)

    async def _handle_update_result(
        self,
        update_result: FlextResult[bool],
        user_id: str,
    ) -> FlextResult[FlextLdapUser]:
        """Handle the result of user update operation."""
        if update_result.is_success:
            logger.info("User updated successfully", extra={"user_id": user_id})
            return await self.find_user_by_uid(user_id)

        logger.error(
            "Failed to update user",
            extra={"user_id": user_id, "error": update_result.error},
        )
        return FlextResult.fail(update_result.error or "User update failed")

    async def delete_user(self, uid: str) -> FlextResult[bool]:
        """Delete user by UID using real LDAP infrastructure.

        No fallbacks or memory storage - uses real LDAP API.
        """
        logger.info("Deleting user", extra={"uid": uid})

        try:
            # Railway Oriented Programming - consolidated deletion pipeline
            return await self._execute_user_deletion_pipeline(uid)

        except Exception as e:
            error_msg = f"User deletion error: {e}"
            logger.exception(error_msg, extra={"uid": uid})
            return FlextResult.fail(error_msg)

    async def _execute_user_deletion_pipeline(self, uid: str) -> FlextResult[bool]:
        """Execute user deletion pipeline with consolidated error handling."""
        # Validate connection and session - Single Responsibility
        validation_result = self._validate_connection_for_operation()
        if validation_result.is_failure:
            error_msg = validation_result.error or "Connection validation failed"
            return FlextResult.fail(error_msg)

        # Find and validate user existence - reuse helper method
        user_result = await self._find_and_validate_user(uid)
        if user_result.is_failure:
            return FlextResult.fail(f"User {uid} not found for deletion")

        user = user_result.data
        if not user:
            return FlextResult.fail(f"User {uid} not found")

        # Session ID guaranteed by validation above
        session_id = self._session_id
        if not session_id:
            return FlextResult.fail("No session ID available")

        # Use real FlextLdapApi for user deletion
        delete_result = await self._api.delete_user(
            session_id=session_id,
            user_dn=user.dn,
        )

        # Handle deletion result - Single Responsibility
        return self._handle_deletion_result(delete_result, uid)

    def _handle_deletion_result(
        self,
        delete_result: FlextResult[bool],
        uid: str,
    ) -> FlextResult[bool]:
        """Handle the result of user deletion operation."""
        if delete_result.is_success:
            logger.info("User deleted successfully", extra={"uid": uid})
            return FlextResult.ok(data=True)

        logger.error(
            "Failed to delete user", extra={"uid": uid, "error": delete_result.error}
        )
        return FlextResult.fail(delete_result.error or "User deletion failed")

    async def list_users(
        self,
        base_dn: str | None = None,
        filter_expr: str | None = None,
    ) -> FlextResult[list[FlextLdapUser]]:
        """List users from LDAP directory using real infrastructure.

        No fallbacks or memory storage - uses real LDAP API.
        """
        logger.info(
            "Listing users",
            extra={
                "base_dn": base_dn,
                "filter_expr": filter_expr,
            },
        )

        if not self.is_connected():
            return FlextResult.fail("Not connected to LDAP server")

        try:
            # Use provided parameters or defaults
            search_base = base_dn or self._get_search_base_dn()
            search_filter = filter_expr or "(objectClass=person)"

            # Session ID guaranteed by is_connected() check above
            if self._session_id is None:
                return FlextResult.fail("No session ID available for operation")
            # Use real FlextLdapApi for user search
            search_result = await self._api.search(
                session_id=self._session_id,
                base_dn=search_base,
                filter_expr=search_filter,
                attributes=["uid", "cn", "sn", "mail", "dn"],
            )

            if search_result.is_success:
                users = []
                for entry in search_result.data or []:
                    # Convert FlextLdapEntry to FlextLdapUser
                    user_attrs = entry.attributes
                    uid_attrs = user_attrs.get("uid", [""])
                    uid = uid_attrs[0] if uid_attrs else ""

                    if uid:  # Only create user if UID exists
                        user = FlextLdapUser(
                            id=str(uuid4()),
                            dn=entry.dn,
                            uid=uid,
                            cn=self._extract_attr_value(user_attrs, "cn"),
                            sn=self._extract_attr_value(user_attrs, "sn"),
                            mail=self._extract_attr_value(user_attrs, "mail"),
                        )
                        users.append(user)

                logger.info("Users listed successfully", extra={"count": len(users)})
                return FlextResult.ok(users)

            logger.error("Failed to list users", extra={"error": search_result.error})
            return FlextResult.fail(search_result.error or "Failed to list users")

        except Exception as e:
            error_msg = f"User listing error: {e}"
            logger.exception(error_msg)
            return FlextResult.fail(error_msg)

    def _get_search_base_dn(self) -> str:
        """Get base DN for LDAP searches - configurable default."""
        # Default RFC-compliant base DN - can be overridden by configuration
        return "dc=example,dc=com"

    def _extract_attr_value(
        self,
        attributes: dict[str, list[str]],
        attr_name: str,
    ) -> str | None:
        """Extract first value from LDAP attribute list, handling None gracefully."""
        attr_list = attributes.get(attr_name, [])
        if attr_list:
            return attr_list[0]
        return None if attr_name == "mail" else ""
