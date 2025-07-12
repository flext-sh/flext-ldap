"""LDAP Operations using flext-core patterns."""

from __future__ import annotations

from typing import Any, TypeVar

from flext_core.domain.types import ServiceResult
from flext_ldap.models import LDAPEntry, LDAPFilter, LDAPScope

try:
    from ldap3 import Connection
    from ldap3.core.exceptions import LDAPException
except ImportError:
    Connection = Any
    LDAPException = Exception

# Use centralized logger from flext-observability - ELIMINATE DUPLICATION
from flext_observability.logging import get_logger

logger = get_logger(__name__)

T = TypeVar("T")


class LDAPOperation:
    """Base class for LDAP operations using flext-core patterns."""

    def __init__(self, connection: Connection) -> None:
        self.connection = connection

    def is_connected(self) -> bool:
        """Check if the LDAP connection is active and bound.

        Returns:
            True if connection is bound, False otherwise

        """
        return bool(self.connection and self.connection.bound)

    def get_connection_info(self) -> dict[str, bool | str | None]:
        """Get information about the LDAP connection.

        Returns:
            Dictionary containing connection status, server, and user info

        """
        if not self.connection:
            return {"connected": False}
        return {
            "connected": self.connection.bound,
            "server": (
                str(self.connection.server)
                if hasattr(self.connection, "server")
                else None
            ),
            "user": getattr(self.connection, "user", None),
        }


class SearchOperation(LDAPOperation):
    """LDAP search operation using flext-core patterns."""

    async def execute(
        self,
        base_dn: str,
        filter_obj: LDAPFilter | str,
        scope: LDAPScope = LDAPScope.SUB,
        attributes: list[str] | None = None,
    ) -> ServiceResult[list[LDAPEntry]]:
        """Execute an LDAP search operation.

        Args:
            base_dn: Base distinguished name for the search
            filter_obj: LDAP filter (LDAPFilter object or string)
            scope: Search scope (default: SUB)
            attributes: List of attributes to retrieve (default: all)

        Returns:
            ServiceResult containing list of LDAPEntry objects or error

        """
        try:
            if isinstance(filter_obj, LDAPFilter):
                search_filter = filter_obj.filter_string
            else:
                search_filter = filter_obj

            scope_mapping = {
                LDAPScope.BASE: "BASE",
                LDAPScope.ONE: "LEVEL",
                LDAPScope.SUB: "SUBTREE",
            }

            logger.debug(
                "Executing LDAP search: base_dn=%s, filter=%s",
                base_dn,
                search_filter,
            )

            success = self.connection.search(
                search_base=base_dn,
                search_filter=search_filter,
                search_scope=scope_mapping.get(scope, "SUBTREE"),
                attributes=attributes or ["*"],
            )

            if not success:
                error_msg = f"Search failed: {getattr(self.connection, 'result', 'Unknown error')}"
                logger.error("LDAP search failed: %s", error_msg)
                return ServiceResult.failure(error_msg)

            entries = []
            for entry in self.connection.entries:
                attrs = {}
                for attr_name, attr_value in entry.entry_attributes_as_dict.items():
                    attrs[attr_name] = (
                        attr_value if isinstance(attr_value, list) else [attr_value]
                    )

                entries.append(LDAPEntry(dn=entry.entry_dn, attributes=attrs))

            logger.debug("LDAP search completed: found %d entries", len(entries))
            return ServiceResult.success(entries)

        except LDAPException as e:
            error_msg = f"Search failed: {e}"
            logger.exception("LDAP search exception: %s", error_msg)
            return ServiceResult.failure(error_msg)
        except Exception as e:
            error_msg = f"Unexpected error during search: {e}"
            logger.exception("Unexpected error during LDAP search: %s", error_msg)
            return ServiceResult.failure(error_msg)


class ModifyOperation(LDAPOperation):
    """LDAP modify operation using flext-core patterns."""

    async def execute(self, dn: str, changes: dict[str, Any]) -> ServiceResult[None]:
        """Execute an LDAP modify operation.

        Args:
            dn: Distinguished name of the entry to modify
            changes: Dictionary of changes to apply

        Returns:
            ServiceResult indicating success or error

        """
        try:
            logger.debug("Executing LDAP modify: dn=%s", dn)

            success = self.connection.modify(dn, changes)

            if not success:
                error_msg = f"Modify failed: {getattr(self.connection, 'result', 'Unknown error')}"
                logger.error("LDAP modify failed: %s", error_msg)
                return ServiceResult.failure(error_msg)

            logger.debug("LDAP modify completed: dn=%s", dn)
            return ServiceResult.success(None)

        except LDAPException as e:
            error_msg = f"Modify failed: {e}"
            logger.exception("LDAP modify exception: %s", error_msg)
            return ServiceResult.failure(error_msg)
        except Exception as e:
            error_msg = f"Unexpected error during modify: {e}"
            logger.exception("Unexpected error during LDAP modify: %s", error_msg)
            return ServiceResult.failure(error_msg)


class AddOperation(LDAPOperation):
    """LDAP add operation using flext-core patterns."""

    async def execute(
        self,
        dn: str,
        object_class: list[str],
        attributes: dict[str, Any],
    ) -> ServiceResult[None]:
        """Execute an LDAP add operation.

        Args:
            dn: Distinguished name for the new entry
            object_class: List of object classes for the new entry
            attributes: Dictionary of attributes for the new entry

        Returns:
            ServiceResult indicating success or error

        """
        try:
            logger.debug("Executing LDAP add: dn=%s", dn)

            success = self.connection.add(dn, object_class, attributes)

            if not success:
                error_msg = (
                    f"Add failed: {getattr(self.connection, 'result', 'Unknown error')}"
                )
                logger.error("LDAP add failed: %s", error_msg)
                return ServiceResult.failure(error_msg)

            logger.debug("LDAP add completed: dn=%s", dn)
            return ServiceResult.success(None)

        except LDAPException as e:
            error_msg = f"Add failed: {e}"
            logger.exception("LDAP add exception: %s", error_msg)
            return ServiceResult.failure(error_msg)
        except Exception as e:
            error_msg = f"Unexpected error during add: {e}"
            logger.exception("Unexpected error during LDAP add: %s", error_msg)
            return ServiceResult.failure(error_msg)


class DeleteOperation(LDAPOperation):
    """LDAP delete operation using flext-core patterns."""

    async def execute(self, dn: str) -> ServiceResult[None]:
        """Execute an LDAP delete operation.

        Args:
            dn: Distinguished name of the entry to delete

        Returns:
            ServiceResult indicating success or error

        """
        try:
            logger.debug("Executing LDAP delete: dn=%s", dn)

            success = self.connection.delete(dn)

            if not success:
                error_msg = f"Delete failed: {getattr(self.connection, 'result', 'Unknown error')}"
                logger.error("LDAP delete failed: %s", error_msg)
                return ServiceResult.failure(error_msg)

            logger.debug("LDAP delete completed: dn=%s", dn)
            return ServiceResult.success(None)

        except LDAPException as e:
            error_msg = f"Delete failed: {e}"
            logger.exception("LDAP delete exception: %s", error_msg)
            return ServiceResult.failure(error_msg)
        except Exception as e:
            error_msg = f"Unexpected error during delete: {e}"
            logger.exception("Unexpected error during LDAP delete: %s", error_msg)
            return ServiceResult.failure(error_msg)


__all__ = [
    "AddOperation",
    "DeleteOperation",
    "LDAPOperation",
    "ModifyOperation",
    "SearchOperation",
]
