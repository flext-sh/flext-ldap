"""LDAP3 adapter — type-safe wrappers for ldap3 Connection methods.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_ldap import c, m, p, t, u

if TYPE_CHECKING:
    from collections.abc import Callable


class FlextLdapLdap3Wrappers:
    """Type-safe static wrappers for untyped ldap3 Connection methods."""

    @staticmethod
    def value_to_str_list(
        value: t.Ldap.Ldap3EntryValue | t.JsonValue | t.StrSequence,
    ) -> t.MutableSequenceOf[str]:
        """Convert an ldap3 attribute payload through the canonical utility.

        Returns:
            The resulting ``t.MutableSequenceOf[str]``.
        """
        return list(u.Ldap.ldap3_value_to_strings(value))

    @staticmethod
    def _ldap3_method(
        connection: p.Ldap.Ldap3Connection,
        method_name: str,
    ) -> Callable[..., bool]:
        """Get a typed callable for an untyped ldap3 Connection method.

        ldap3 library methods return Unknown types which cause pyright errors.
        This helper extracts the method via getattr and wraps the return as bool.

        Returns:
            The resulting ``Callable[..., bool]``.
        """
        method: Callable[..., bool] = getattr(connection, method_name)
        return method

    @staticmethod
    def add(
        connection: p.Ldap.Ldap3Connection,
        dn: str,
        object_class: t.StrSequence | str | None,
        attributes: t.MappingKV[str, t.StrSequence],
    ) -> bool:
        """Type-safe wrapper for untyped ldap3 Connection.add().

        Attribute values are forwarded verbatim: ldap3 accepts sequence
        values natively and the directory server enforces each attribute's
        single-valued syntax. Collapsing sequences to their first element
        silently dropped entry data — an ``objectClass`` chain of
        ``["top", "inetOrgPerson", "person"]`` reached the wire as
        ``"top"`` and the add failed server-side schema validation with
        ``objectClassViolation``.

        Returns:
            The resulting ``bool``.
        """
        add_fn = FlextLdapLdap3Wrappers._ldap3_method(connection, "add")
        return add_fn(dn, object_class, dict(attributes))

    @staticmethod
    def delete(connection: p.Ldap.Ldap3Connection, dn: str) -> bool:
        """Type-safe wrapper for untyped ldap3 Connection.delete().

        Returns:
            The resulting ``bool``.
        """
        delete_fn = FlextLdapLdap3Wrappers._ldap3_method(connection, "delete")
        return delete_fn(dn)

    @staticmethod
    def bound(connection: p.Ldap.Ldap3Connection) -> bool:
        """Safely read ldap3 bound state from dynamic connection objects.

        Returns:
            The resulting ``bool``.
        """
        bound_state: bool = getattr(connection, "bound", False)
        return bound_state

    @staticmethod
    def bind(connection: p.Ldap.Ldap3Connection) -> bool:
        """Bind only after the adapter owns the connection for cleanup.

        Returns:
            The resulting ``bool``.
        """
        bind_fn = FlextLdapLdap3Wrappers._ldap3_method(connection, "bind")
        return bind_fn()

    @staticmethod
    def modify(
        connection: p.Ldap.Ldap3Connection,
        dn: str,
        changes: t.Ldap.OperationChanges,
    ) -> bool:
        """Type-safe wrapper for untyped ldap3 Connection.modify().

        Returns:
            The resulting ``bool``.
        """
        modify_fn = FlextLdapLdap3Wrappers._ldap3_method(connection, "modify")
        return modify_fn(dn, changes)

    @staticmethod
    def search(connection: p.Ldap.Ldap3Connection, params: m.Ldap.SearchParams) -> bool:
        """Safely invoke ldap3 search on dynamic connection objects.

        Returns:
            The resulting ``bool``.
        """
        scope_map: t.MappingKV[int, c.Ldap.Ldap3SearchScope] = {
            c.Ldap.SearchScopeValue.BASE: c.Ldap.Ldap3SearchScope.BASE,
            c.Ldap.SearchScopeValue.LEVEL: c.Ldap.Ldap3SearchScope.LEVEL,
            c.Ldap.SearchScopeValue.SUBTREE: c.Ldap.Ldap3SearchScope.SUBTREE,
        }
        search_fn = FlextLdapLdap3Wrappers._ldap3_method(connection, "search")
        return search_fn(
            search_base=params.base_dn,
            search_filter=params.filter_str,
            search_scope=scope_map[params.ldap_scope],
            attributes=list(params.search_attributes),
            size_limit=params.size_limit,
            time_limit=params.time_limit,
        )

    @staticmethod
    def start_tls(connection: p.Ldap.Ldap3Connection) -> bool:
        """Safely invoke STARTTLS from dynamic ldap3 connection objects.

        Returns:
            The resulting ``bool``.

        Raises:
            AttributeError: If start_tls method not available on connection object.
        """
        start_tls_fn = getattr(connection, "start_tls", None)
        if start_tls_fn is None:
            msg = "start_tls method not available on connection object"
            raise AttributeError(msg)
        result: bool = start_tls_fn()
        return result

    @staticmethod
    def unbind(connection: p.Ldap.Ldap3Connection) -> bool:
        """Type-safe wrapper for untyped ldap3 p.Ldap.Ldap3Connection.unbind().

        Returns:
            The resulting ``bool``.
        """
        unbind_fn = FlextLdapLdap3Wrappers._ldap3_method(connection, "unbind")
        return unbind_fn()


__all__: list[str] = ["FlextLdapLdap3Wrappers"]
