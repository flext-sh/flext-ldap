"""Adapter host — lazily owns the shared ldap3 adapter for LDAP services.

Service mixins inherit this host to obtain the adapter behind the
``p.Ldap.LdapAdapter`` contract; the concrete ldap3 implementation stays in
``adapters/ldap3.py`` (the sole ldap3 owner per AGENTS.md §2.7).

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldap import s, t, u
from flext_ldap.adapters.ldap3 import FlextLdapLdap3Adapter


class FlextLdapAdapterHost[
    TResult: t.JsonPayload | t.SequenceOf[t.JsonPayload] = t.JsonPayload
    | t.SequenceOf[t.JsonPayload],
](s[TResult]):
    """Own the shared ldap3 adapter behind the ``p.Ldap.LdapAdapter`` contract.

    Service mixins inherit this host to obtain the lazily constructed adapter
    via DIP: callers depend on the protocol while this module (the sole ldap3
    owner per AGENTS.md §2.7) constructs the concrete implementation.
    """

    _adapter: FlextLdapLdap3Adapter | None = u.PrivateAttr(
        default_factory=lambda: None,
    )

    def _ensure_adapter(self) -> FlextLdapLdap3Adapter:
        """Return the shared ldap3 adapter for this service instance.

        The concrete type is the module-private construction boundary; callers
        keep depending on the ``p.Ldap.LdapAdapter`` protocol through the
        service-level signatures that hand the adapter out.
        """
        if self._adapter is None:
            self._adapter = FlextLdapLdap3Adapter()
        return self._adapter

    @property
    def is_connected(self) -> bool:
        """The ``True`` when the shared adapter has an active bind."""
        adapter = self._adapter
        if adapter is None:
            return False
        connected: bool = adapter.is_connected
        return connected
