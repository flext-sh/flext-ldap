"""Adapter host — lazily owns the shared ldap3 adapter for LDAP services.

Service mixins inherit this host to obtain the adapter behind the
``p.Ldap.LdapAdapter`` contract; the concrete ldap3 implementation stays in
``adapters/ldap3.py`` (the sole ldap3 owner per AGENTS.md §2.7).

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldap import p, s, t, u
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

    _adapter: p.Ldap.LdapAdapter | None = u.PrivateAttr(default_factory=lambda: None)

    def _ensure_adapter(self) -> p.Ldap.LdapAdapter:
        """Return the shared ldap3 adapter for this service instance."""
        if self._adapter is None:
            adapter: p.Ldap.LdapAdapter = FlextLdapLdap3Adapter()
            self._adapter = adapter
            return adapter
        return self._adapter

    @property
    def is_connected(self) -> bool:
        """The ``True`` when the shared adapter has an active bind."""
        adapter = self._adapter
        if adapter is None:
            return False
        connected: bool = adapter.is_connected
        return connected
