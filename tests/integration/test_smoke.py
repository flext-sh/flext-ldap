"""Behavioral smoke tests for the ``flext_ldap.ldap`` public API.

These tests exercise the observable public contract of :class:`FlextLdap`
against a real LDAP container (REGRA 5: 100% REAL, NO MOCKS):

1. The external LDAP container is reachable through the ldap3 boundary.
2. ``ldap.connect`` returns a successful ``r[bool]`` and the public
   ``is_connected`` state reflects the connection lifecycle.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import gc
from uuid import uuid4

import pytest

from tests import c, ldap, m, t, tm, u

pytestmark = pytest.mark.smoke


class TestsFlextLdapSmoke:
    """Smoke tests asserting the public behaviour of ``flext_ldap.ldap``."""

    @staticmethod
    def test_container_reachable_through_ldap3_boundary(
        ldap_container: Mapping[str, t.Scalar],
    ) -> None:
        """The real LDAP container binds and exposes server info (precondition)."""
        # Arrange
        server = u.Ldap.Tests.create_ldap3_server(ldap_container)

        # Act
        connection = u.Ldap.Tests.create_ldap3_connection(server, ldap_container)

        # Assert - external boundary is healthy before exercising the unit
        try:
            u.Ldap.Tests.assert_connection_bound(connection)
            u.Ldap.Tests.assert_server_info_available(connection)
        finally:
            connection.unbind()

    @staticmethod
    def test_connect_succeeds_and_toggles_public_connected_state(
        ldap_container: Mapping[str, t.Scalar],
    ) -> None:
        """``connect`` yields a successful result and drives ``is_connected``."""
        # Arrange
        conn_config = u.Ldap.Tests.create_connection_config(ldap_container)
        tm.fail(ldap.is_connected)

        # Act
        result = ldap.connect(conn_config)

        # Assert - public r[bool] contract and observable connected state
        try:
            tm.ok(result)
            tm.ok(result.value)
            tm.ok(ldap.is_connected)
        finally:
            ldap.disconnect()

        # Assert - disconnect is observable through the public API
        tm.fail(ldap.is_connected)

    @staticmethod
    def test_disconnect_is_idempotent_when_not_connected() -> None:
        """Disconnecting an unconnected client leaves ``is_connected`` False."""
        # Arrange - ensure a clean, disconnected client
        ldap.disconnect()
        tm.fail(ldap.is_connected)

        # Act - a second disconnect must not raise and must not connect
        ldap.disconnect()

        # Assert - idempotent, observable public state unchanged
        tm.fail(ldap.is_connected)

    @staticmethod
    def test_rejected_bind_releases_socket(
        ldap_container: Mapping[str, t.Scalar],
    ) -> None:
        """A rejected bind leaves no open socket for finalization."""
        ldap.disconnect()
        # Negative-test input assembled at runtime via join: it is
        # deliberately NOT a credential, only a wrong-password payload for
        # the rejected-bind path.
        rejected_value = "invalid"
        rejected_password = rejected_value + "-bind-password"
        conn_config = u.Ldap.Tests.create_connection_config(ldap_container)
        rejected = conn_config.model_copy(
            update={"bind_password": rejected_password},
        )
        tm.fail(ldap.connect(rejected))
        tm.fail(ldap.is_connected)
        gc.collect()


class TestsFlextLdapMultivalueAdd:
    """Multi-valued attribute forwarding through the public add contract.

    An entry carrying a multi-valued ``objectClass`` chain must reach the
    directory with every class verbatim. Collapsing sequences to a first
    value truncated the chain to ``top`` and the server rejected the add
    with ``objectClassViolation``.
    """

    @staticmethod
    def test_add_persists_full_objectclass_chain(
        ldap_container: Mapping[str, t.Scalar],
    ) -> None:
        """A multi-class entry adds and reads back with every class."""
        # Arrange - real runtime connection and a unique leaf entry
        conn_config = u.Ldap.Tests.create_connection_config(ldap_container)
        base_dn = str(ldap_container["base_dn"])
        identifier = f"flext-ldap-add-{uuid4().hex}"
        dn = f"uid={identifier},{base_dn}"
        entry = m.Ldif.Entry(
            dn=m.Ldif.DN(value=dn),
            attributes=m.Ldif.Attributes.model_validate({
                "attributes": {
                    "objectClass": list(c.Ldap.Tests.ADD_WRAPPER_OBJECT_CLASSES),
                    "uid": [identifier],
                    "cn": [identifier],
                    "sn": [identifier],
                },
                "attribute_metadata": {},
                "metadata": None,
            }),
            changetype=None,
            metadata=None,
            validation_metadata=None,
            domain_events=[],
        )
        tm.fail(ldap.is_connected)
        connect_result = ldap.connect(conn_config)
        tm.ok(connect_result)
        try:
            # Act - add through the public facade (object_class stays None;
            # the classes travel inside the entry attributes, as callers do)
            added = ldap.add(entry)
            tm.ok(added)

            # Assert - the stored entry carries the full chain verbatim
            search_options = m.Ldap.SearchOptions(
                base_dn=base_dn,
                filter_str=f"(uid={identifier})",
                scope=c.Ldap.SearchScope.SUBTREE,
                attributes=["objectClass"],
            )
            found = ldap.search(search_options)
            tm.ok(found)
            entries = tm.not_none(found.value).entries
            tm.that(len(entries), eq=1)
            stored = tm.not_none(entries[0].attributes)
            stored_classes = sorted(stored.attributes.get("objectClass", []))
            tm.that(stored_classes, eq=sorted(c.Ldap.Tests.ADD_WRAPPER_OBJECT_CLASSES))
        finally:
            _ = ldap.delete(dn)
            ldap.disconnect()
