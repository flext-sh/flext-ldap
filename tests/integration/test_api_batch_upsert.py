"""Integration tests for FlextLdap batch_upsert method.

Tests batch_upsert functionality with real LDAP operations.
All tests use real LDAP server, no mocks.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from flext_ldif.models import FlextLdifModels

from flext_ldap import FlextLdap
from tests.fixtures.constants import RFC

pytestmark = pytest.mark.integration


class TestFlextLdapBatchUpsert:
    """Tests for FlextLdap batch_upsert method."""

    def test_batch_upsert_with_multiple_entries(
        self,
        ldap_client: FlextLdap,
    ) -> None:
        """Test batch_upsert with multiple entries (covers line 511 in api.py)."""
        # Cleanup first
        test_dns = [
            f"cn=testbatch1,{RFC.DEFAULT_BASE_DN}",
            f"cn=testbatch2,{RFC.DEFAULT_BASE_DN}",
            f"cn=testbatch3,{RFC.DEFAULT_BASE_DN}",
        ]
        for dn in test_dns:
            _ = ldap_client.delete(dn)

        # Create multiple entries
        entries = [
            FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(value=test_dns[0]),
                attributes=FlextLdifModels.LdifAttributes(
                    attributes={
                        "cn": ["testbatch1"],
                        "objectClass": ["top", "person"],
                        "sn": ["Batch1"],
                    },
                ),
            ),
            FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(value=test_dns[1]),
                attributes=FlextLdifModels.LdifAttributes(
                    attributes={
                        "cn": ["testbatch2"],
                        "objectClass": ["top", "person"],
                        "sn": ["Batch2"],
                    },
                ),
            ),
            FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(value=test_dns[2]),
                attributes=FlextLdifModels.LdifAttributes(
                    attributes={
                        "cn": ["testbatch3"],
                        "objectClass": ["top", "person"],
                        "sn": ["Batch3"],
                    },
                ),
            ),
        ]

        # Test batch_upsert through API (covers line 511)
        result = ldap_client.batch_upsert(entries)
        assert result.is_success
        stats = result.unwrap()
        assert stats["synced"] >= 0
        assert stats["failed"] == 0
        assert stats["skipped"] >= 0
        assert stats["synced"] + stats["skipped"] == 3

        # Cleanup
        for dn in test_dns:
            _ = ldap_client.delete(dn)

    def test_batch_upsert_with_progress_callback(
        self,
        ldap_client: FlextLdap,
    ) -> None:
        """Test batch_upsert with progress callback."""
        # Cleanup first
        test_dns = [
            f"cn=testprogress1,{RFC.DEFAULT_BASE_DN}",
            f"cn=testprogress2,{RFC.DEFAULT_BASE_DN}",
        ]
        for dn in test_dns:
            _ = ldap_client.delete(dn)

        # Create entries
        entries = [
            FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(value=test_dns[0]),
                attributes=FlextLdifModels.LdifAttributes(
                    attributes={
                        "cn": ["testprogress1"],
                        "objectClass": ["top", "person"],
                        "sn": ["Progress1"],
                    },
                ),
            ),
            FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(value=test_dns[1]),
                attributes=FlextLdifModels.LdifAttributes(
                    attributes={
                        "cn": ["testprogress2"],
                        "objectClass": ["top", "person"],
                        "sn": ["Progress2"],
                    },
                ),
            ),
        ]

        # Track progress
        progress_calls: list[tuple[int, int, str, dict[str, int]]] = []

        def progress_callback(
            idx: int, total: int, dn: str, stats: dict[str, int]
        ) -> None:
            """Track progress calls."""
            progress_calls.append((idx, total, dn, stats))

        # Test batch_upsert with progress callback
        result = ldap_client.batch_upsert(entries, progress_callback=progress_callback)
        assert result.is_success

        # Verify progress callback was called
        assert len(progress_calls) == 2
        assert progress_calls[0][0] == 1
        assert progress_calls[0][1] == 2
        assert progress_calls[1][0] == 2
        assert progress_calls[1][1] == 2

        # Cleanup
        for dn in test_dns:
            _ = ldap_client.delete(dn)
