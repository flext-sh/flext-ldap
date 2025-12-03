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
from flext_ldap.models import FlextLdapModels

from ..fixtures.constants import RFC
from ..helpers.operation_helpers import TestOperationHelpers

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
        TestOperationHelpers.assert_result_success(result)
        stats = result.unwrap()
        # Validate actual content: batch stats should be consistent
        assert stats.synced >= 0
        assert stats.failed == 0
        assert stats.skipped >= 0
        # LdapBatchStats has synced, failed, skipped (no total_entries field)
        assert stats.synced + stats.skipped == 3, (
            f"Expected synced+skipped=3, got synced={stats.synced}, skipped={stats.skipped}"
        )

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
        progress_calls: list[tuple[int, int, str, FlextLdapModels.LdapBatchStats]] = []

        def progress_callback(
            idx: int,
            total: int,
            dn: str,
            stats: FlextLdapModels.LdapBatchStats,
        ) -> None:
            """Track progress calls."""
            progress_calls.append((idx, total, dn, stats))

        # Test batch_upsert with progress callback
        result = ldap_client.batch_upsert(entries, progress_callback=progress_callback)
        TestOperationHelpers.assert_result_success(result)
        stats = result.unwrap()
        # Validate actual content: batch stats should be consistent
        assert stats.synced >= 0
        assert stats.failed == 0
        assert stats.skipped >= 0
        # LdapBatchStats has synced, failed, skipped (no total_entries field)
        assert stats.synced + stats.skipped == 2, (
            f"Expected synced+skipped=2, got synced={stats.synced}, skipped={stats.skipped}"
        )

        # Verify progress callback was called
        assert len(progress_calls) == 2
        assert progress_calls[0][0] == 1
        assert progress_calls[0][1] == 2
        assert progress_calls[1][0] == 2
        assert progress_calls[1][1] == 2
        # Validate callback stats
        for idx, (current, total, dn, callback_stats) in enumerate(progress_calls):
            assert current == idx + 1, (
                f"Callback {idx}: expected current={idx + 1}, got {current}"
            )
            assert total == 2, f"Callback {idx}: expected total=2, got {total}"
            assert isinstance(dn, str), f"Callback {idx}: DN should be string"
            # Validate callback stats structure
            assert callback_stats.synced >= 0, f"Callback {idx}: synced should be >= 0"
            assert callback_stats.failed >= 0, f"Callback {idx}: failed should be >= 0"
            assert callback_stats.skipped >= 0, (
                f"Callback {idx}: skipped should be >= 0"
            )

        # Cleanup
        for dn in test_dns:
            _ = ldap_client.delete(dn)
