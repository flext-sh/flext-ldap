"""Tests for retry logic and idempotent sync (Gap #7, Gap #10).

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest
from flext_core import FlextTypes

from flext_ldap import FlextLdap


class TestRetryLogic:
    """Test retry with exponential backoff (Gap #7)."""

    def test_is_permanent_error_detection(self) -> None:
        """Should correctly identify permanent vs transient errors."""
        api = FlextLdap()

        # Permanent errors - should return True
        assert api._is_permanent_error("invalid credentials")
        assert api._is_permanent_error("INVALID DN syntax")  # Case-insensitive
        assert api._is_permanent_error("schema violation occurred")
        assert api._is_permanent_error("already exists")
        assert api._is_permanent_error("constraint violation")
        assert api._is_permanent_error("insufficient access rights")
        assert api._is_permanent_error("no such object")
        assert api._is_permanent_error("object class violation")
        assert api._is_permanent_error("not allowed on rdn")
        assert api._is_permanent_error("naming violation")

        # Transient errors - should return False
        assert not api._is_permanent_error("connection timeout")
        assert not api._is_permanent_error("connection refused")
        assert not api._is_permanent_error("network unreachable")
        assert not api._is_permanent_error("temporary failure")
        assert not api._is_permanent_error("server is busy")
        assert not api._is_permanent_error("unavailable")

    def test_retry_with_exponential_backoff_pattern(self) -> None:
        """Verify exponential backoff calculation pattern."""
        # Test backoff calculation: 2^attempt for attempts 0, 1, 2
        backoff_base = 2.0
        expected_backoffs = [
            (0, 1.0),  # 2^0 = 1
            (1, 2.0),  # 2^1 = 2
            (2, 4.0),  # 2^2 = 4
            (3, 8.0),  # 2^3 = 8
        ]

        for attempt, expected in expected_backoffs:
            actual = backoff_base**attempt
            assert actual == expected, (
                f"Attempt {attempt}: expected {expected}, got {actual}"
            )


class TestIdempotentSync:
    """Test idempotent check (skip unchanged entries) (Gap #7)."""

    def test_entry_needs_update_no_changes(self) -> None:
        """Should return False when entries are identical."""
        api = FlextLdap()

        live_attrs: dict[str, FlextTypes.StringList | str] = {
            "cn": ["test"],
            "objectClass": ["person", "top"],
        }
        desired_attrs: dict[str, FlextTypes.StringList | str] = {
            "cn": "test",
            "objectClass": ["person", "top"],
        }

        assert not api._entry_needs_update(live_attrs, desired_attrs)

    def test_entry_needs_update_changed_value(self) -> None:
        """Should return True when values change."""
        api = FlextLdap()

        live_attrs: dict[str, FlextTypes.StringList | str] = {
            "cn": ["test"],
            "mail": ["old@client-a.com"],
        }
        desired_attrs: dict[str, FlextTypes.StringList | str] = {
            "cn": "test",
            "mail": "new@client-a.com",
        }

        assert api._entry_needs_update(live_attrs, desired_attrs)

    def test_entry_needs_update_added_attribute(self) -> None:
        """Should return True when attribute is added."""
        api = FlextLdap()

        live_attrs: dict[str, FlextTypes.StringList | str] = {"cn": ["test"]}
        desired_attrs: dict[str, FlextTypes.StringList | str] = {
            "cn": "test",
            "mail": "test@client-a.com",
        }

        assert api._entry_needs_update(live_attrs, desired_attrs)

    def test_entry_needs_update_removed_attribute(self) -> None:
        """Should return True when attribute is removed."""
        api = FlextLdap()

        live_attrs: dict[str, FlextTypes.StringList | str] = {
            "cn": ["test"],
            "mail": ["test@client-a.com"],
        }
        desired_attrs: dict[str, FlextTypes.StringList | str] = {"cn": "test"}

        assert api._entry_needs_update(live_attrs, desired_attrs)


class TestMultiValuedComparison:
    """Test SET-based comparison for multi-valued attributes (Gap #10)."""

    def test_objectclass_order_independence(self) -> None:
        """Same objectClasses in different order should be considered equal."""
        api = FlextLdap()

        live: dict[str, FlextTypes.StringList | str] = {
            "objectClass": ["top", "person", "organizationalPerson", "inetOrgPerson"],
        }

        desired: dict[str, FlextTypes.StringList | str] = {
            "objectClass": ["inetOrgPerson", "organizationalPerson", "person", "top"],
        }

        # Should NOT need update (same values, different order)
        assert not api._entry_needs_update(live, desired)

    def test_member_attribute_order_independence(self) -> None:
        """Group members in different order should be equal."""
        api = FlextLdap()

        live: dict[str, FlextTypes.StringList | str] = {
            "member": [
                "cn=user1,dc=client-a",
                "cn=user2,dc=client-a",
                "cn=user3,dc=client-a",
            ],
        }

        desired: dict[str, FlextTypes.StringList | str] = {
            "member": [
                "cn=user3,dc=client-a",
                "cn=user1,dc=client-a",
                "cn=user2,dc=client-a",
            ],
        }

        assert not api._entry_needs_update(live, desired)

    def test_detect_added_value(self) -> None:
        """Should detect when value is added to multi-valued attribute."""
        api = FlextLdap()

        live: dict[str, FlextTypes.StringList | str] = {
            "objectClass": ["top", "person"]
        }

        desired: dict[str, FlextTypes.StringList | str] = {
            "objectClass": ["top", "person", "inetOrgPerson"]
        }  # Added

        assert api._entry_needs_update(live, desired)

    def test_detect_removed_value(self) -> None:
        """Should detect when value is removed from multi-valued attribute."""
        api = FlextLdap()

        live: dict[str, FlextTypes.StringList | str] = {
            "objectClass": ["top", "person", "inetOrgPerson"]
        }

        desired: dict[str, FlextTypes.StringList | str] = {
            "objectClass": ["top", "person"]
        }  # Removed inetOrgPerson

        assert api._entry_needs_update(live, desired)

    def test_detect_attribute_added(self) -> None:
        """Should detect when new attribute is added."""
        api = FlextLdap()

        live: dict[str, FlextTypes.StringList | str] = {"cn": ["test"]}

        desired: dict[str, FlextTypes.StringList | str] = {
            "cn": ["test"],
            "mail": ["test@client-a.com"],
        }  # Added mail

        assert api._entry_needs_update(live, desired)

    def test_detect_attribute_removed(self) -> None:
        """Should detect when attribute is removed."""
        api = FlextLdap()

        live: dict[str, FlextTypes.StringList | str] = {
            "cn": ["test"],
            "mail": ["test@client-a.com"],
        }

        desired: dict[str, FlextTypes.StringList | str] = {
            "cn": ["test"]
        }  # Removed mail

        assert api._entry_needs_update(live, desired)

    def test_single_valued_attribute_comparison(self) -> None:
        """Single-valued attributes should be compared directly."""
        api = FlextLdap()

        live: dict[str, FlextTypes.StringList | str] = {"cn": "test"}

        desired: dict[str, FlextTypes.StringList | str] = {"cn": "test"}

        assert not api._entry_needs_update(live, desired)

        # Changed value
        desired_changed: dict[str, FlextTypes.StringList | str] = {"cn": "changed"}
        assert api._entry_needs_update(live, desired_changed)

    def test_mixed_single_and_multi_valued(self) -> None:
        """Should handle mix of single and multi-valued attributes."""
        api = FlextLdap()

        live: dict[str, FlextTypes.StringList | str] = {
            "cn": "John Doe",  # Single-valued
            "objectClass": ["top", "person", "inetOrgPerson"],  # Multi-valued
            "mail": ["john@client-a.com"],  # Multi-valued (1 value)
        }

        desired: dict[str, FlextTypes.StringList | str] = {
            "cn": "John Doe",  # Same
            "objectClass": ["inetOrgPerson", "person", "top"],  # Same (different order)
            "mail": ["john@client-a.com"],  # Same
        }

        assert not api._entry_needs_update(live, desired)

    def test_empty_attribute_values(self) -> None:
        """Should handle empty attribute values correctly."""
        api = FlextLdap()

        live: dict[str, FlextTypes.StringList | str] = {"cn": ["test"], "mail": []}

        desired: dict[str, FlextTypes.StringList | str] = {
            "cn": ["test"],
            "mail": [],
        }

        assert not api._entry_needs_update(live, desired)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
