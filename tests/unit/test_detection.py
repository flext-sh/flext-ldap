"""Behavioral unit tests for ``flext_ldap.services.detection``.

**Module under test:** ``flext_ldap.services.detection.FlextLdapServerDetector``.

**Contract exercised (public behavior only):**
- ``execute()`` returns a failed ``r`` when the ``connection`` keyword is
  missing or is not an ldap3-compatible connection.
- ``detect_from_connection()`` returns the resolved server-type string for a
  bound connection and propagates a failure when the rootDSE cannot be read.
- The public rootDSE helpers surfaced through ``u.Ldap`` classify vendor
  metadata and extract attribute values.

Connections are the only genuine external boundary; they are represented by
structural test doubles that satisfy the ``p.Ldap`` connection protocols. No
private attributes, internal collaborators, or implementation details of the
detector are touched.

Note: ``execute()`` success returns an ``m.Ldap.OperationResult`` model, but its
signature types ``**kwargs`` as scalars (``str | float | bool | None``), so a
connection cannot be passed through it without a typing violation. The success
model state is therefore asserted through the type-clean public method
``detect_from_connection`` and cannot be exercised via ``execute``.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from flext_tests import tm

from flext_ldap.services.detection import FlextLdapServerDetector
from tests import c, p, u

if TYPE_CHECKING:
    from collections.abc import Callable

    from tests import t

pytestmark = pytest.mark.unit


class TestsFlextLdapDetection:
    """Behavioral contract of ``FlextLdapServerDetector`` and its rootDSE helpers."""

    class _RootDseEntryDouble:
        """Structural double for one ldap3 rootDSE entry (external boundary)."""

        def __init__(
            self,
            attributes: t.MappingKV[str, t.Ldap.Ldap3EntryValue],
        ) -> None:
            self._attributes = attributes

        @property
        def entry_attributes_as_dict(
            self,
        ) -> t.MappingKV[str, t.Ldap.Ldap3EntryValue]:
            return self._attributes

    class _ConnectionDouble:
        """Structural double for a bound ldap3 rootDSE connection (boundary)."""

        def __init__(
            self,
            *,
            entries: t.SequenceOf[p.Ldap.RootDseEntry | t.Ldap.Ldap3EntryValue],
            searchable: bool = True,
            search_succeeds: bool = True,
        ) -> None:
            self._entries = entries
            self._searchable = searchable
            self._search_succeeds = search_succeeds

        @property
        def search(self) -> Callable[..., bool | t.JsonValue | None] | None:
            if not self._searchable:
                return None
            succeeds = self._search_succeeds
            return lambda **_kwargs: succeeds

        @property
        def result(self) -> t.JsonMapping | None:
            return {"description": "operation failed"}

        @property
        def entries(
            self,
        ) -> t.SequenceOf[p.Ldap.RootDseEntry | t.Ldap.Ldap3EntryValue]:
            return self._entries

    @staticmethod
    def _connection_for(
        vendor_name: str | None,
        vendor_version: str | None,
    ) -> p.Ldap.RootDseConnection:
        """Build a bound connection double advertising the given vendor metadata."""
        attributes: dict[str, t.Ldap.Ldap3EntryValue] = {}
        if vendor_name is not None:
            attributes[c.Ldap.RootDseAttribute.VENDOR_NAME] = [vendor_name]
        if vendor_version is not None:
            attributes[c.Ldap.RootDseAttribute.VENDOR_VERSION] = [vendor_version]
        entry = TestsFlextLdapDetection._RootDseEntryDouble(attributes)
        return TestsFlextLdapDetection._ConnectionDouble(entries=[entry])

    @pytest.mark.parametrize(
        ("kwargs", "expect_failure", "error_substring"),
        c.Ldap.Tests.DETECTION_EXECUTE_SCENARIOS,
    )
    def test_execute_reports_failure_for_invalid_connection_argument(
        self,
        kwargs: t.MappingKV[str, bool | float | str | None] | None,
        *,
        expect_failure: bool,
        error_substring: str,
    ) -> None:
        """execute() fails with a descriptive error for missing/invalid connection."""
        detector = FlextLdapServerDetector()

        result = detector.execute() if kwargs is None else detector.execute(**kwargs)

        tm.that(result.failure, eq=expect_failure)
        tm.that(result.success, eq=not expect_failure)
        tm.that(str(result.error), has=error_substring)

    @pytest.mark.parametrize(
        ("attrs", "key", "expected"),
        c.Ldap.Tests.DETECTION_GET_FIRST_VALUE_SCENARIOS,
    )
    def test_get_first_attribute_value_returns_first_truthy_value(
        self,
        attrs: t.MappingKV[str, t.StrSequence],
        key: str,
        expected: str | None,
    ) -> None:
        """The rootDSE helper returns the first non-empty value, else ``None``."""
        value = u.Ldap.get_first_attribute_value(dict(attrs), key)

        tm.that(value, eq=expected)

    @pytest.mark.parametrize(
        ("vendor_name", "vendor_version", "supported_controls", "expected"),
        c.Ldap.Tests.DETECTION_FROM_ATTRIBUTES_SCENARIOS,
    )
    def test_detect_server_type_classifies_vendor_metadata(
        self,
        vendor_name: str | None,
        vendor_version: str | None,
        supported_controls: t.StrSequence,
        expected: str,
    ) -> None:
        """Vendor metadata resolves to the canonical server-type identifier."""
        _ = supported_controls

        result = u.Ldap.detect_server_type(
            vendor_name=vendor_name,
            vendor_version=vendor_version,
            naming_contexts=[c.Ldap.EXAMPLE_BASE_DN],
            supported_extensions=[],
        )

        tm.that(result, eq=expected)

    @pytest.mark.parametrize(
        ("vendor_name", "vendor_version", "expected"),
        [
            ("Oracle Corporation", "12.2.1.4.0", "oid"),
            ("Oracle Unified Directory", "12.2.1.4.0", "oud"),
            ("OpenLDAP", "2.4.57", "openldap"),
            ("389 Project", "2.0.0", "ds389"),
            (None, None, "rfc"),
        ],
    )
    def test_detect_from_connection_returns_detected_server_type(
        self,
        vendor_name: str | None,
        vendor_version: str | None,
        expected: str,
    ) -> None:
        """A bound connection yields the server type read from its rootDSE."""
        detector = FlextLdapServerDetector()
        connection = self._connection_for(vendor_name, vendor_version)

        result = detector.detect_from_connection(connection)

        tm.that(result.success, eq=True)
        tm.that(result.unwrap(), eq=expected)

    def test_detect_from_connection_is_idempotent(self) -> None:
        """Detecting twice on the same connection yields the same server type."""
        detector = FlextLdapServerDetector()
        connection = self._connection_for("Oracle Unified Directory", "12.2.1.4.0")

        first = detector.detect_from_connection(connection)
        second = detector.detect_from_connection(connection)

        tm.that(first.success, eq=True)
        tm.that(first.unwrap(), eq=second.unwrap())

    @pytest.mark.parametrize(
        ("searchable", "search_succeeds", "entries", "error_substring"),
        [
            (False, True, [], "search unavailable"),
            (True, False, [], "rootDSE query"),
            (True, True, [], "no entries"),
        ],
    )
    def test_detect_from_connection_propagates_rootdse_failure(
        self,
        *,
        searchable: bool,
        search_succeeds: bool,
        entries: list[p.Ldap.RootDseEntry | t.Ldap.Ldap3EntryValue],
        error_substring: str,
    ) -> None:
        """A failed rootDSE read surfaces as a failed detection result."""
        detector = FlextLdapServerDetector()
        connection = TestsFlextLdapDetection._ConnectionDouble(
            entries=entries,
            searchable=searchable,
            search_succeeds=search_succeeds,
        )

        result = detector.detect_from_connection(connection)

        tm.that(result.failure, eq=True)
        tm.that(str(result.error), has=error_substring)
