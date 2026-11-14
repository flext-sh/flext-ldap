"""Behavioral unit tests for the rootDSE server-type classification.

**Contract exercised (public behavior only):**
- ``u.Ldap.detect_from_root_dse()`` classifies the rootDSE attributes the
  adapter read on connect into the canonical server-type identifier.
- The public rootDSE helpers surfaced through ``u.Ldap`` classify vendor
  metadata and extract attribute values.

The rootDSE itself is read by the adapter on the real connection; its
end-to-end detection is exercised by the integration connect tests.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

import pytest

from tests import c, tm, u

pytestmark = pytest.mark.unit


class TestsFlextLdapDetection:
    """Behavioral contract of the rootDSE classification helpers."""

    @pytest.mark.parametrize(
        ("attrs", "key", "expected"),
        c.Ldap.Tests.DETECTION_GET_FIRST_VALUE_SCENARIOS,
    )
    @staticmethod
    def test_get_first_attribute_value_returns_first_truthy_value(
        attrs: Mapping[str, Sequence[str]],
        key: str,
        expected: str | None,
    ) -> None:
        """The rootDSE helper returns the first non-empty value, else ``None``."""
        value = u.Ldap.resolve_first_attribute_value(dict(attrs), key)

        tm.that(value, eq=expected)

    @pytest.mark.parametrize(
        ("vendor_name", "vendor_version", "supported_controls", "expected"),
        c.Ldap.Tests.DETECTION_FROM_ATTRIBUTES_SCENARIOS,
    )
    @staticmethod
    def test_detect_server_type_classifies_vendor_metadata(
        vendor_name: str | None,
        vendor_version: str | None,
        supported_controls: Sequence[str],
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
    @staticmethod
    def test_detect_from_root_dse_returns_detected_server_type(
        vendor_name: str | None,
        vendor_version: str | None,
        expected: str,
    ) -> None:
        """RootDSE attributes yield the server type their vendor metadata names."""
        attributes: dict[str, list[str]] = {}
        if vendor_name is not None:
            attributes[c.Ldap.RootDseAttribute.VENDOR_NAME] = [vendor_name]
        if vendor_version is not None:
            attributes[c.Ldap.RootDseAttribute.VENDOR_VERSION] = [vendor_version]

        tm.that(u.Ldap.detect_from_root_dse(attributes), eq=expected)
