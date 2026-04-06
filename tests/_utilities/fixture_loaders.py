"""Fixture loading utilities for flext-ldap test data.

Provides _FixtureLoaderUtils class composable into u.Ldap.Tests via MRO.
Access: u.Ldap.Tests.Fixtures.load_json(), u.Ldap.Tests.Fixtures.load_ldif(), etc.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import ClassVar

from pydantic import TypeAdapter, ValidationError

from flext_core import FlextLogger, r
from flext_ldif import ldif
from tests import c, m, t

GenericFieldsDict = t.Ldap.Tests.GenericFieldsDict


class _FixtureLoaderUtils:
    """Fixture loading helpers composed into u.Ldap.Tests via MRO.

    Provides Fixtures nested class accessible via u.Ldap.Tests.Fixtures.*.
    """

    _logger: ClassVar[FlextLogger] = FlextLogger(__name__)

    class Fixtures:
        """Test data fixture loaders accessible via u.Ldap.Tests.Fixtures.*."""

        FIXTURES_DIR: ClassVar[Path] = (
            Path(__file__).resolve().parent.parent / "fixtures"
        )
        JSON_FIELDS_SEQUENCE_ADAPTER: ClassVar[
            TypeAdapter[Sequence[GenericFieldsDict]]
        ] = TypeAdapter(Sequence[GenericFieldsDict])

        @staticmethod
        def load_json(filename: str) -> r[Sequence[GenericFieldsDict]]:
            filepath = _FixtureLoaderUtils.Fixtures.FIXTURES_DIR / filename
            try:
                if not filepath.exists():
                    return r[Sequence[GenericFieldsDict]].fail(
                        f"Fixture file not found: {filename}",
                    )
                raw_content = filepath.read_text(encoding="utf-8")
                data: Sequence[GenericFieldsDict] = (
                    _FixtureLoaderUtils.Fixtures.JSON_FIELDS_SEQUENCE_ADAPTER.validate_json(
                        raw_content
                    )
                )
                return r[Sequence[GenericFieldsDict]].ok(data)
            except (OSError, ValueError, ValidationError) as e:
                return r[Sequence[GenericFieldsDict]].fail(
                    f"Failed to load JSON fixture {filename}: {e}",
                )

        @staticmethod
        def load_ldif(filename: str) -> r[str]:
            filepath = _FixtureLoaderUtils.Fixtures.FIXTURES_DIR / filename
            try:
                if not filepath.exists():
                    return r[str].fail(f"Fixture file not found: {filename}")
                with filepath.open(encoding="utf-8") as fixture_file:
                    content = fixture_file.read()
                return r[str].ok(content)
            except OSError as e:
                return r[str].fail(f"Failed to load LDIF fixture {filename}: {e}")

        @staticmethod
        def load_docker_config() -> r[t.ContainerMapping]:
            filepath = _FixtureLoaderUtils.Fixtures.FIXTURES_DIR / "docker_config.json"
            try:
                if not filepath.exists():
                    return r[t.ContainerMapping].fail("Docker config file not found")
                raw_content = filepath.read_text(encoding="utf-8")
                config: t.ContainerMapping = (
                    t.Tests.SCALAR_MAPPING_ADAPTER.validate_json(raw_content)
                )
                return r[t.ContainerMapping].ok(config)
            except (OSError, ValueError, ValidationError) as e:
                return r[t.ContainerMapping].fail(
                    f"Failed to load docker config: {e}",
                )

        @staticmethod
        def load_users_json() -> Sequence[GenericFieldsDict]:
            result = _FixtureLoaderUtils.Fixtures.load_json("test_users.json")
            if result.is_success:
                return result.value
            _FixtureLoaderUtils._logger.warning(f"Failed to load users: {result.error}")
            return []

        @staticmethod
        def load_groups_json() -> Sequence[GenericFieldsDict]:
            result = _FixtureLoaderUtils.Fixtures.load_json("test_groups.json")
            if result.is_success:
                return result.value
            _FixtureLoaderUtils._logger.warning(
                f"Failed to load groups: {result.error}",
            )
            return []

        @staticmethod
        def load_base_ldif() -> str:
            result = _FixtureLoaderUtils.Fixtures.load_ldif("test_base.ldif")
            if result.is_success:
                return result.value
            _FixtureLoaderUtils._logger.warning(
                f"Failed to load base LDIF: {result.error}",
            )
            return ""

        @staticmethod
        def load_base_ldif_entries() -> Sequence[m.Ldif.Entry]:
            ldif_content = _FixtureLoaderUtils.Fixtures.load_base_ldif()
            if not ldif_content:
                return []
            ldif_instance = ldif()
            result = ldif_instance.parse_ldif(
                ldif_content,
                server_type=c.Ldap.ServerDefaults.DEFAULT_TYPE,
            )
            if result.is_success:
                return [
                    entry
                    for entry in result.value
                    if hasattr(entry, "dn") and hasattr(entry, "attributes")
                ]
            _FixtureLoaderUtils._logger.warning(
                f"Failed to parse base LDIF: {result.error}",
            )
            return []

        @staticmethod
        def convert_user_json_to_entry(
            user_data: GenericFieldsDict,
        ) -> GenericFieldsDict:
            object_classes_raw = user_data.get("object_classes", [])
            object_classes: t.StrSequence = (
                object_classes_raw if isinstance(object_classes_raw, list) else []
            )
            attributes: dict[str, t.StrSequence] = {
                "objectClass": [str(oc) for oc in object_classes],
                "uid": [str(user_data.get("uid", ""))],
                "cn": [str(user_data.get("cn", ""))],
                "sn": [str(user_data.get("sn", ""))],
            }
            optional_fields = {
                "given_name": "givenName",
                "mail": "mail",
                "telephone_number": "telephoneNumber",
                "mobile": "mobile",
                "department": "departmentNumber",
                "title": "title",
                "organization": "o",
                "organizational_unit": "ou",
            }
            for json_key, ldap_attr in optional_fields.items():
                if json_key in user_data:
                    attributes[ldap_attr] = [str(user_data.get(json_key, ""))]
            result: GenericFieldsDict = {
                "dn": str(user_data.get("dn", "")),
                "attributes": attributes,
            }
            return result

        @staticmethod
        def convert_group_json_to_entry(
            group_data: GenericFieldsDict,
        ) -> GenericFieldsDict:
            object_classes_raw = group_data.get("object_classes", [])
            object_classes: t.StrSequence = (
                object_classes_raw if isinstance(object_classes_raw, list) else []
            )
            attributes: dict[str, t.StrSequence] = {
                "objectClass": [str(oc) for oc in object_classes],
                "cn": [str(group_data.get("cn", ""))],
            }
            if "description" in group_data:
                attributes["description"] = [str(group_data.get("description", ""))]
            if "member_dns" in group_data:
                member_dns = group_data.get("member_dns", [])
                if isinstance(member_dns, list):
                    attributes["member"] = [str(member) for member in member_dns]
                else:
                    attributes["member"] = [str(member_dns)]
            result: GenericFieldsDict = {
                "dn": str(group_data.get("dn", "")),
                "attributes": attributes,
            }
            return result


class TestFixtures(_FixtureLoaderUtils.Fixtures):
    pass


__all__ = ["TestFixtures", "_FixtureLoaderUtils"]
