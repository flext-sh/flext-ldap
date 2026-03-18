from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TypeVar

import pytest
from flext_core import T, r
from flext_core.typings import t as core_t
from flext_tests import FlextTestsUtilities

from flext_ldap import (
    FlextLdap,
    FlextLdapOperations,
    FlextLdapUtilities,
)
from tests import c, m, p, t
from tests._utilities.docker_infra import _DockerInfraUtils
from tests._utilities.fixture_loaders import _FixtureLoaderUtils


class TestsFlextLdapUtilities(FlextTestsUtilities, FlextLdapUtilities):
    """Utilities for flext-ldap tests - extends u and FlextLdapUtilities.

    Architecture: Extends both u and FlextLdapUtilities with flext-ldap-specific utility methods.
    All generic utilities from u and production utilities from FlextLdapUtilities are available through inheritance.

    Rules:
    - NEVER redeclare utilities from u or FlextLdapUtilities
    - Only flext-ldap-specific utilities allowed
    - All generic utilities come from u
    - All production utilities come from FlextLdapUtilities
    """

    class Ldap(FlextLdapUtilities.Ldap):
        """LDAP test utilities."""

        class Tests(_DockerInfraUtils, _FixtureLoaderUtils):
            """flext-ldap-specific test utilities definitions namespace.

            Consolidates operation helpers, type adapters, and utility methods.
            Use u.Ldap.Tests.* for all flext-ldap test utilities.
            """

            # LDAP modify operation codes (from helpers)
            LDAP_MODIFY_ADD: int = 0
            LDAP_MODIFY_DELETE: int = 1
            LDAP_MODIFY_REPLACE: int = 2

            T = TypeVar("T")
            LdapClientType = FlextLdap | p.Ldap.LdapClient
            LdapOperationsType = FlextLdap | FlextLdapOperations | p.Ldap.LdapClient
            SearchScopeType = c.Ldap.SearchScope

            @staticmethod
            def _ldap_entry_to_protocol_adapter(
                entry: t.Ldap.Tests.LdapEntry,
            ) -> p.Ldap.LdapEntry:
                """Convert LdapEntry to protocol adapter.

                Args:
                    entry: LdapEntry to convert

                Returns:
                    Protocol adapter compatible with p.Ldap.LdapEntry

                """

                class _LdapEntryProtocolAdapter:
                    dn: str | p.Ldap.DN | None
                    attributes: Mapping[str, Sequence[str]] | p.Ldap.Attributes | None
                    metadata: core_t.ConfigMap | None

                    def __init__(
                        self,
                        dn: str,
                        attributes: Mapping[str, Sequence[str]],
                        *,
                        metadata: core_t.ConfigMap | None = None,
                    ) -> None:
                        self.dn = dn
                        self.attributes = attributes
                        self.metadata = metadata

                dn_str = str(entry.dn) if entry.dn is not None else ""
                attrs: Mapping[str, Sequence[str]] = (
                    entry.attributes.attributes
                    if entry.attributes is not None
                    and hasattr(entry.attributes, "attributes")
                    else {}
                )
                return _LdapEntryProtocolAdapter(dn=dn_str, attributes=attrs)

            @staticmethod
            def _validate_scope(
                scope: str | c.Ldap.SearchScope,
            ) -> c.Ldap.SearchScope:
                """Validate and return a SearchScope StrEnum.

                Uses u.parse for unified enum parsing via test utilities.

                Args:
                    scope: Scope string or StrEnum to validate

                Returns:
                    Validated scope as SearchScope StrEnum

                Raises:
                    ValueError: If scope is not valid

                """
                valid_scopes: frozenset[str] = frozenset({
                    c.Ldap.SearchScope.BASE.value,
                    c.Ldap.SearchScope.ONELEVEL.value,
                    c.Ldap.SearchScope.SUBTREE.value,
                })
                if isinstance(scope, c.Ldap.SearchScope):
                    return scope
                parse_result = FlextTestsUtilities.parse(
                    scope, target=c.Ldap.SearchScope
                )
                if parse_result.is_success:
                    return parse_result.value
                msg = f"Invalid scope: {scope}. Must be one of {valid_scopes}"
                raise ValueError(msg)

            @staticmethod
            def _ensure_flext_result(result: r[T] | object) -> r[T]:
                """Ensure result is r, converting from protocol if needed.

                Args:
                    result: Result that may be r or protocol result

                Returns:
                    r[T] instance

                """
                if isinstance(result, r):
                    return result
                assert isinstance(result, r), f"Expected r[T], got {type(result)}"
                return result

            @staticmethod
            def _assert_result_success(
                result: r[T], error_msg: str = "Operation failed"
            ) -> r[T]:
                """Assert result is success and return it.

                Args:
                    result: Result to check
                    error_msg: Error message if failure

                Returns:
                    Result if success

                Raises:
                    AssertionError: If result is failure

                """
                if not result.is_success:
                    raise AssertionError(error_msg)
                return result

            @staticmethod
            def _ensure_entry_has_dn(entry: t.Ldap.Tests.LdapEntry) -> None:
                """Ensure entry has DN for protocol compatibility.

                Args:
                    entry: LdapEntry to validate

                Raises:
                    ValueError: If entry.dn is None

                """
                if not hasattr(entry, "dn") or entry.dn is None:
                    error_msg = "Entry must have a DN to add"
                    raise ValueError(error_msg)

            @staticmethod
            def _ensure_entry_has_attributes(entry: t.Ldap.Tests.LdapEntry) -> None:
                """Ensure entry has attributes for protocol compatibility.

                Args:
                    entry: LdapEntry to validate

                Raises:
                    ValueError: If entry.attributes is None

                """
                if not hasattr(entry, "attributes") or entry.attributes is None:
                    error_msg = "Entry must have attributes to add"
                    raise ValueError(error_msg)

            @staticmethod
            def _ensure_entry_protocol_compatible(
                entry: t.Ldap.Tests.LdapEntry,
            ) -> None:
                """Ensure entry is compatible with Entry.

                Args:
                    entry: LdapEntry to validate

                Raises:
                    ValueError: If entry.dn or entry.attributes is None

                """
                TestsFlextLdapUtilities.Ldap.Tests._ensure_entry_has_dn(entry)
                TestsFlextLdapUtilities.Ldap.Tests._ensure_entry_has_attributes(entry)

            @staticmethod
            def _get_entry_for_protocol(
                entry: t.Ldap.Tests.LdapEntry,
            ) -> t.Ldap.Tests.LdapEntry:
                """Get entry compatible with LdapEntry after validation.

                Args:
                    entry: LdapEntry that has been validated via _ensure_entry_protocol_compatible

                Returns:
                    Entry (m.Ldif.Entry) compatible with LdapEntry

                """
                if not (hasattr(entry, "dn") and hasattr(entry, "attributes")):
                    raise TypeError(
                        f"Entry must have dn and attributes, got {type(entry)}"
                    )
                return entry

            @staticmethod
            def _validate_search_options_type(
                search_options_raw: Mapping[str, str | int | bool] | None,
            ) -> m.Ldap.SearchOptions:
                """Validate and return SearchOptions type.

                Args:
                    search_options_raw: Raw search options to validate

                Returns:
                    Validated SearchOptions instance

                Raises:
                    TypeError: If search_options_raw is not SearchOptions

                """
                if not isinstance(search_options_raw, m.Ldap.SearchOptions):
                    error_msg = "search_options must be m.Ldap.SearchOptions"
                    raise TypeError(error_msg)
                return search_options_raw

            @staticmethod
            def connect_with_skip_on_failure(
                client: FlextLdap | p.Ldap.LdapClient,
                connection_config: m.Ldap.ConnectionConfig,
            ) -> None:
                """Connect client and skip test on failure.

                Args:
                    client: LDAP client implementing p.Ldap.LdapClient
                    connection_config: Connection configuration

                """
                connect_result = client.connect(connection_config)
                if connect_result.is_failure:
                    pytest.skip(
                        f"Failed to connect: {connect_result.error}. This test requires a running LDAP container."
                    )

            @staticmethod
            def search_and_assert_success(
                client: FlextLdap | FlextLdapOperations | p.Ldap.LdapClient,
                base_dn: str,
                *,
                filter_str: str = "(objectClass=*)",
                expected_min_count: int = 0,
                expected_max_count: int | None = None,
                scope: str = c.Ldap.SearchScope.SUBTREE.value,
                attributes: list[str] | None = None,
                size_limit: int = 0,
            ) -> m.Ldap.SearchResult:
                """Search and assert success.

                Args:
                    client: LDAP client with search method
                    base_dn: Base DN for search
                    filter_str: LDAP filter string
                    expected_min_count: Minimum number of entries expected
                    expected_max_count: Maximum number of entries expected (optional)
                    scope: Search scope
                    attributes: Attributes to retrieve
                    size_limit: Maximum number of entries to return

                Returns:
                    SearchResult

                """
                validated_scope = TestsFlextLdapUtilities.Ldap.Tests._validate_scope(
                    scope
                )
                search_options = m.Ldap.SearchOptions(
                    base_dn=base_dn,
                    filter_str=filter_str,
                    scope=validated_scope.value,
                    attributes=attributes,
                    size_limit=size_limit,
                )
                if isinstance(client, (FlextLdap, FlextLdapOperations)):
                    search_result_raw: (
                        r[m.Ldap.SearchResult] | r[p.Ldap.SearchResult]
                    ) = client.search(search_options)
                else:
                    if not hasattr(search_options, "base_dn"):
                        raise TypeError(
                            f"SearchOptions must have base_dn, got {type(search_options)}"
                        )
                    search_result_protocol = client.search(search_options)
                    search_result_raw = search_result_protocol
                if not isinstance(search_result_raw, r):
                    search_result_raw = (
                        TestsFlextLdapUtilities.Ldap.Tests._ensure_flext_result(
                            search_result_raw
                        )
                    )
                assert search_result_raw.is_success, "Search failed"
                result_untyped = search_result_raw.value
                if not isinstance(result_untyped, m.Ldap.SearchResult):
                    raise TypeError(
                        f"Expected m.Ldap.SearchResult, got {type(result_untyped)}"
                    )
                result: m.Ldap.SearchResult = result_untyped
                assert len(result.entries) >= expected_min_count, (
                    f"Expected at least {expected_min_count} entries, got {len(result.entries)}"
                )
                if expected_max_count is not None:
                    assert len(result.entries) <= expected_max_count, (
                        f"Expected at most {expected_max_count} entries, got {len(result.entries)}"
                    )
                return result

            @staticmethod
            def create_inetorgperson_entry(
                cn_value: str,
                base_dn: str,
                *,
                sn: str | None = None,
                mail: str | None = None,
                use_uid: bool = False,
                additional_attrs: t.Ldap.Tests.GenericFieldsDict | None = None,
                **extra_attributes: str | int | bool | list[str],
            ) -> m.Ldif.Entry:
                """Create inetOrgPerson entry.

                Args:
                    cn_value: Common name value (or uid if use_uid=True)
                    base_dn: Base DN for entry
                    sn: Optional surname
                    mail: Optional email
                    use_uid: If True, creates uid-based DN
                    additional_attrs: Optional additional attributes
                    **extra_attributes: Additional attributes as kwargs

                Returns:
                    m.Ldif.Entry with inetOrgPerson objectClass

                """
                if use_uid:
                    dn = f"uid={cn_value},ou=people,{base_dn}"
                    entry_attributes: dict[str, list[str]] = {
                        "objectClass": [
                            "top",
                            "person",
                            "organizationalPerson",
                            "inetOrgPerson",
                        ],
                        "uid": [cn_value],
                    }
                    if sn:
                        entry_attributes["sn"] = [sn]
                else:
                    dn = f"cn={cn_value},{base_dn}"
                    entry_attributes_cn: dict[str, list[str]] = {
                        "cn": [cn_value],
                        "objectClass": ["top", "person", "inetOrgPerson"],
                        "sn": [sn or cn_value],
                    }
                    entry_attributes = entry_attributes_cn
                if mail:
                    entry_attributes["mail"] = [mail]
                if "cn" in extra_attributes:
                    cn_extra = extra_attributes.pop("cn")
                    if isinstance(cn_extra, list):
                        entry_attributes["cn"] = [str(v) for v in cn_extra]
                    else:
                        entry_attributes["cn"] = [str(cn_extra)]
                if additional_attrs:
                    normalized_additional: dict[str, list[str]] = {}
                    for key, value in additional_attrs.items():
                        if isinstance(value, list):
                            normalized_additional[key] = [str(v) for v in value]
                        else:
                            normalized_additional[key] = [str(value)]
                    entry_attributes.update(normalized_additional)
                if extra_attributes:
                    normalized_extra: dict[str, list[str]] = {}
                    for key, value in extra_attributes.items():
                        if isinstance(value, list):
                            normalized_extra[key] = [str(v) for v in value]
                        else:
                            normalized_extra[key] = [str(value)]
                    entry_attributes.update(normalized_extra)
                return m.Ldif.Entry(
                    dn=m.Ldif.DN(value=dn),
                    attributes=m.Ldif.Attributes(attributes=entry_attributes),
                    metadata=None,
                )


u = TestsFlextLdapUtilities

__all__ = ["TestsFlextLdapUtilities", "u"]
