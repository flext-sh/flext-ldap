"""Unit tests for LDAP3 adapter helper classes.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Callable
from types import MappingProxyType
from typing import override

import pytest

from flext_ldap.adapters import (
    FlextLdapLdap3Wrappers,
    OperationExecutor,
    ResultConverter,
    ResultConverterExtractMixin,
    SearchExecutor,
)
from tests.constants import c
from tests.models import m
from tests.protocols import p
from tests.typings import t
from tests.utilities import u

pytestmark = pytest.mark.unit


class TestsFlextLdapLdap3AdapterHelpers:
    """Unit coverage for LDAP3 adapter helper classes."""

    class Attribute:
        """Structural ldap3 attribute used by helper tests."""

        def __init__(self, values: t.Ldap.Ldap3AttributeValues) -> None:
            self._values = values

        @property
        def values(self) -> t.Ldap.Ldap3AttributeValues:
            return self._values

        @property
        def value(self) -> t.Ldap.Ldap3EntryValue:
            return self._values[0] if self._values else c.Ldap.Tests.STRING_EMPTY

    class Entry:
        """Structural ldap3 entry used by converter tests."""

        def __init__(
            self,
            dn: str | None,
            attributes: t.Ldap.Ldap3AttributeDict,
        ) -> None:
            self._dn = dn
            self._attributes = attributes

        @property
        def entry_dn(self) -> str | None:
            return self._dn

        @property
        def entry_attributes(self) -> t.StrSequence:
            return tuple(self._attributes)

        @property
        def entry_attributes_as_dict(self) -> t.Ldap.Ldap3AttributeDict:
            return self._attributes

        def __getitem__(self, attribute_name: str) -> p.Ldap.Ldap3Attribute:
            """Return the structural ldap3 attribute for one name."""
            values = self._attributes[attribute_name]
            return TestsFlextLdapLdap3AdapterHelpers.Attribute(values)

    class ParseResponse:
        """Structural ldap3 parse response used by converter tests."""

        def __init__(self, entries: t.SequenceOf[p.Ldap.Ldap3Entry]) -> None:
            self._entries = entries

        @property
        def entries(self) -> t.SequenceOf[p.Ldap.Ldap3Entry]:
            return self._entries

    class ServerInfo:
        """Structural ldap3 server info for connection tests."""

        @property
        def naming_contexts(self) -> t.StrSequence | None:
            return (c.Ldap.Tests.RFC_DEFAULT_BASE_DN,)

        @property
        def other(self) -> t.MappingKV[str, t.JsonValue]:
            return {}

    class Server:
        """Structural ldap3 server for connection tests."""

        @property
        def info(self) -> p.Ldap.Ldap3ServerInfo | None:
            return TestsFlextLdapLdap3AdapterHelpers.ServerInfo()

        @override
        def __str__(self) -> str:
            """Return the server host marker."""
            host: str = c.LOCALHOST
            return host

    class RecordingConnection:
        """Structural ldap3 connection that records wrapper calls."""

        def __init__(
            self,
            *,
            result: t.JsonMapping | None = None,
            entries: t.SequenceOf[p.Ldap.Ldap3Entry] = (),
            search_error: OSError | None = None,
        ) -> None:
            self._bound = False
            self._entries = entries
            self._result = result
            self._search_error = search_error
            self._server = TestsFlextLdapLdap3AdapterHelpers.Server()
            self.last_add_dn = c.Ldap.Tests.STRING_EMPTY
            self.last_add_object_class: t.StrSequence | str | None = None
            self.last_add_attributes: t.MappingKV[str, str] = {}
            self.last_deleted_dn = c.Ldap.Tests.STRING_EMPTY
            self.last_modified_dn = c.Ldap.Tests.STRING_EMPTY
            self.last_modify_changes: t.Ldap.OperationChanges = dict[
                str,
                t.SequenceOf[t.Ldap.OperationChangeValue],
            ]()
            self.last_search_base = c.Ldap.Tests.STRING_EMPTY
            self.last_search_filter = c.Ldap.Tests.STRING_EMPTY
            self.last_search_scope: c.Ldap.Ldap3SearchScope | None = None
            self.last_search_attributes: t.StrSequence | str = ()
            self.last_size_limit = c.Ldap.Tests.SEARCH_DEFAULT_LIMIT_ZERO
            self.last_time_limit = c.Ldap.Tests.SEARCH_DEFAULT_LIMIT_ZERO

        @property
        def server(self) -> p.Ldap.Ldap3Server:
            return self._server

        @property
        def bound(self) -> bool:
            return self._bound

        def bind(self) -> bool:
            self._bound = True
            return self._bound

        @property
        def result(self) -> t.JsonMapping | None:
            return self._result

        @property
        def entries(self) -> t.SequenceOf[p.Ldap.Ldap3Entry]:
            return self._entries

        @property
        def add(self) -> Callable[..., bool]:
            return self._add

        @property
        def delete(self) -> Callable[..., bool]:
            return self._delete

        @property
        def modify(self) -> Callable[..., bool]:
            return self._modify

        @property
        def search(self) -> Callable[..., bool | t.JsonValue | None]:
            return self._search

        @property
        def start_tls(self) -> Callable[..., bool]:
            return self._start_tls

        @property
        def unbind(self) -> Callable[..., bool]:
            return self._unbind

        def _add(
            self,
            dn: str,
            object_class: t.StrSequence | str | None,
            attributes: t.MappingKV[str, str],
        ) -> bool:
            self.last_add_dn = dn
            self.last_add_object_class = object_class
            self.last_add_attributes = attributes
            return True

        def _delete(self, dn: str) -> bool:
            self.last_deleted_dn = dn
            return True

        def _modify(self, dn: str, changes: t.Ldap.OperationChanges) -> bool:
            self.last_modified_dn = dn
            self.last_modify_changes = changes
            return True

        def _search(
            self,
            *,
            search_base: str,
            search_filter: str,
            search_scope: c.Ldap.Ldap3SearchScope,
            attributes: t.StrSequence | str,
            size_limit: int,
            time_limit: int,
        ) -> bool:
            if self._search_error is not None:
                raise self._search_error
            self.last_search_base = search_base
            self.last_search_filter = search_filter
            self.last_search_scope = search_scope
            self.last_search_attributes = attributes
            self.last_size_limit = size_limit
            self.last_time_limit = time_limit
            return True

        def _start_tls(self) -> bool:
            return True

        def _unbind(self) -> bool:
            self._bound = False
            return True

    class MissingTlsConnection(RecordingConnection):
        """Connection whose STARTTLS method is absent at runtime."""

        @property
        @override
        def start_tls(self) -> Callable[..., bool]:
            message = "start_tls"
            raise AttributeError(message)

    class FailingOperationConnection(RecordingConnection):
        """Connection that reports LDAP operation failure."""

        @override
        def _delete(self, dn: str) -> bool:
            self.last_deleted_dn = dn
            return False

    @staticmethod
    def _entry(dn: str = c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE) -> m.Ldif.Entry:
        return m.Ldif.Entry(
            dn=m.Ldif.DN(value=dn),
            attributes=m.Ldif.Attributes.model_validate(
                {
                    "attributes": {
                        c.Ldap.AttributeName.COMMON_NAME: [c.Ldap.Tests.STRING_SIMPLE],
                        c.Ldap.Tests.SEARCH_ATTRIBUTES[1]: [
                            c.Ldap.Tests.CONFIG_EXAMPLE_HOST
                        ],
                    },
                },
            ),
        )

    @staticmethod
    def _ldap3_entry(
        dn: str | None = c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE,
    ) -> p.Ldap.Ldap3Entry:
        return TestsFlextLdapLdap3AdapterHelpers.Entry(
            dn,
            {
                c.Ldap.AttributeName.COMMON_NAME: (
                    c.Ldap.Tests.STRING_SIMPLE.encode(c.Ldif.Encoding.UTF8),
                ),
                c.Ldap.Tests.SEARCH_ATTRIBUTES[1]: (c.Ldap.Tests.CONFIG_EXAMPLE_HOST,),
            },
        )

    @staticmethod
    def _success_result() -> t.JsonMapping:
        return {
            "result": c.Ldap.ResultCode.SUCCESS.value,
            "message": c.Ldap.Tests.STRING_EMPTY,
            "description": c.Ldap.Tests.STRING_EMPTY,
        }

    @staticmethod
    def _failure_result() -> t.JsonMapping:
        return {
            "result": c.Ldap.ResultCode.NO_SUCH_OBJECT.value,
            "message": c.Ldap.Tests.BASE_FAIL_ERROR_MESSAGE,
            "description": c.Ldap.ResultCode.NO_SUCH_OBJECT.name,
        }

    @staticmethod
    def _search_params() -> m.Ldap.SearchParams:
        return m.Ldap.SearchParams(
            base_dn=c.Ldap.Tests.RFC_DEFAULT_BASE_DN,
            filter_str=c.Ldap.Tests.RFC_DEFAULT_FILTER,
            ldap_scope=c.Ldap.SearchScopeValue.SUBTREE,
            search_attributes=c.Ldap.Tests.SEARCH_ATTRIBUTES,
            size_limit=c.Ldap.Tests.SEARCH_DEFAULT_LIMIT_ZERO,
            time_limit=c.Ldap.Tests.SEARCH_DEFAULT_LIMIT_ZERO,
        )

    @pytest.mark.parametrize("case", c.Ldap.Tests.LdapValueCase)
    def test_value_to_str_list_uses_canonical_conversion(
        self,
        case: c.Ldap.Tests.LdapValueCase,
    ) -> None:
        value, expected = c.Ldap.Tests.LDAP3_VALUE_TO_STRINGS_SCENARIOS[case]

        converted = FlextLdapLdap3Wrappers.value_to_str_list(value)

        u.Ldap.Tests.that(converted, eq=list(expected))

    def test_wrappers_delegate_and_normalize_arguments(self) -> None:
        connection = self.RecordingConnection()
        changes: t.Ldap.OperationChanges = {
            c.Ldap.AttributeName.COMMON_NAME: (
                (
                    c.Ldap.ModifyOperation.REPLACE,
                    (c.Ldap.Tests.STRING_SIMPLE_UPPER,),
                ),
            ),
        }

        add_result = FlextLdapLdap3Wrappers.add(
            connection,
            c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE,
            None,
            {
                c.Ldap.AttributeName.COMMON_NAME: (c.Ldap.Tests.STRING_SIMPLE,),
                c.Ldap.Tests.SEARCH_ATTRIBUTES[1]: (),
            },
        )
        delete_result = FlextLdapLdap3Wrappers.delete(
            connection,
            c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE,
        )
        modify_result = FlextLdapLdap3Wrappers.modify(
            connection,
            c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE,
            changes,
        )
        unbind_result = FlextLdapLdap3Wrappers.unbind(connection)

        u.Ldap.Tests.that(add_result, eq=True)
        u.Ldap.Tests.that(connection.last_add_dn, eq=c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE)
        u.Ldap.Tests.that(
            connection.last_add_attributes[c.Ldap.AttributeName.COMMON_NAME],
            eq=c.Ldap.Tests.STRING_SIMPLE,
        )
        u.Ldap.Tests.that(
            connection.last_add_attributes[c.Ldap.Tests.SEARCH_ATTRIBUTES[1]],
            eq=c.Ldap.Tests.STRING_EMPTY,
        )
        u.Ldap.Tests.that(delete_result, eq=True)
        u.Ldap.Tests.that(
            connection.last_deleted_dn,
            eq=c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE,
        )
        u.Ldap.Tests.that(modify_result, eq=True)
        u.Ldap.Tests.that(connection.last_modify_changes, eq=changes)
        u.Ldap.Tests.that(unbind_result, eq=True)

    def test_search_wrapper_normalizes_scope_and_attributes(self) -> None:
        connection = self.RecordingConnection()

        search_result = FlextLdapLdap3Wrappers.search(
            connection,
            search_base=c.Ldap.Tests.RFC_DEFAULT_BASE_DN,
            search_filter=c.Ldap.Tests.RFC_DEFAULT_FILTER,
            search_scope=c.Ldap.SearchScopeValue.BASE,
            attributes=c.Ldap.Tests.SEARCH_ATTRIBUTES,
            size_limit=c.Ldap.Tests.SEARCH_SIZE_LIMIT_CUSTOM,
            time_limit=c.Ldap.Tests.SEARCH_TIME_LIMIT_CUSTOM,
        )

        u.Ldap.Tests.that(search_result, eq=True)
        u.Ldap.Tests.that(
            connection.last_search_scope,
            eq=c.Ldap.Ldap3SearchScope.BASE,
        )
        u.Ldap.Tests.that(
            connection.last_search_attributes,
            eq=list(c.Ldap.Tests.SEARCH_ATTRIBUTES),
        )
        u.Ldap.Tests.that(
            connection.last_size_limit,
            eq=c.Ldap.Tests.SEARCH_SIZE_LIMIT_CUSTOM,
        )

    def test_start_tls_missing_method_raises(self) -> None:
        with pytest.raises(AttributeError, match="start_tls method"):
            FlextLdapLdap3Wrappers.start_tls(self.MissingTlsConnection())

    def test_result_extract_handles_ldif_and_ldap3_entries(self) -> None:
        ldif_entry = self._entry()
        ldap3_entry = self._ldap3_entry()

        ldif_dn = ResultConverterExtractMixin.extract_dn(ldif_entry)
        ldap3_dn = ResultConverterExtractMixin.extract_dn(ldap3_entry)
        ldap3_attrs = ResultConverterExtractMixin.extract_attributes(ldap3_entry)
        attrs_input: t.MappingKV[
            str,
            t.Ldap.Ldap3EntryValue | t.JsonValue | t.StrSequence,
        ] = {
            c.Ldap.AttributeName.COMMON_NAME.value: c.Ldap.Tests.STRING_SIMPLE,
            c.Ldap.AttributeName.OBJECT_CLASS.value: (
                c.Ldap.Tests.SEARCH_ENTRIES_AFFECTED_ONE
            ),
            c.Ldap.AttributeName.ALL_ATTRIBUTES.value: None,
        }
        attrs_dict = ResultConverterExtractMixin.extract_attrs_dict(attrs_input)

        u.Ldap.Tests.that(ldif_dn.value, eq=c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE)
        u.Ldap.Tests.that(ldap3_dn.value, eq=c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE)
        u.Ldap.Tests.that(
            ldap3_attrs.attributes[c.Ldap.AttributeName.COMMON_NAME],
            eq=[c.Ldap.Tests.STRING_SIMPLE],
        )
        u.Ldap.Tests.that(
            attrs_dict[c.Ldap.AttributeName.COMMON_NAME],
            eq=[c.Ldap.Tests.STRING_SIMPLE],
        )
        u.Ldap.Tests.that(
            attrs_dict[c.Ldap.AttributeName.OBJECT_CLASS],
            eq=[str(c.Ldap.Tests.SEARCH_ENTRIES_AFFECTED_ONE)],
        )
        u.Ldap.Tests.that(attrs_dict[c.Ldap.AttributeName.ALL_ATTRIBUTES], eq=[])

    def test_result_extract_metadata_from_entry_and_mapping(self) -> None:
        metadata = m.Ldif.ServerMetadata.model_validate(
            {
                "server_type": c.Ldif.ServerTypes.RFC,
            },
        )
        entry = self._entry().model_copy(update={"metadata": metadata})

        entry_metadata = ResultConverterExtractMixin.extract_metadata(entry)
        normalized_metadata = ResultConverterExtractMixin._normalize_metadata(
            {
                "server_type": c.Ldif.ServerTypes.RFC.value,
            },
        )
        assert normalized_metadata is not None
        mapped_metadata = m.Ldif.ServerMetadata.model_validate(normalized_metadata)

        assert entry_metadata is not None
        u.Ldap.Tests.that(entry_metadata.server_type, eq=c.Ldif.ServerTypes.RFC)
        u.Ldap.Tests.that(mapped_metadata.server_type, eq=c.Ldif.ServerTypes.RFC)

    def test_result_converter_converts_connection_and_parse_response(self) -> None:
        ldap3_entry = self._ldap3_entry()
        connection = self.RecordingConnection(entries=(ldap3_entry,))
        parsed_response = self.ParseResponse((ldap3_entry,))

        converted = ResultConverter.convert_ldap3_results(connection)
        converted_entries = u.Ldap.Tests.ok(
            ResultConverter.convert_parsed_entries(parsed_response),
        )

        u.Ldap.Tests.that(converted[0][0], eq=c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE)
        u.Ldap.Tests.that(
            converted[0][1][c.Ldap.AttributeName.COMMON_NAME],
            eq=[c.Ldap.Tests.STRING_SIMPLE],
        )
        u.Ldap.Tests.that(
            converted_entries[0].dn is not None,
            eq=True,
        )
        u.Ldap.Tests.that(
            converted_entries[0].dn.value if converted_entries[0].dn else "",
            eq=c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE,
        )

    def test_search_executor_returns_entries_for_success(self) -> None:
        connection = self.RecordingConnection(
            result=self._success_result(),
            entries=(self._ldap3_entry(),),
        )

        entries = u.Ldap.Tests.ok(
            SearchExecutor.execute(
                connection,
                self._search_params(),
                c.Ldif.ServerTypes.RFC,
            ),
        )

        u.Ldap.Tests.that(len(entries), eq=c.Ldap.Tests.SEARCH_ENTRIES_AFFECTED_ONE)
        u.Ldap.Tests.that(
            entries[0].dn is not None,
            eq=True,
        )
        u.Ldap.Tests.that(
            entries[0].dn.value if entries[0].dn else "",
            eq=c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE,
        )
        u.Ldap.Tests.that(
            connection.last_search_scope,
            eq=c.Ldap.Ldap3SearchScope.SUBTREE,
        )

    def test_search_executor_reports_ldap_failure(self) -> None:
        connection = self.RecordingConnection(result=self._failure_result())

        error = u.Ldap.Tests.fail(
            SearchExecutor.execute(
                connection,
                self._search_params(),
                c.Ldif.ServerTypes.RFC,
            ),
        )

        u.Ldap.Tests.that(error, contains=c.Ldap.ResultCode.NO_SUCH_OBJECT.name)

    def test_search_executor_reports_invalid_server_type(self) -> None:
        connection = self.RecordingConnection(result=self._success_result())

        error = u.Ldap.Tests.fail(
            SearchExecutor.execute(
                connection,
                self._search_params(),
                c.Ldap.Tests.CONSTANT_INVALID_STATUS,
            ),
        )

        u.Ldap.Tests.that(error, contains="Unsupported server type")

    def test_search_executor_reports_wrapper_exception(self) -> None:
        connection = self.RecordingConnection(
            search_error=OSError(c.Ldap.Tests.BASE_FAIL_ERROR_MESSAGE),
        )

        error = u.Ldap.Tests.fail(
            SearchExecutor.execute(
                connection,
                self._search_params(),
                c.Ldif.ServerTypes.RFC,
            ),
        )

        u.Ldap.Tests.that(error, contains="Search")

    def test_operation_executor_validates_mapping_result_payload(self) -> None:
        payload = MappingProxyType(self._failure_result())
        connection = self.FailingOperationConnection(result=payload)

        error = u.Ldap.Tests.fail(
            OperationExecutor.execute_delete(
                connection,
                c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE,
            ),
        )

        u.Ldap.Tests.that(error, contains=c.Ldap.ResultCode.NO_SUCH_OBJECT.name)

    def test_operation_executor_normalizes_json_description_payload(self) -> None:
        description = c.Ldap.Tests.SEARCH_ENTRIES_AFFECTED_ONE
        payload = MappingProxyType(
            {
                "result": c.Ldap.ResultCode.NO_SUCH_OBJECT.value,
                "description": description,
            },
        )
        connection = self.FailingOperationConnection(result=payload)

        error = u.Ldap.Tests.fail(
            OperationExecutor.execute_delete(
                connection,
                c.Ldap.Tests.ENTRY_DN_TEST_EXAMPLE,
            ),
        )

        u.Ldap.Tests.that(error, contains=repr(description))


__all__: list[str] = ["TestsFlextLdapLdap3AdapterHelpers"]
