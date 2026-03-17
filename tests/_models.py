"""Auto-generated centralized models."""

from __future__ import annotations

from pydantic import RootModel


class FlextAutoConstants:
    pass


class FlextAutoTypes:
    pass


class FlextAutoProtocols:
    pass


class FlextAutoUtilities:
    pass


class FlextAutoModels:
    pass


c = FlextAutoConstants
t = FlextAutoTypes
p = FlextAutoProtocols
u = FlextAutoUtilities
m = FlextAutoModels


class GenericFieldsDict(RootModel[dict[str, str | int | bool | list[str]]]):
    pass


class LdapContainerDict(RootModel[dict[str, str | int | bool]]):
    pass


class LdapConnectionConfigDict(RootModel[dict[str, str | int | bool | None]]):
    pass


class LdapSearchOptionsDict(RootModel[dict[str, str | int | bool]]):
    pass


class LdapEntryDataDict(RootModel[dict[str, str | int | bool | list[str]]]):
    pass


class LdapSchemaAttributeDict(RootModel[dict[str, str | list[str] | bool]]):
    pass


class LdapSchemaObjectClassDict(RootModel[dict[str, str | list[str] | bool]]):
    pass


class LdapModifyOperationDict(RootModel[dict[str, str | int | bool | list[str]]]):
    pass


class LdapSearchResultDict(RootModel[dict[str, str | int | bool | list[str]]]):
    pass


class LdapTestScenarioDict(RootModel[dict[str, str | int | bool]]):
    pass


class GenericTestCaseDict(RootModel[dict[str, str | int | bool]]):
    pass


class GenericCallableParameterDict(RootModel[dict[str, str | int | bool]]):
    pass


class LdapConnectionResultDict(RootModel[dict[str, str | int | bool]]):
    pass
