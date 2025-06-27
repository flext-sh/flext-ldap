#!/usr/bin/env python3
"""Teste de compatibilidade para verificar a extração dos módulos da API.

Este teste verifica se os módulos extraídos mantêm a mesma interface
da API monolítica original.
"""

import os
import sys

# Adiciona o src ao path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))


def test_config_extraction() -> None:
    """Testa se LDAPConfig foi extraído corretamente."""
    # Import from extracted module
    from ldap_core_shared.api.config import LDAPConfig

    # Test basic functionality
    config = LDAPConfig(
        server="ldaps://ldap.example.com:636",
        auth_dn="cn=admin,dc=example,dc=com",
        auth_password="test123",
        base_dn="dc=example,dc=com",
        pool_size=15,
    )

    # Verify auto-detection works
    assert config.server == "ldap.example.com"
    assert config.port == 636
    assert config.use_tls is True
    assert config.pool_size == 15


def test_result_extraction() -> None:
    """Testa se Result[T] foi extraído corretamente."""
    from ldap_core_shared.api.results import Result

    # Test success result
    success_result = Result.ok(
        data=["user1", "user2"],
        execution_time_ms=150.5,
        source="test",
    )

    assert success_result.success is True
    assert success_result.data == ["user1", "user2"]
    assert success_result.execution_time_ms == 150.5
    assert success_result.context["source"] == "test"

    # Test failure result
    fail_result = Result.fail(
        "User not found",
        code="USER_NOT_FOUND",
        execution_time_ms=75.2,
    )

    assert fail_result.success is False
    assert fail_result.error == "User not found"
    assert fail_result.error_code == "USER_NOT_FOUND"
    assert fail_result.execution_time_ms == 75.2


def test_query_extraction() -> None:
    """Testa se Query foi extraído corretamente."""
    from ldap_core_shared.api.config import LDAPConfig
    from ldap_core_shared.api.query import Query

    # Mock facade for query
    class MockFacade:
        def __init__(self) -> None:
            self._config = LDAPConfig(
                server="ldap.example.com",
                auth_dn="cn=admin,dc=example,dc=com",
                auth_password="test123",
                base_dn="dc=example,dc=com",
            )

    mock_facade = MockFacade()

    # Test query building
    query = (
        Query(mock_facade)
        .users()
        .in_department("Engineering")
        .with_title("*Senior*")
        .enabled_only()
        .select("cn", "mail", "department")
        .limit(25)
    )

    # Verify internal state
    assert query._object_class == "person"
    assert "(department=Engineering)" in query._filters
    assert "(title=*Senior*)" in query._filters
    assert "(!(userAccountControl:1.2.840.113556.1.4.803:=2))" in query._filters
    assert query._attributes == ["cn", "mail", "department"]
    assert query._limit == 25


def test_package_structure() -> None:
    """Testa se a estrutura do pacote está correta."""
    # Test package imports
    from ldap_core_shared.api import LDAPConfig, Query, Result

    # Verify they are the same classes
    from ldap_core_shared.api.config import LDAPConfig as ConfigClass
    from ldap_core_shared.api.query import Query as QueryClass
    from ldap_core_shared.api.results import Result as ResultClass

    assert LDAPConfig is ConfigClass
    assert Result is ResultClass
    assert Query is QueryClass


def main() -> bool | None:
    """Executa todos os testes de extração."""
    try:
        test_config_extraction()
        test_result_extraction()
        test_query_extraction()
        test_package_structure()

        return True

    except Exception:
        import traceback

        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
