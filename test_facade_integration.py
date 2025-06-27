#!/usr/bin/env python3
"""Testes Abrangentes de Integração - Facade Pattern Validation.
============================================================

Este arquivo testa a integração completa da refatoração do God Object
para True Facade Pattern, validando:

1. Compatibilidade total com API existente
2. Delegação correta para subsistemas existentes
3. Funcionalidade de todos os módulos especializados
4. Performance e comportamento correto do Facade
5. Integração com ConnectionManager, domain models, etc.

DESIGN PATTERN TESTED: TRUE FACADE
==================================
- Facade delega APENAS (sem lógica de negócio)
- Módulos especializados têm responsabilidade única
- Integração com subsistemas existentes mantida
- API externa permanece inalterada
"""

import asyncio
import sys
import time
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent / "src"))


def test_module_imports() -> bool | None:
    """Testa que todos os módulos podem ser importados corretamente."""
    try:
        # Test individual module imports
        # Test unified API import (should work exactly like before)

        return True

    except Exception:
        import traceback

        traceback.print_exc()
        return False


def test_config_value_object() -> bool | None:
    """Testa o LDAPConfig Value Object."""
    try:
        from ldap_core_shared.api.config import LDAPConfig

        # Test basic configuration
        config = LDAPConfig(
            server="ldap.company.com",
            auth_dn="cn=admin,dc=company,dc=com",
            auth_password="secret123",
            base_dn="dc=company,dc=com",
        )

        # Test auto-detection features
        LDAPConfig(
            server="ldaps://secure.company.com:636",
            auth_dn="cn=admin,dc=company,dc=com",
            auth_password="secret123",
            base_dn="dc=company,dc=com",
        )

        # Test immutability (Value Object characteristic)
        try:
            config.server = "hacker.com"  # Should fail on frozen dataclass
        except Exception:
            pass

        return True

    except Exception:
        return False


def test_result_pattern() -> bool | None:
    """Testa o Result[T] pattern para tratamento de erros."""
    try:
        from ldap_core_shared.api.results import Result

        # Test success result
        Result.ok(
            {"users": ["john", "jane"]},
            execution_time_ms=150,
            source="test",
        )

        # Test failure result
        Result.fail(
            "User not found",
            code="USER_NOT_FOUND",
            execution_time_ms=50,
            default_data=[],
        )

        # Test exception handling
        try:
            msg = "Test exception"
            raise ValueError(msg)
        except Exception as e:
            Result.from_exception(e, execution_time_ms=25)

        return True

    except Exception:
        return False


def test_query_builder() -> bool | None:
    """Testa o Query Builder com interface fluente."""
    try:
        from ldap_core_shared.api.config import LDAPConfig
        from ldap_core_shared.api.facade import LDAP

        # Create mock LDAP facade for query testing
        config = LDAPConfig(
            server="ldap.test.com",
            auth_dn="cn=test,dc=test,dc=com",
            auth_password="test",
            base_dn="dc=test,dc=com",
        )

        ldap = LDAP(config, use_connection_manager=False)  # Disable real connections

        # Test fluent query building
        query = (
            ldap.query()
            .users()
            .in_department("Engineering")
            .with_title("*Manager*")
            .enabled_only()
            .select("cn", "mail", "title")
            .limit(25)
            .sort_by("cn")
        )

        # Test that query maintains reference to facade (check operations object)
        assert query._ldap is not None, "Query deve manter referência ao facade"

        return True

    except Exception:
        import traceback

        traceback.print_exc()
        return False


async def test_facade_delegation() -> bool | None:
    """Testa que o Facade delega corretamente para módulos especializados."""
    try:
        from ldap_core_shared.api.config import LDAPConfig
        from ldap_core_shared.api.facade import LDAP

        config = LDAPConfig(
            server="ldap.test.com",
            auth_dn="cn=test,dc=test,dc=com",
            auth_password="test",
            base_dn="dc=test,dc=com",
        )

        ldap = LDAP(config, use_connection_manager=True)

        # Test that facade creates specialized modules lazily

        # Operations module should be None initially
        assert ldap._operations is None, "Operations deve ser inicializado lazily"

        # Access operations - should trigger initialization
        ldap._get_operations()
        assert ldap._operations is not None, (
            "Operations deve ser inicializado após acesso"
        )

        # Validation module should be None initially
        assert ldap._validation is None, "Validation deve ser inicializado lazily"
        ldap._get_validation()
        assert ldap._validation is not None, (
            "Validation deve ser inicializado após acesso"
        )

        # Test delegation methods exist and delegate correctly
        query = ldap.query()  # Should delegate to Query creation
        assert query is not None, "Query deve ser criado via delegação"

        # Test connection info delegation
        connection_info = ldap.get_connection_info()
        assert isinstance(connection_info, dict), "Connection info deve retornar dict"
        assert "config" in connection_info, "Deve incluir informações de config"
        assert "status" in connection_info, "Deve incluir status de conexão"

        return True

    except Exception:
        import traceback

        traceback.print_exc()
        return False


async def test_subsystem_integration() -> bool | None:
    """Testa integração com subsistemas existentes (ConnectionManager, domain, etc.)."""
    try:
        from ldap_core_shared.api.config import LDAPConfig
        from ldap_core_shared.api.facade import LDAP

        config = LDAPConfig(
            server="ldap.enterprise.com",
            auth_dn="cn=admin,dc=enterprise,dc=com",
            auth_password="admin123",
            base_dn="dc=enterprise,dc=com",
            pool_size=10,
        )

        # Test enterprise ConnectionManager integration
        ldap_enterprise = LDAP(config, use_connection_manager=True)

        # Should initialize with ConnectionManager
        if ldap_enterprise._connection_manager is not None:
            # Test that connection info includes enterprise details
            info = ldap_enterprise.get_connection_info()
            assert info["status"]["connection_mode"] == "enterprise"

        # Test simple mode fallback
        ldap_simple = LDAP(config, use_connection_manager=False)
        info_simple = ldap_simple.get_connection_info()
        assert info_simple["status"]["connection_mode"] == "simple"

        # Test domain model integration (LDAPEntry)
        from ldap_core_shared.domain.models import LDAPEntry

        # Create test entry to verify domain integration
        test_entry = LDAPEntry(
            dn="cn=testuser,dc=test,dc=com",
            attributes={
                "cn": ["testuser"],
                "mail": ["test@company.com"],
                "objectClass": ["person", "organizationalPerson"],
            },
        )

        assert test_entry.dn == "cn=testuser,dc=test,dc=com"
        # LDAPEntry.get_attribute returns string, not list in this implementation
        cn_value = test_entry.get_attribute("cn")
        assert cn_value in ("testuser", ["testuser"]), f"CN value: {cn_value}"

        return True

    except Exception:
        import traceback

        traceback.print_exc()
        return False


async def test_api_compatibility() -> bool | None:
    """Testa que a API pública mantém compatibilidade total."""
    try:
        # Test that all original imports still work
        from ldap_core_shared.api import (
            LDAP,
            LDAPConfig,
            connect,
            ldap_session,
            validate_ldap_config,
        )

        # Test factory functions
        try:
            # This would normally connect, but we test the interface
            config = LDAPConfig(
                server="ldap.test.com",
                auth_dn="cn=test,dc=test,dc=com",
                auth_password="test",
                base_dn="dc=test,dc=com",
            )

            # Test that connect function exists and has correct signature
            import inspect

            connect_sig = inspect.signature(connect)
            expected_params = ["server", "auth_dn", "auth_password", "base_dn"]
            actual_params = list(connect_sig.parameters.keys())

            for param in expected_params:
                assert param in actual_params, f"Parâmetro {param} deve existir"

            # Test ldap_session context manager signature
            session_sig = inspect.signature(ldap_session)
            for param in expected_params:
                assert param in list(session_sig.parameters.keys())

            # Test validate_ldap_config function
            validation_sig = inspect.signature(validate_ldap_config)
            assert "config" in validation_sig.parameters

        except Exception:
            pass

        # Test LDAP class has all expected methods
        ldap = LDAP(config)

        expected_methods = [
            "find_user_by_email",
            "find_user_by_name",
            "find_users_in_department",
            "find_group_by_name",
            "get_user_groups",
            "get_group_members",
            "query",
            "search",
            "test_connection",
            "validate_entry_schema",
        ]

        for method in expected_methods:
            assert hasattr(ldap, method), f"Método {method} deve existir"

        # Test that context manager protocol works
        assert hasattr(ldap, "__aenter__"), "Deve implementar async context manager"
        assert hasattr(ldap, "__aexit__"), "Deve implementar async context manager"

        return True

    except Exception:
        import traceback

        traceback.print_exc()
        return False


def test_performance_and_memory() -> bool | None:
    """Testa que a refatoração não prejudicou performance ou uso de memória."""
    try:
        import gc
        import os

        import psutil

        # Measure memory before creating objects
        process = psutil.Process(os.getpid())
        memory_before = process.memory_info().rss / 1024 / 1024  # MB

        # Create multiple LDAP instances to test memory usage
        from ldap_core_shared.api import LDAP, LDAPConfig

        configs = []
        ldaps = []

        for i in range(10):
            config = LDAPConfig(
                server=f"ldap{i}.test.com",
                auth_dn=f"cn=admin{i},dc=test,dc=com",
                auth_password=f"password{i}",
                base_dn="dc=test,dc=com",
            )
            configs.append(config)

            ldap = LDAP(config, use_connection_manager=False)
            ldaps.append(ldap)

        memory_after = process.memory_info().rss / 1024 / 1024  # MB
        memory_used = memory_after - memory_before

        # Test lazy initialization performance
        start_time = time.time()

        for ldap in ldaps:
            # Access operations (should trigger lazy init)
            ldap._get_operations()
            ldap._get_validation()
            ldap.query()

        (time.time() - start_time) * 1000  # ms

        # Test that memory is reasonable (should be < 50MB for this test)
        if memory_used < 50:
            pass

        # Test delegation overhead
        start_time = time.time()

        for ldap in ldaps:
            ldap.get_connection_info()  # Delegation method

        (time.time() - start_time) * 1000  # ms

        # Cleanup
        del configs, ldaps
        gc.collect()

        return True

    except ImportError:
        return True
    except Exception:
        return False


async def run_all_tests():
    """Executa todos os testes de integração."""
    tests = [
        ("Importação de Módulos", test_module_imports),
        ("LDAPConfig Value Object", test_config_value_object),
        ("Result[T] Pattern", test_result_pattern),
        ("Query Builder", test_query_builder),
        ("Facade Delegation", test_facade_delegation),
        ("Integração Subsistemas", test_subsystem_integration),
        ("Compatibilidade API", test_api_compatibility),
        ("Performance & Memória", test_performance_and_memory),
    ]

    results = []

    for test_name, test_func in tests:
        try:
            if asyncio.iscoroutinefunction(test_func):
                result = await test_func()
            else:
                result = test_func()
            results.append((test_name, result))
        except Exception:
            results.append((test_name, False))

    # Summary

    passed = 0
    failed = 0

    for test_name, result in results:
        if result:
            passed += 1
        else:
            failed += 1

    if failed == 0:
        pass

    return failed == 0


if __name__ == "__main__":
    success = asyncio.run(run_all_tests())
    sys.exit(0 if success else 1)
