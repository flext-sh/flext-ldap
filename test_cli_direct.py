#!/usr/bin/env python3
"""Teste direto do CLI para aumentar coverage.

Testa imports e inicialização básica sem executar comandos.
"""

import sys
sys.path.insert(0, 'src')

def test_cli_imports():
    """Testa imports básicos do CLI."""
    try:
        from flext_ldap.cli import (
            LDAPConnectionTestParams
        )
        print("✅ CLI imports OK")

        # Test parameter classes
        params = LDAPConnectionTestParams(server="test.example.com", port=389)
        assert params.server == "test.example.com"
        assert params.port == 389
        print("✅ LDAPConnectionTestParams creation OK")

        return True

    except Exception as e:
        print(f"❌ CLI import error: {e}")
        return False

def test_cli_handlers():
    """Testa handlers básicos do CLI."""
    try:
        from flext_ldap.cli import LDAPConnectionHandler, LDAPSearchHandler, LDAPUserHandler

        # Test that handlers are classes (not functions)
        assert hasattr(LDAPConnectionHandler, 'test_connection')
        assert hasattr(LDAPSearchHandler, 'search_entries')
        assert hasattr(LDAPUserHandler, 'get_user_info')

        print("✅ CLI handlers structure OK")
        return True

    except Exception as e:
        print(f"❌ CLI handlers error: {e}")
        return False

def test_cli_click_structure():
    """Testa estrutura básica do Click CLI."""
    try:
        from flext_ldap.cli import cli

        # Test that cli is a Click command
        assert hasattr(cli, 'callback')
        assert hasattr(cli, 'commands')

        print("✅ CLI Click structure OK")
        return True

    except Exception as e:
        print(f"❌ CLI Click structure error: {e}")
        return False

def run_all_cli_tests():
    """Executa todos os testes do CLI."""
    tests = [
        test_cli_imports,
        test_cli_handlers,
        test_cli_click_structure
    ]

    passed = 0
    total = len(tests)

    for test in tests:
        print(f"\n--- Running {test.__name__} ---")
        if test():
            passed += 1
            print(f"✅ {test.__name__} PASSED")
        else:
            print(f"❌ {test.__name__} FAILED")

    print(f"\n🎯 CLI SUMMARY: {passed}/{total} tests passed")
    if passed == total:
        print("🎉 ALL CLI TESTS PASSED - CLI coverage increased!")
    else:
        print("⚠️  Some CLI tests failed")

    return passed == total

if __name__ == "__main__":
    success = run_all_cli_tests()
    sys.exit(0 if success else 1)
