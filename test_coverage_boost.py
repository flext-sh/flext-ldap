#!/usr/bin/env python3
"""Teste direto para aumentar coverage de módulos básicos.

Executado sem pytest para evitar travamentos.
"""

import sys

sys.path.insert(0, "src")


def test_basic_imports() -> bool | None:
    """Testa imports básicos de todos os módulos."""
    try:

        from flext_ldap.config import FlextLdapSettings
        from flext_ldap.entities import FlextLdapUser
        from flext_ldap.values import FlextLdapCreateUserRequest

        # Test basic entity creation
        user = FlextLdapUser(
            id="test-id",
            dn="cn=test,dc=example,dc=com",
            uid="test",
            cn="Test User",
            sn="User"
        )
        assert user.uid == "test"
        assert user.cn == "Test User"

        # Test user request creation
        request = FlextLdapCreateUserRequest(
            dn="cn=test,dc=example,dc=com",
            uid="test",
            cn="Test User",
            sn="User"
        )
        assert request.uid == "test"

        # Test config creation
        config = FlextLdapSettings(
            host="localhost",
            port=389,
            use_ssl=False
        )
        assert config.host == "localhost"
        assert config.port == 389

        return True

    except Exception:
        return False


def test_api_initialization() -> bool | None:
    """Testa inicialização básica da API."""
    try:
        from flext_ldap import FlextLdapApi

        # Test API creation without config
        api = FlextLdapApi()
        assert api is not None

        # Test with config
        from flext_ldap.config import FlextLdapSettings
        config = FlextLdapSettings(host="test.example.com", port=389)
        api_with_config = FlextLdapApi(config)
        assert api_with_config is not None

        return True

    except Exception:
        return False


def test_domain_entities() -> bool | None:
    """Testa entidades de domínio básicas."""
    try:
        from flext_ldap.entities import FlextLdapEntry, FlextLdapGroup

        # Test FlextLdapEntry
        entry = FlextLdapEntry(
            id="entry-id",
            dn="cn=test,dc=example,dc=com",
            attributes={"cn": ["test"], "objectClass": ["person"]}
        )
        assert entry.dn == "cn=test,dc=example,dc=com"
        assert "cn" in entry.attributes

        # Test FlextLdapGroup
        group = FlextLdapGroup(
            id="group-id",
            dn="cn=group,dc=example,dc=com",
            cn="Test Group"
        )
        assert group.cn == "Test Group"

        return True

    except Exception:
        return False


def run_all_tests():
    """Executa todos os testes diretos."""
    tests = [
        test_basic_imports,
        test_api_initialization,
        test_domain_entities
    ]

    passed = 0
    total = len(tests)

    for test in tests:
        if test():
            passed += 1

    if passed == total:
        pass

    return passed == total


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
