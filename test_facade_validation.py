#!/usr/bin/env python3
"""Teste de validação do padrão Facade sem conexão de rede.

Este script valida a implementação do padrão Facade na API LDAP Core Shared
sem tentar estabelecer conexões reais com servidores LDAP.
"""

import asyncio
import os
import sys

# Adiciona o src ao path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from ldap_core_shared.api import LDAP, LDAPConfig, Result, validate_ldap_config


async def test_facade_validation() -> None:
    """Teste de validação do padrão Facade."""
    # 1. Teste LDAPConfig (Value Object)
    config = LDAPConfig(
        server="ldaps://ldap.example.com:636",
        auth_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
        auth_password="test123",
        base_dn="dc=example,dc=com",
        pool_size=15,
    )

    # 2. Teste validação sem conexão
    validation = await validate_ldap_config(config, test_connection=False)

    if validation.data.get("recommendations"):
        for _rec in validation.data["recommendations"]:
            pass

    # 3. Teste inicialização da Facade
    ldap = LDAP(config, use_connection_manager=True)

    # 4. Teste Query Builder sem execução
    (ldap.query()
            .users()
            .in_department("Engineering")
            .with_title("*Senior*")
            .enabled_only()
            .select("cn", "mail", "department")
            .limit(25))

    # 5. Teste Result Pattern

    # Success result
    Result.ok(
        data=["user1", "user2"],
        execution_time_ms=150.5,
        context={"source": "test"},
    )

    # Failure result
    Result.fail(
        "User not found",
        code="USER_NOT_FOUND",
        execution_time_ms=75.2,
    )

    # 6. Teste Connection Info (sem conexão real)
    ldap.get_connection_info()

    # 7. Teste configuração com problemas
    bad_config = LDAPConfig(
        server="",  # Servidor vazio
        auth_dn="",  # DN vazio
        auth_password="test123",
        base_dn="dc=example,dc=com",
        pool_size=2,  # Pool muito pequeno
    )

    bad_validation = await validate_ldap_config(bad_config, test_connection=False)

    for _issue in bad_validation.data["config_validation"]["issues"]:
        pass


if __name__ == "__main__":
    asyncio.run(test_facade_validation())
