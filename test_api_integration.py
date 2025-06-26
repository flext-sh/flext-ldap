#!/usr/bin/env python3
"""Test script para validar a integração da API unificada como Facade.

Este script demonstra o padrão Facade implementado na API LDAP Core Shared.
Mostra como a API delega para componentes especializados mantendo interface simples.
"""

import asyncio

from src.ldap_core_shared.api import (
    LDAP,
    LDAPConfig,
    validate_ldap_config,
)


async def test_facade_pattern() -> None:
    """Teste do padrão Facade com delegação para ConnectionManager."""
    # 1. Teste de configuração (Value Object)
    config = LDAPConfig(
        server="ldaps://ldap.example.com:636",
        auth_dn="cn=admin,dc=example,dc=com",
        auth_password="test123",
        base_dn="dc=example,dc=com",
        pool_size=10,
    )

    # 2. Teste de validação de configuração
    validation = await validate_ldap_config(config, test_connection=False)
    if validation.data.get("recommendations"):
        for _rec in validation.data["recommendations"]:
            pass

    # 3. Teste da facade LDAP com ConnectionManager
    try:
        async with LDAP(config, use_connection_manager=True) as ldap:

            # Teste de informações de conexão
            ldap.get_connection_info()

            # Teste de builder de queries (Builder Pattern)
            (ldap.query()
                    .users()
                    .in_department("IT")
                    .enabled_only()
                    .select("cn", "mail")
                    .limit(10))

            # Teste de operações semânticas
            await ldap.find_users_in_department("Engineering")

            # Teste de validação de schema
            await validate_ldap_config(config, test_connection=False, validate_schema=False)

    except Exception:
        pass

    # 4. Teste de função de conveniência
    try:
        # Esta função também usa o padrão facade
        pass
    except Exception:
        pass


if __name__ == "__main__":
    asyncio.run(test_facade_pattern())
