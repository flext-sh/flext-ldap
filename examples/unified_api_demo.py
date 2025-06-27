#!/usr/bin/env python3
"""🚀 DEMO: API UNIFICADA - Todas as funcionalidades organizadas de forma intuitiva.

Este exemplo demonstra como a API unificada organiza TODA a biblioteca
ldap-core-shared em categorias lógicas e intuitivas, seguindo KISS/SOLID/DRY.

Principais benefícios:
- 🎯 KISS: Interface simples e intuitiva
- 🏗️ SOLID: Responsabilidade única por categoria
- 🔄 DRY: Delegação para módulos existentes
- 📚 ORGANIZAÇÃO: Sem milhares de classes e helpers espalhados

Usage:
    python examples/unified_api_demo.py
"""

import asyncio

from ldap_core_shared import LDAP, LDAPConfig


async def demo_unified_api() -> None:
    """Demonstração da API unificada organizada por categorias."""
    # Configuração simplificada
    config = LDAPConfig(
        server="ldap.example.com",
        auth_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
        auth_password="password",
        base_dn="dc=example,dc=com",
    )

    # Usar a API unificada
    async with LDAP(config) as ldap:
        # ================================================================
        # 🔍 CATEGORIA: SEARCH & DISCOVERY
        # ================================================================

        # Busca simples de usuários
        await ldap.search_category().users("john*")

        # Busca simples de grupos
        await ldap.search_category().groups("REDACTED_LDAP_BIND_PASSWORD*")

        # Busca avançada com controle total
        await ldap.search_category().advanced(
            filter_expr="(objectClass=person)", attributes=["cn", "mail", "department"]
        )

        # ================================================================
        # 👥 CATEGORIA: USERS
        # ================================================================

        # Buscar usuário por email
        await ldap.users_category().find_by_email("john@example.com")

        # Buscar usuários por departamento
        await ldap.users_category().find_by_department("IT")

        # ================================================================
        # 👥 CATEGORIA: GROUPS
        # ================================================================

        # Buscar grupo por nome
        await ldap.groups_category().find_by_name("REDACTED_LDAP_BIND_PASSWORDs")

        # Encontrar grupos vazios
        await ldap.groups_category().find_empty()

        # ================================================================
        # 📋 CATEGORIA: SCHEMA
        # ================================================================

        # Descobrir schema do servidor
        await ldap.schema_category().discover()

        # ================================================================
        # 📄 CATEGORIA: LDIF
        # ================================================================

        # Exemplo de processamento LDIF
        ldif_content = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
sn: Test User
"""
        await ldap.ldif_category().parse_content(ldif_content)

        # ================================================================
        # ⚡ CATEGORIA: PERFORMANCE
        # ================================================================

        # Criar monitor de performance
        ldap.performance_category().create_monitor("demo_operations")

        # ================================================================
        # 🔒 CATEGORIA: SECURITY
        # ================================================================

        # Descobrir identidade atual
        identity_result = await ldap.security_category().who_am_i()
        if identity_result.success:
            pass

        # ================================================================
        # 🔄 CATEGORIA: MIGRATION
        # ================================================================

        # Criar migração simplificada
        ldap.migration_category().create("/source", "/output")

        # ================================================================
        # 🛠️ CATEGORIA: ADMIN
        # ================================================================

        # Obter capacidades do servidor
        await ldap.REDACTED_LDAP_BIND_PASSWORD_category().get_server_capabilities()

        # Obter Root DSE
        await ldap.REDACTED_LDAP_BIND_PASSWORD_category().get_root_dse()


def demo_simple_usage() -> None:
    """Demonstração de uso simples da API unificada."""


if __name__ == "__main__":
    try:
        # Executar demo principal
        asyncio.run(demo_unified_api())

        # Mostrar exemplo de uso
        demo_simple_usage()

    except KeyboardInterrupt:
        pass
    except Exception:
        pass
