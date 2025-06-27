#!/usr/bin/env python3
"""🚀 DEMO: API LIMPA E ORGANIZADA - Interface KISS/SOLID/DRY.

Este exemplo demonstra como a nova API limpa organiza TODA a biblioteca
ldap-core-shared em categorias lógicas e intuitivas.

BENEFÍCIOS DA NOVA API:
- 🎯 KISS: Interface simples e intuitiva
- 🏗️ SOLID: Responsabilidade única por categoria
- 🔄 DRY: Delegação para módulos existentes
- 📚 ORGANIZAÇÃO: Funcionalidades agrupadas logicamente
- 🚀 PRODUTIVIDADE: Discover fácil via autocomplete

Usage:
    python examples/clean_api_demo.py
"""

import asyncio

from ldap_core_shared import LDAP, LDAPConfig


async def demo_clean_api() -> None:
    """Demonstração da nova API limpa e organizada."""
    # Configuração simplificada
    config = LDAPConfig(
        server="ldap.example.com",
        auth_dn="cn=admin,dc=example,dc=com",
        auth_password="password",
        base_dn="dc=example,dc=com",
    )

    # Usar a nova API limpa
    async with LDAP(config) as ldap:
        # ================================================================
        # 🔍 CATEGORIA: SEARCH & DISCOVERY
        # ================================================================

        # Busca simples de usuários
        await ldap.search().users("john*")

        # Busca simples de grupos
        await ldap.search().groups("admin*")

        # Busca avançada
        await ldap.search().advanced(
            filter_expr="(objectClass=person)", attributes=["cn", "mail", "department"]
        )

        # ================================================================
        # 👥 CATEGORIA: USERS
        # ================================================================

        # Buscar usuário por email
        user_result = await ldap.users().find_by_email("john@example.com")
        if user_result.success:
            pass

        # Buscar usuário por nome
        await ldap.users().find_by_name("john")

        # Operações de usuário
        await ldap.users().create("cn=newuser,dc=example,dc=com", {"cn": ["newuser"]})

        await ldap.users().update(
            "cn=newuser,dc=example,dc=com", {"description": ["Updated user"]}
        )

        await ldap.users().delete("cn=newuser,dc=example,dc=com")

        # ================================================================
        # 👥 CATEGORIA: GROUPS
        # ================================================================

        # Buscar grupo por nome
        await ldap.groups().find_by_name("admins")

        # Obter membros do grupo
        await ldap.groups().get_members("cn=admins,dc=example,dc=com")

        # ================================================================
        # 📋 CATEGORIA: SCHEMA
        # ================================================================

        # Descobrir schema do servidor
        schema_result = await ldap.schema().discover()
        if schema_result.success:
            pass

        # Validar entrada
        test_entry = {
            "dn": "cn=test,dc=example,dc=com",
            "objectClass": ["person"],
            "cn": ["test"],
        }
        await ldap.schema().validate_entry(test_entry)

        # ================================================================
        # 📄 CATEGORIA: LDIF
        # ================================================================

        # Exemplo de processamento LDIF
        ldif_content = """dn: cn=test,dc=example,dc=com
objectClass: person
cn: test
sn: Test User
"""
        await ldap.ldif().parse_content(ldif_content)

        # Processar arquivo LDIF (simulado)
        await ldap.ldif().parse_file("/tmp/test.ldif")

        # Escrever arquivo LDIF
        entries = [{"dn": "cn=user1,dc=example,dc=com", "cn": ["user1"]}]
        await ldap.ldif().write_file(entries, "/tmp/output.ldif")

        # ================================================================
        # 📊 CATEGORIA: ASN.1
        # ================================================================

        # Operações ASN.1
        data = {"messageID": 1, "operation": "search"}
        ber_encode_result = ldap.asn1().encode_ber(data)

        if ber_encode_result.success:
            ldap.asn1().decode_ber(ber_encode_result.data)

        ldap.asn1().encode_der(data)

        # ================================================================
        # 🔐 CATEGORIA: SASL
        # ================================================================

        # Listar mecanismos SASL
        mechanisms_result = ldap.sasl().list_mechanisms()
        if mechanisms_result.success:
            pass

        # Simular autenticação SASL
        await ldap.sasl().bind_external()

        # ================================================================
        # 🎛️ CATEGORIA: CONTROLS
        # ================================================================

        # Criar controles
        ldap.controls().create_paged_results(1000)

        ldap.controls().create_server_side_sort(["cn", "mail"])

        # ================================================================
        # 🔌 CATEGORIA: EXTENSIONS
        # ================================================================

        # Descobrir identidade
        identity_result = await ldap.extensions().who_am_i()
        if identity_result.success:
            pass

        # Start TLS
        await ldap.extensions().start_tls()

        # ================================================================
        # 🌐 CATEGORIA: PROTOCOLS
        # ================================================================

        # Analisar URL LDAP
        url_result = ldap.protocols().parse_ldap_url(
            "ldap://server.com/dc=example,dc=com"
        )
        if url_result.success:
            pass

        # Conectar via LDAPS (simulado)
        await ldap.protocols().connect_ldaps("secure.example.com", 636)

        # ================================================================
        # 🛠️ CATEGORIA: UTILITIES
        # ================================================================

        # Analisar DN
        ldap.utilities().parse_dn("cn=user,ou=people,dc=example,dc=com")

        # Normalizar DN
        normalize_result = ldap.utilities().normalize_dn(
            "CN=User, OU=People, DC=Example, DC=Com"
        )
        if normalize_result.success:
            pass

        # Validar email
        ldap.utilities().validate_email("user@example.com")

        # ================================================================
        # ⚡ CATEGORIA: PERFORMANCE
        # ================================================================

        # Criar monitor de performance
        ldap.performance().create_monitor("demo_operations")

        # Busca em lote
        search_configs = [
            {"filter": "(cn=user1)", "base": "dc=example,dc=com"},
            {"filter": "(cn=user2)", "base": "dc=example,dc=com"},
        ]
        await ldap.performance().bulk_search(search_configs)

        # ================================================================
        # 🛠️ CATEGORIA: ADMIN
        # ================================================================

        # Obter capacidades do servidor
        capabilities = await ldap.admin().get_server_capabilities()
        if capabilities.success:
            pass

        # Obter Root DSE
        await ldap.admin().get_root_dse()


def demo_convenience_functions() -> None:
    """Demonstração das funções de conveniência."""


async def demo_comparison() -> None:
    """Demonstração comparando a API antiga vs nova."""


if __name__ == "__main__":
    try:
        # Executar demo principal
        asyncio.run(demo_clean_api())

        # Mostrar funções de conveniência
        demo_convenience_functions()

        # Mostrar comparação
        asyncio.run(demo_comparison())

    except KeyboardInterrupt:
        pass
    except Exception:
        pass
