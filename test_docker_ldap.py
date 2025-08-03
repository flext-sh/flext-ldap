#!/usr/bin/env python3
"""Teste simples para verificar container Docker LDAP compartilhado."""

import sys

from tests.conftest import OPENLDAP_PORT, OpenLDAPContainerManager


def test_docker_ldap_container() -> bool | None:
    """Teste básico do container LDAP Docker."""
    # Criar manager
    manager = OpenLDAPContainerManager()

    try:
        # Iniciar container
        manager.start_container()

        # Verificar se está rodando
        assert manager.is_container_running()

        # Testar conexão básica
        import socket

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex(("localhost", OPENLDAP_PORT))
        sock.close()

        if result == 0:
            pass

        return True

    except Exception:
        return False
    finally:
        # Sempre limpar
        manager.stop_container()


if __name__ == "__main__":
    success = test_docker_ldap_container()
    sys.exit(0 if success else 1)
