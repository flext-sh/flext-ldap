#!/usr/bin/env python3
"""
Teste simples para verificar container Docker LDAP compartilhado
"""
import pytest
from tests.conftest import OpenLDAPContainerManager, OPENLDAP_PORT

def test_docker_ldap_container():
    """Teste básico do container LDAP Docker"""
    print("Iniciando teste do container LDAP...")
    
    # Criar manager
    manager = OpenLDAPContainerManager()
    
    try:
        # Iniciar container
        print("Iniciando container LDAP...")
        container = manager.start_container()
        
        print(f"Container iniciado: {container.name}")
        print(f"Status: {container.status}")
        print(f"Porta: {OPENLDAP_PORT}")
        
        # Verificar se está rodando
        assert manager.is_container_running()
        print("✅ Container LDAP está rodando!")
        
        # Testar conexão básica
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex(('localhost', OPENLDAP_PORT))
        sock.close()
        
        if result == 0:
            print("✅ Porta LDAP está acessível!")
        else:
            print(f"⚠️  Porta LDAP não conectou: {result}")
        
        return True
        
    except Exception as e:
        print(f"❌ Erro no teste: {e}")
        return False
    finally:
        # Sempre limpar
        manager.stop_container()
        print("Container LDAP parado.")

if __name__ == "__main__":
    success = test_docker_ldap_container()
    exit(0 if success else 1)