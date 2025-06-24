"""Enterprise LDAP Security Module with SSH Tunnels and Authentication.

This module provides comprehensive security features for LDAP operations,
including SSH tunnel management, advanced authentication, and security monitoring.

Architecture:
    Security module implementing security patterns for LDAP operations with
    SSH tunnel support and authentication management.

Key Features:
    - SSH Tunnel Management: Secure connections through SSH tunnels
    - Advanced Authentication: Multiple authentication methods
    - Security Monitoring: Authentication attempts and security events
    - Certificate Management: SSL/TLS certificate validation
    - Security Hardening: Security best practices implementation

Version: 1.0.0-enterprise
"""

from __future__ import annotations

import socket
import threading
import time
from contextlib import contextmanager
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from ldap_core_shared.utils.constants import (
    SSH_LOCAL_PORT_RANGE,
    SSH_TUNNEL_RETRY_ATTEMPTS,
    SSH_TUNNEL_TIMEOUT,
)
from ldap_core_shared.utils.performance import PerformanceMonitor


class SSHTunnelConfig(BaseModel):
    """SSH tunnel configuration."""
    
    model_config = ConfigDict(
        strict=True,
        extra="forbid",
        frozen=True,
        validate_assignment=True,
    )
    
    ssh_host: str
    ssh_port: int = Field(default=22, gt=0, lt=65536)
    ssh_username: str
    ssh_password: str | None = None
    ssh_key_file: str | None = None
    ssh_key_password: str | None = None
    
    # Tunnel settings
    local_bind_port: int | None = Field(default=None, gt=0, lt=65536)
    remote_host: str = "localhost"
    remote_port: int = Field(gt=0, lt=65536)
    
    # Security settings
    compression: bool = False
    timeout: int = Field(default=SSH_TUNNEL_TIMEOUT, gt=0)


class SSHTunnel:
    """SSH tunnel for secure LDAP connections."""
    
    def __init__(self, config: SSHTunnelConfig) -> None:
        """Initialize SSH tunnel.
        
        Args:
            config: SSH tunnel configuration
        """
        self.config = config
        self._tunnel = None
        self._local_port: int | None = None
        self._is_active = False
        self._performance_monitor = PerformanceMonitor("ssh_tunnel")
    
    def start(self) -> int:
        """Start SSH tunnel.
        
        Returns:
            int: Local port number
        """
        try:
            # Import here to avoid dependency issues if paramiko not installed
            from sshtunnel import SSHTunnelForwarder
        except ImportError as e:
            raise ImportError("sshtunnel package required for SSH tunnel support") from e
        
        start_time = time.time()
        
        try:
            # Determine local port
            if self.config.local_bind_port:
                local_port = self.config.local_bind_port
            else:
                local_port = self._find_free_port()
            
            # Create SSH tunnel
            tunnel_kwargs = {
                "ssh_address_or_host": (self.config.ssh_host, self.config.ssh_port),
                "ssh_username": self.config.ssh_username,
                "remote_bind_address": (self.config.remote_host, self.config.remote_port),
                "local_bind_address": ("127.0.0.1", local_port),
                "compression": self.config.compression,
            }
            
            # Add authentication method
            if self.config.ssh_password:
                tunnel_kwargs["ssh_password"] = self.config.ssh_password
            elif self.config.ssh_key_file:
                tunnel_kwargs["ssh_pkey"] = self.config.ssh_key_file
                if self.config.ssh_key_password:
                    tunnel_kwargs["ssh_private_key_password"] = self.config.ssh_key_password
            
            self._tunnel = SSHTunnelForwarder(**tunnel_kwargs)
            
            # Start tunnel
            self._tunnel.start()
            self._local_port = self._tunnel.local_bind_port
            self._is_active = True
            
            # Record successful start
            duration = time.time() - start_time
            self._performance_monitor.record_operation(duration, True)
            
            return self._local_port
        
        except Exception as e:
            duration = time.time() - start_time
            self._performance_monitor.record_operation(duration, False)
            raise RuntimeError(f"Failed to start SSH tunnel: {str(e)}") from e
    
    def stop(self) -> None:
        """Stop SSH tunnel."""
        if self._tunnel and self._is_active:
            try:
                self._tunnel.stop()
                self._is_active = False
                self._local_port = None
            except Exception:
                pass  # Ignore errors during shutdown
    
    @property
    def is_active(self) -> bool:
        """Check if tunnel is active."""
        return self._is_active and self._tunnel and self._tunnel.is_alive
    
    @property
    def local_port(self) -> int | None:
        """Get local port number."""
        return self._local_port
    
    def _find_free_port(self) -> int:
        """Find a free port in the allowed range."""
        start_port, end_port = SSH_LOCAL_PORT_RANGE
        
        for port in range(start_port, end_port + 1):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.bind(("127.0.0.1", port))
                    return port
            except OSError:
                continue
        
        raise RuntimeError("No free ports available in range")
    
    def __enter__(self):
        """Context manager entry."""
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.stop()


class AuthenticationManager:
    """Manage LDAP authentication with security features."""
    
    def __init__(self) -> None:
        """Initialize authentication manager."""
        self._performance_monitor = PerformanceMonitor("authentication")
        self._auth_attempts: dict[str, list[float]] = {}
        self._max_attempts = 5
        self._lockout_duration = 300  # 5 minutes
    
    def authenticate(
        self,
        bind_dn: str,
        password: str,
        connection,
    ) -> tuple[bool, str]:
        """Authenticate LDAP user with security monitoring.
        
        Args:
            bind_dn: Distinguished name to authenticate
            password: Password
            connection: LDAP connection
            
        Returns:
            tuple: (success, message)
        """
        start_time = time.time()
        
        # Check for account lockout
        if self._is_locked_out(bind_dn):
            return False, "Account temporarily locked due to failed attempts"
        
        try:
            # Attempt authentication
            success = connection.bind(bind_dn, password)
            duration = time.time() - start_time
            
            if success:
                # Clear failed attempts on successful auth
                self._clear_failed_attempts(bind_dn)
                self._performance_monitor.record_operation(duration, True)
                return True, "Authentication successful"
            else:
                # Record failed attempt
                self._record_failed_attempt(bind_dn)
                self._performance_monitor.record_operation(duration, False)
                return False, "Authentication failed"
        
        except Exception as e:
            duration = time.time() - start_time
            self._record_failed_attempt(bind_dn)
            self._performance_monitor.record_operation(duration, False)
            return False, f"Authentication error: {str(e)}"
    
    def _is_locked_out(self, bind_dn: str) -> bool:
        """Check if account is locked out."""
        if bind_dn not in self._auth_attempts:
            return False
        
        attempts = self._auth_attempts[bind_dn]
        current_time = time.time()
        
        # Remove old attempts outside lockout window
        attempts[:] = [t for t in attempts if current_time - t < self._lockout_duration]
        
        return len(attempts) >= self._max_attempts
    
    def _record_failed_attempt(self, bind_dn: str) -> None:
        """Record failed authentication attempt."""
        if bind_dn not in self._auth_attempts:
            self._auth_attempts[bind_dn] = []
        
        self._auth_attempts[bind_dn].append(time.time())
    
    def _clear_failed_attempts(self, bind_dn: str) -> None:
        """Clear failed attempts for user."""
        if bind_dn in self._auth_attempts:
            del self._auth_attempts[bind_dn]
    
    def get_auth_stats(self) -> dict[str, Any]:
        """Get authentication statistics."""
        metrics = self._performance_monitor.get_metrics()
        
        locked_accounts = sum(
            1 for attempts in self._auth_attempts.values()
            if len(attempts) >= self._max_attempts
        )
        
        return {
            "total_auth_attempts": metrics.operation_count,
            "successful_auths": metrics.success_count,
            "failed_auths": metrics.error_count,
            "success_rate": metrics.success_rate,
            "locked_accounts": locked_accounts,
            "average_auth_time": metrics.average_duration,
        }


class SecurityManager:
    """Comprehensive security management for LDAP operations."""
    
    def __init__(self) -> None:
        """Initialize security manager."""
        self.auth_manager = AuthenticationManager()
        self._active_tunnels: dict[str, SSHTunnel] = {}
        self._security_events: list[dict[str, Any]] = []
    
    @contextmanager
    def secure_tunnel(self, config: SSHTunnelConfig, tunnel_id: str | None = None):
        """Create secure SSH tunnel context.
        
        Args:
            config: SSH tunnel configuration
            tunnel_id: Optional tunnel identifier
            
        Yields:
            SSHTunnel: Active SSH tunnel
        """
        if tunnel_id is None:
            tunnel_id = f"tunnel_{int(time.time() * 1000)}"
        
        tunnel = SSHTunnel(config)
        
        try:
            tunnel.start()
            self._active_tunnels[tunnel_id] = tunnel
            
            self._log_security_event(
                "tunnel_started",
                {
                    "tunnel_id": tunnel_id,
                    "ssh_host": config.ssh_host,
                    "local_port": tunnel.local_port,
                }
            )
            
            yield tunnel
        
        finally:
            tunnel.stop()
            if tunnel_id in self._active_tunnels:
                del self._active_tunnels[tunnel_id]
            
            self._log_security_event(
                "tunnel_stopped",
                {
                    "tunnel_id": tunnel_id,
                    "ssh_host": config.ssh_host,
                }
            )
    
    def create_tunnel(self, config: SSHTunnelConfig) -> SSHTunnel:
        """Create and start SSH tunnel.
        
        Args:
            config: SSH tunnel configuration
            
        Returns:
            SSHTunnel: Active tunnel
        """
        tunnel = SSHTunnel(config)
        tunnel.start()
        
        tunnel_id = f"tunnel_{id(tunnel)}"
        self._active_tunnels[tunnel_id] = tunnel
        
        self._log_security_event(
            "tunnel_created",
            {
                "tunnel_id": tunnel_id,
                "ssh_host": config.ssh_host,
                "local_port": tunnel.local_port,
            }
        )
        
        return tunnel
    
    def close_tunnel(self, tunnel: SSHTunnel) -> None:
        """Close SSH tunnel.
        
        Args:
            tunnel: Tunnel to close
        """
        tunnel.stop()
        
        # Remove from active tunnels
        tunnel_id = None
        for tid, t in self._active_tunnels.items():
            if t is tunnel:
                tunnel_id = tid
                break
        
        if tunnel_id:
            del self._active_tunnels[tunnel_id]
            
            self._log_security_event(
                "tunnel_closed",
                {"tunnel_id": tunnel_id}
            )
    
    def close_all_tunnels(self) -> None:
        """Close all active tunnels."""
        for tunnel_id, tunnel in list(self._active_tunnels.items()):
            tunnel.stop()
            self._log_security_event(
                "tunnel_force_closed",
                {"tunnel_id": tunnel_id}
            )
        
        self._active_tunnels.clear()
    
    def get_active_tunnels(self) -> dict[str, dict[str, Any]]:
        """Get information about active tunnels."""
        active_info = {}
        
        for tunnel_id, tunnel in self._active_tunnels.items():
            active_info[tunnel_id] = {
                "is_active": tunnel.is_active,
                "local_port": tunnel.local_port,
                "ssh_host": tunnel.config.ssh_host,
                "ssh_port": tunnel.config.ssh_port,
                "remote_host": tunnel.config.remote_host,
                "remote_port": tunnel.config.remote_port,
            }
        
        return active_info
    
    def validate_ssl_certificate(self, host: str, port: int) -> dict[str, Any]:
        """Validate SSL certificate for LDAP server.
        
        Args:
            host: LDAP server host
            port: LDAP server port
            
        Returns:
            dict: Certificate validation results
        """
        try:
            import ssl
            
            context = ssl.create_default_context()
            
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    
                    return {
                        "valid": True,
                        "subject": dict(x[0] for x in cert.get("subject", [])),
                        "issuer": dict(x[0] for x in cert.get("issuer", [])),
                        "not_before": cert.get("notBefore"),
                        "not_after": cert.get("notAfter"),
                        "serial_number": cert.get("serialNumber"),
                        "version": cert.get("version"),
                    }
        
        except Exception as e:
            return {
                "valid": False,
                "error": str(e),
            }
    
    def get_security_events(self, limit: int = 100) -> list[dict[str, Any]]:
        """Get recent security events.
        
        Args:
            limit: Maximum number of events to return
            
        Returns:
            list: Security events
        """
        return self._security_events[-limit:]
    
    def get_security_summary(self) -> dict[str, Any]:
        """Get security summary.
        
        Returns:
            dict: Security summary
        """
        auth_stats = self.auth_manager.get_auth_stats()
        
        return {
            "active_tunnels": len(self._active_tunnels),
            "security_events": len(self._security_events),
            "authentication": auth_stats,
            "tunnel_info": self.get_active_tunnels(),
        }
    
    def _log_security_event(self, event_type: str, details: dict[str, Any]) -> None:
        """Log security event.
        
        Args:
            event_type: Type of security event
            details: Event details
        """
        event = {
            "event_type": event_type,
            "timestamp": time.time(),
            "details": details,
        }
        
        self._security_events.append(event)
        
        # Keep only recent events (last 1000)
        if len(self._security_events) > 1000:
            self._security_events = self._security_events[-1000:]


# Global security manager instance
_security_manager: SecurityManager | None = None


def get_security_manager() -> SecurityManager:
    """Get global security manager instance."""
    global _security_manager
    if _security_manager is None:
        _security_manager = SecurityManager()
    return _security_manager


def create_ssh_tunnel(config: SSHTunnelConfig) -> SSHTunnel:
    """Create SSH tunnel using global security manager.
    
    Args:
        config: SSH tunnel configuration
        
    Returns:
        SSHTunnel: Active tunnel
    """
    return get_security_manager().create_tunnel(config)


def close_ssh_tunnel(tunnel: SSHTunnel) -> None:
    """Close SSH tunnel using global security manager.
    
    Args:
        tunnel: Tunnel to close
    """
    get_security_manager().close_tunnel(tunnel)
