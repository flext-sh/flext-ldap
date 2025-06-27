"""Tests for LDAP Start TLS Extension Implementation.

This module provides comprehensive test coverage for the Start TLS extended
operation implementation including TLS configuration, certificate validation,
and security management with enterprise-grade validation.

Test Coverage:
    - TLSVerifyMode: Certificate verification mode enumeration
    - TLSVersion: Supported TLS/SSL version enumeration
    - TLSConfiguration: TLS/SSL configuration and validation
    - StartTLSResult: Result processing and security information
    - StartTLSExtension: Extended operation implementation
    - TLSUpgradeManager: Advanced TLS upgrade management
    - Convenience functions and configuration builders

Security Testing:
    - Certificate validation and verification modes
    - Client certificate authentication configuration
    - TLS version and cipher suite validation
    - Hostname verification and security settings
    - Insecure configuration warnings and protection

Integration Testing:
    - RFC 4511 and RFC 2830 compliance validation
    - Extension request/response encoding/decoding
    - TLS configuration parameter validation
    - Error handling and exception management
    - Security information extraction and display
"""

from __future__ import annotations

import pytest

from ldap_core_shared.extensions.base import ExtensionOIDs
from ldap_core_shared.extensions.start_tls import (
    StartTLSExtension,
    StartTLSResult,
    TLSConfiguration,
    TLSUpgradeManager,
    TLSVerifyMode,
    TLSVersion,
    start_tls,
    start_tls_insecure,
    start_tls_with_ca,
    start_tls_with_client_cert,
)


class TestTLSVerifyMode:
    """Test cases for TLSVerifyMode enumeration."""

    def test_verify_mode_values(self) -> None:
        """Test TLS verify mode enumeration values."""
        assert TLSVerifyMode.NONE.value == "none"
        assert TLSVerifyMode.OPTIONAL.value == "optional"
        assert TLSVerifyMode.REQUIRED.value == "required"

    def test_verify_mode_completeness(self) -> None:
        """Test that all expected verify modes are defined."""
        expected_modes = {"NONE", "OPTIONAL", "REQUIRED"}
        actual_modes = {member.name for member in TLSVerifyMode}
        assert actual_modes == expected_modes


class TestTLSVersion:
    """Test cases for TLSVersion enumeration."""

    def test_tls_version_values(self) -> None:
        """Test TLS version enumeration values."""
        assert TLSVersion.SSL_V23.value == "SSLv23"
        assert TLSVersion.TLS_V1.value == "TLSv1"
        assert TLSVersion.TLS_V1_1.value == "TLSv1.1"
        assert TLSVersion.TLS_V1_2.value == "TLSv1.2"
        assert TLSVersion.TLS_V1_3.value == "TLSv1.3"

    def test_tls_version_completeness(self) -> None:
        """Test that all expected TLS versions are defined."""
        expected_versions = {"SSL_V23", "TLS_V1", "TLS_V1_1", "TLS_V1_2", "TLS_V1_3"}
        actual_versions = {member.name for member in TLSVersion}
        assert actual_versions == expected_versions


class TestTLSConfiguration:
    """Test cases for TLSConfiguration."""

    def test_default_configuration(self) -> None:
        """Test default TLS configuration creation."""
        config = TLSConfiguration()

        assert config.ca_cert_file is None
        assert config.ca_cert_dir is None
        assert config.cert_file is None
        assert config.key_file is None
        assert config.verify_mode == TLSVerifyMode.REQUIRED
        assert config.check_hostname is True
        assert config.tls_version == TLSVersion.TLS_V1_2
        assert config.cipher_suites is None

    def test_configuration_with_ca_cert(self) -> None:
        """Test configuration with CA certificate."""
        config = TLSConfiguration(
            ca_cert_file="/path/to/ca.pem",
            ca_cert_dir="/path/to/ca/dir",
        )

        assert config.ca_cert_file == "/path/to/ca.pem"
        assert config.ca_cert_dir == "/path/to/ca/dir"
        assert config.verify_mode == TLSVerifyMode.REQUIRED

    def test_configuration_with_client_cert(self) -> None:
        """Test configuration with client certificate."""
        config = TLSConfiguration(
            cert_file="/path/to/client.pem",
            key_file="/path/to/client.key",
        )

        assert config.cert_file == "/path/to/client.pem"
        assert config.key_file == "/path/to/client.key"
        assert config.has_client_cert() is True

    def test_configuration_validation_cert_without_key(self) -> None:
        """Test validation error when cert provided without key."""
        with pytest.raises(
            ValueError, match="Client certificate requires corresponding private key"
        ):
            TLSConfiguration(cert_file="/path/to/client.pem")

    def test_configuration_validation_key_without_cert(self) -> None:
        """Test validation error when key provided without cert."""
        with pytest.raises(
            ValueError, match="Private key requires corresponding client certificate"
        ):
            TLSConfiguration(key_file="/path/to/client.key")

    def test_configuration_with_security_settings(self) -> None:
        """Test configuration with custom security settings."""
        config = TLSConfiguration(
            verify_mode=TLSVerifyMode.OPTIONAL,
            check_hostname=False,
            tls_version=TLSVersion.TLS_V1_3,
            cipher_suites="ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM",
        )

        assert config.verify_mode == TLSVerifyMode.OPTIONAL
        assert config.check_hostname is False
        assert config.tls_version == TLSVersion.TLS_V1_3
        assert config.cipher_suites == "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM"

    def test_has_client_cert_method(self) -> None:
        """Test has_client_cert method."""
        # Without client cert
        config1 = TLSConfiguration()
        assert config1.has_client_cert() is False

        # With client cert
        config2 = TLSConfiguration(
            cert_file="/path/to/client.pem",
            key_file="/path/to/client.key",
        )
        assert config2.has_client_cert() is True

        # With only cert file (invalid, but method should still work)
        config3 = TLSConfiguration(ca_cert_file="/path/to/ca.pem")
        assert config3.has_client_cert() is False

    def test_is_verification_enabled_method(self) -> None:
        """Test is_verification_enabled method."""
        # Verification enabled (default)
        config1 = TLSConfiguration()
        assert config1.is_verification_enabled() is True

        # Verification required
        config2 = TLSConfiguration(verify_mode=TLSVerifyMode.REQUIRED)
        assert config2.is_verification_enabled() is True

        # Verification optional
        config3 = TLSConfiguration(verify_mode=TLSVerifyMode.OPTIONAL)
        assert config3.is_verification_enabled() is True

        # Verification disabled
        config4 = TLSConfiguration(verify_mode=TLSVerifyMode.NONE)
        assert config4.is_verification_enabled() is False

    def test_get_ssl_context_params_basic(self) -> None:
        """Test getting SSL context parameters for basic configuration."""
        config = TLSConfiguration()
        params = config.get_ssl_context_params()

        expected_params = {
            "verify_mode": "required",
            "check_hostname": True,
            "minimum_version": "TLSv1.2",
        }

        assert params == expected_params

    def test_get_ssl_context_params_with_ca_cert(self) -> None:
        """Test getting SSL context parameters with CA certificate."""
        config = TLSConfiguration(
            ca_cert_file="/path/to/ca.pem",
            ca_cert_dir="/path/to/ca/dir",
        )
        params = config.get_ssl_context_params()

        assert params["ca_cert_file"] == "/path/to/ca.pem"
        assert params["ca_cert_dir"] == "/path/to/ca/dir"

    def test_get_ssl_context_params_with_client_cert(self) -> None:
        """Test getting SSL context parameters with client certificate."""
        config = TLSConfiguration(
            cert_file="/path/to/client.pem",
            key_file="/path/to/client.key",
        )
        params = config.get_ssl_context_params()

        assert params["cert_file"] == "/path/to/client.pem"
        assert params["key_file"] == "/path/to/client.key"

    def test_get_ssl_context_params_with_cipher_suites(self) -> None:
        """Test getting SSL context parameters with cipher suites."""
        config = TLSConfiguration(
            cipher_suites="HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA",
        )
        params = config.get_ssl_context_params()

        assert (
            params["cipher_suites"]
            == "HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA"
        )

    def test_get_ssl_context_params_complete(self) -> None:
        """Test getting SSL context parameters with complete configuration."""
        config = TLSConfiguration(
            ca_cert_file="/path/to/ca.pem",
            cert_file="/path/to/client.pem",
            key_file="/path/to/client.key",
            verify_mode=TLSVerifyMode.OPTIONAL,
            check_hostname=False,
            tls_version=TLSVersion.TLS_V1_3,
            cipher_suites="ECDHE+AESGCM",
        )
        params = config.get_ssl_context_params()

        expected_params = {
            "verify_mode": "optional",
            "check_hostname": False,
            "minimum_version": "TLSv1.3",
            "ca_cert_file": "/path/to/ca.pem",
            "cert_file": "/path/to/client.pem",
            "key_file": "/path/to/client.key",
            "cipher_suites": "ECDHE+AESGCM",
        }

        assert params == expected_params


class TestStartTLSResult:
    """Test cases for StartTLSResult."""

    def test_result_creation_default(self) -> None:
        """Test creating result with default values."""
        result = StartTLSResult(result_code=0)

        assert result.result_code == 0
        assert result.tls_established is False
        assert result.tls_version is None
        assert result.cipher_suite is None
        assert result.peer_certificate is None
        assert result.connection_encrypted is False

    def test_result_creation_successful_tls(self) -> None:
        """Test creating result for successful TLS establishment."""
        peer_cert = {
            "subject": {"CN": "ldap.example.com"},
            "issuer": {"CN": "Example CA"},
            "notBefore": "Jan  1 00:00:00 2024 GMT",
            "notAfter": "Jan  1 00:00:00 2025 GMT",
        }

        result = StartTLSResult(
            result_code=0,
            tls_established=True,
            tls_version="TLSv1.3",
            cipher_suite="ECDHE-RSA-AES256-GCM-SHA384",
            peer_certificate=peer_cert,
            connection_encrypted=True,
        )

        assert result.result_code == 0
        assert result.tls_established is True
        assert result.tls_version == "TLSv1.3"
        assert result.cipher_suite == "ECDHE-RSA-AES256-GCM-SHA384"
        assert result.peer_certificate == peer_cert
        assert result.connection_encrypted is True

    def test_is_tls_active_method(self) -> None:
        """Test is_tls_active method."""
        # Not active - default state
        result1 = StartTLSResult(result_code=0)
        assert result1.is_tls_active() is False

        # TLS established but not encrypted
        result2 = StartTLSResult(
            result_code=0,
            tls_established=True,
            connection_encrypted=False,
        )
        assert result2.is_tls_active() is False

        # Encrypted but TLS not established
        result3 = StartTLSResult(
            result_code=0,
            tls_established=False,
            connection_encrypted=True,
        )
        assert result3.is_tls_active() is False

        # Both TLS established and encrypted
        result4 = StartTLSResult(
            result_code=0,
            tls_established=True,
            connection_encrypted=True,
        )
        assert result4.is_tls_active() is True

    def test_get_security_info_method(self) -> None:
        """Test get_security_info method."""
        peer_cert = {"subject": {"CN": "ldap.example.com"}}

        result = StartTLSResult(
            result_code=0,
            tls_established=True,
            tls_version="TLSv1.2",
            cipher_suite="ECDHE-RSA-AES128-GCM-SHA256",
            peer_certificate=peer_cert,
            connection_encrypted=True,
        )

        security_info = result.get_security_info()

        expected_info = {
            "tls_active": True,
            "tls_version": "TLSv1.2",
            "cipher_suite": "ECDHE-RSA-AES128-GCM-SHA256",
            "peer_certificate": peer_cert,
        }

        assert security_info == expected_info

    def test_str_representation_success(self) -> None:
        """Test string representation for successful result."""
        result = StartTLSResult(
            result_code=0,
            tls_established=True,
            tls_version="TLSv1.3",
            connection_encrypted=True,
        )

        str_repr = str(result)
        assert str_repr == "Start TLS successful (version: TLSv1.3)"

    def test_str_representation_partial_success(self) -> None:
        """Test string representation for partial success."""
        result = StartTLSResult(
            result_code=0,
            tls_established=True,
            connection_encrypted=False,
        )

        str_repr = str(result)
        assert str_repr == "Start TLS completed"

    def test_str_representation_failure(self) -> None:
        """Test string representation for failed result."""
        result = StartTLSResult(
            result_code=1,
            error_message="TLS handshake failed",
            tls_established=False,
        )

        str_repr = str(result)
        assert "Start TLS failed" in str_repr
        assert "TLS handshake failed" in str_repr


class TestStartTLSExtension:
    """Test cases for StartTLSExtension."""

    def test_extension_initialization_default(self) -> None:
        """Test extension initialization with default configuration."""
        extension = StartTLSExtension()

        assert extension.request_name == ExtensionOIDs.START_TLS
        assert extension.request_value is None
        assert isinstance(extension.tls_config, TLSConfiguration)
        assert extension.tls_config.verify_mode == TLSVerifyMode.REQUIRED

    def test_extension_initialization_with_config(self) -> None:
        """Test extension initialization with custom configuration."""
        tls_config = TLSConfiguration(
            ca_cert_file="/path/to/ca.pem",
            verify_mode=TLSVerifyMode.OPTIONAL,
        )
        extension = StartTLSExtension(tls_config=tls_config)

        assert extension.tls_config == tls_config
        assert extension.tls_config.ca_cert_file == "/path/to/ca.pem"
        assert extension.tls_config.verify_mode == TLSVerifyMode.OPTIONAL

    def test_encode_request_value(self) -> None:
        """Test request value encoding."""
        extension = StartTLSExtension()

        encoded = extension.encode_request_value()
        assert encoded is None

    def test_decode_response_value_success(self) -> None:
        """Test decoding successful response value."""
        result = StartTLSExtension.decode_response_value(None, None)

        assert isinstance(result, StartTLSResult)
        assert result.result_code == 0
        assert result.tls_established is True
        assert result.connection_encrypted is True

    def test_decode_response_value_with_data(self) -> None:
        """Test decoding response value with unexpected data."""
        # Start TLS should not have response data, but should handle gracefully
        result = StartTLSExtension.decode_response_value(None, b"unexpected")

        assert isinstance(result, StartTLSResult)
        assert result.tls_established is True

    def test_create_class_method(self) -> None:
        """Test create class method."""
        extension = StartTLSExtension.create()

        assert isinstance(extension, StartTLSExtension)
        assert extension.request_name == ExtensionOIDs.START_TLS

    def test_create_with_config(self) -> None:
        """Test create class method with configuration."""
        tls_config = TLSConfiguration(verify_mode=TLSVerifyMode.NONE)
        extension = StartTLSExtension.create(tls_config=tls_config)

        assert extension.tls_config == tls_config

    def test_with_default_config_class_method(self) -> None:
        """Test with_default_config class method."""
        extension = StartTLSExtension.with_default_config()

        assert isinstance(extension, StartTLSExtension)
        assert extension.tls_config.verify_mode == TLSVerifyMode.REQUIRED
        assert extension.tls_config.check_hostname is True

    def test_with_client_cert_class_method(self) -> None:
        """Test with_client_cert class method."""
        extension = StartTLSExtension.with_client_cert(
            cert_file="/path/to/client.pem",
            key_file="/path/to/client.key",
            ca_cert_file="/path/to/ca.pem",
        )

        assert extension.tls_config.cert_file == "/path/to/client.pem"
        assert extension.tls_config.key_file == "/path/to/client.key"
        assert extension.tls_config.ca_cert_file == "/path/to/ca.pem"
        assert extension.tls_config.verify_mode == TLSVerifyMode.REQUIRED

    def test_with_client_cert_no_ca(self) -> None:
        """Test with_client_cert class method without CA certificate."""
        extension = StartTLSExtension.with_client_cert(
            cert_file="/path/to/client.pem",
            key_file="/path/to/client.key",
        )

        assert extension.tls_config.cert_file == "/path/to/client.pem"
        assert extension.tls_config.key_file == "/path/to/client.key"
        assert extension.tls_config.ca_cert_file is None

    def test_with_ca_verification_class_method(self) -> None:
        """Test with_ca_verification class method."""
        extension = StartTLSExtension.with_ca_verification(
            ca_cert_file="/path/to/ca.pem",
            verify_hostname=True,
        )

        assert extension.tls_config.ca_cert_file == "/path/to/ca.pem"
        assert extension.tls_config.verify_mode == TLSVerifyMode.REQUIRED
        assert extension.tls_config.check_hostname is True

    def test_with_ca_verification_no_hostname(self) -> None:
        """Test with_ca_verification class method without hostname verification."""
        extension = StartTLSExtension.with_ca_verification(
            ca_cert_file="/path/to/ca.pem",
            verify_hostname=False,
        )

        assert extension.tls_config.ca_cert_file == "/path/to/ca.pem"
        assert extension.tls_config.check_hostname is False

    def test_insecure_class_method(self) -> None:
        """Test insecure class method."""
        extension = StartTLSExtension.insecure()

        assert extension.tls_config.verify_mode == TLSVerifyMode.NONE
        assert extension.tls_config.check_hostname is False

    def test_get_tls_config_method(self) -> None:
        """Test get_tls_config method."""
        tls_config = TLSConfiguration(verify_mode=TLSVerifyMode.OPTIONAL)
        extension = StartTLSExtension(tls_config=tls_config)

        retrieved_config = extension.get_tls_config()
        assert retrieved_config == tls_config

    def test_get_tls_config_none(self) -> None:
        """Test get_tls_config method when config is None."""
        extension = StartTLSExtension()
        extension.tls_config = None

        retrieved_config = extension.get_tls_config()
        assert isinstance(retrieved_config, TLSConfiguration)
        assert retrieved_config.verify_mode == TLSVerifyMode.REQUIRED

    def test_is_client_cert_enabled_method(self) -> None:
        """Test is_client_cert_enabled method."""
        # Without client cert
        extension1 = StartTLSExtension()
        assert extension1.is_client_cert_enabled() is False

        # With client cert
        extension2 = StartTLSExtension.with_client_cert(
            cert_file="/path/to/client.pem",
            key_file="/path/to/client.key",
        )
        assert extension2.is_client_cert_enabled() is True

    def test_is_verification_enabled_method(self) -> None:
        """Test is_verification_enabled method."""
        # Verification enabled (default)
        extension1 = StartTLSExtension()
        assert extension1.is_verification_enabled() is True

        # Verification disabled
        extension2 = StartTLSExtension.insecure()
        assert extension2.is_verification_enabled() is False

    def test_str_representation_default(self) -> None:
        """Test string representation for default configuration."""
        extension = StartTLSExtension()

        str_repr = str(extension)
        assert str_repr == "StartTLS(verify)"

    def test_str_representation_client_cert(self) -> None:
        """Test string representation with client certificate."""
        extension = StartTLSExtension.with_client_cert(
            cert_file="/path/to/client.pem",
            key_file="/path/to/client.key",
        )

        str_repr = str(extension)
        assert "client-cert" in str_repr
        assert "verify" in str_repr

    def test_str_representation_insecure(self) -> None:
        """Test string representation for insecure configuration."""
        extension = StartTLSExtension.insecure()

        str_repr = str(extension)
        assert str_repr == "StartTLS(no-verify)"

    def test_oid_validation(self) -> None:
        """Test that the correct OID is used."""
        extension = StartTLSExtension()

        # START_TLS OID should be the standard RFC 4511/2830 OID
        assert extension.request_name == "1.3.6.1.4.1.1466.20037"


class TestTLSUpgradeManager:
    """Test cases for TLSUpgradeManager."""

    def test_manager_initialization(self) -> None:
        """Test TLS upgrade manager initialization."""
        manager = TLSUpgradeManager()

        assert isinstance(manager._default_config, TLSConfiguration)

    def test_set_default_config(self) -> None:
        """Test setting default configuration."""
        manager = TLSUpgradeManager()
        custom_config = TLSConfiguration(verify_mode=TLSVerifyMode.OPTIONAL)

        manager.set_default_config(custom_config)

        assert manager._default_config == custom_config

    def test_upgrade_connection_not_implemented(self) -> None:
        """Test upgrade_connection method (not implemented)."""
        manager = TLSUpgradeManager()
        mock_connection = object()

        with pytest.raises(
            NotImplementedError,
            match="TLSUpgradeManager requires connection manager integration",
        ):
            manager.upgrade_connection(mock_connection)


class TestConvenienceFunctions:
    """Test cases for convenience functions."""

    def test_start_tls_function(self) -> None:
        """Test start_tls convenience function."""
        extension = start_tls()

        assert isinstance(extension, StartTLSExtension)
        assert extension.tls_config.verify_mode == TLSVerifyMode.REQUIRED

    def test_start_tls_with_ca_function(self) -> None:
        """Test start_tls_with_ca convenience function."""
        extension = start_tls_with_ca("/path/to/ca.pem")

        assert isinstance(extension, StartTLSExtension)
        assert extension.tls_config.ca_cert_file == "/path/to/ca.pem"
        assert extension.tls_config.verify_mode == TLSVerifyMode.REQUIRED

    def test_start_tls_with_client_cert_function(self) -> None:
        """Test start_tls_with_client_cert convenience function."""
        extension = start_tls_with_client_cert(
            cert_file="/path/to/client.pem",
            key_file="/path/to/client.key",
            ca_cert_file="/path/to/ca.pem",
        )

        assert isinstance(extension, StartTLSExtension)
        assert extension.tls_config.cert_file == "/path/to/client.pem"
        assert extension.tls_config.key_file == "/path/to/client.key"
        assert extension.tls_config.ca_cert_file == "/path/to/ca.pem"

    def test_start_tls_with_client_cert_no_ca(self) -> None:
        """Test start_tls_with_client_cert without CA certificate."""
        extension = start_tls_with_client_cert(
            cert_file="/path/to/client.pem",
            key_file="/path/to/client.key",
        )

        assert extension.tls_config.cert_file == "/path/to/client.pem"
        assert extension.tls_config.key_file == "/path/to/client.key"
        assert extension.tls_config.ca_cert_file is None

    def test_start_tls_insecure_function(self) -> None:
        """Test start_tls_insecure convenience function."""
        extension = start_tls_insecure()

        assert isinstance(extension, StartTLSExtension)
        assert extension.tls_config.verify_mode == TLSVerifyMode.NONE
        assert extension.tls_config.check_hostname is False


class TestIntegrationScenarios:
    """Integration test scenarios."""

    def test_rfc_4511_compliance(self) -> None:
        """Test RFC 4511 compliance scenarios."""
        # Test case 1: Basic Start TLS request
        extension = StartTLSExtension()

        assert extension.request_name == ExtensionOIDs.START_TLS
        assert extension.encode_request_value() is None

        # Test case 2: Successful response processing
        result = StartTLSExtension.decode_response_value(None, None)

        assert result.tls_established is True
        assert result.connection_encrypted is True

    def test_extension_request_response_cycle(self) -> None:
        """Test complete extension request/response cycle."""
        # 1. Create extension with configuration
        tls_config = TLSConfiguration(
            ca_cert_file="/path/to/ca.pem",
            verify_mode=TLSVerifyMode.REQUIRED,
        )
        extension = StartTLSExtension(tls_config=tls_config)

        # 2. Encode request (should be None for Start TLS)
        request_value = extension.encode_request_value()
        assert request_value is None

        # 3. Simulate successful server response
        result = StartTLSExtension.decode_response_value(None, None)

        # 4. Verify result
        assert isinstance(result, StartTLSResult)
        assert result.tls_established is True
        assert result.connection_encrypted is True
        assert result.is_tls_active() is True

    def test_multiple_configuration_scenarios(self) -> None:
        """Test multiple configuration scenarios."""
        configs = [
            ("default", StartTLSExtension()),
            ("insecure", StartTLSExtension.insecure()),
            ("ca_verify", StartTLSExtension.with_ca_verification("/path/to/ca.pem")),
            (
                "client_cert",
                StartTLSExtension.with_client_cert("/cert.pem", "/key.pem"),
            ),
        ]

        for _name, extension in configs:
            assert isinstance(extension, StartTLSExtension)
            assert extension.request_name == ExtensionOIDs.START_TLS
            assert extension.encode_request_value() is None

    def test_security_configuration_validation(self) -> None:
        """Test security configuration validation."""
        # Test secure configuration
        secure_extension = StartTLSExtension.with_ca_verification("/path/to/ca.pem")
        assert secure_extension.is_verification_enabled() is True

        # Test insecure configuration
        insecure_extension = StartTLSExtension.insecure()
        assert insecure_extension.is_verification_enabled() is False

        # Test client cert configuration
        client_cert_extension = StartTLSExtension.with_client_cert(
            "/cert.pem", "/key.pem"
        )
        assert client_cert_extension.is_client_cert_enabled() is True
        assert client_cert_extension.is_verification_enabled() is True


class TestSecurityValidation:
    """Security-focused test cases."""

    def test_certificate_validation_modes(self) -> None:
        """Test different certificate validation modes."""
        verification_modes = [
            (TLSVerifyMode.NONE, False),
            (TLSVerifyMode.OPTIONAL, True),
            (TLSVerifyMode.REQUIRED, True),
        ]

        for mode, should_verify in verification_modes:
            config = TLSConfiguration(verify_mode=mode)
            assert config.is_verification_enabled() == should_verify

    def test_hostname_verification_settings(self) -> None:
        """Test hostname verification settings."""
        # Hostname verification enabled
        config1 = TLSConfiguration(check_hostname=True)
        params1 = config1.get_ssl_context_params()
        assert params1["check_hostname"] is True

        # Hostname verification disabled
        config2 = TLSConfiguration(check_hostname=False)
        params2 = config2.get_ssl_context_params()
        assert params2["check_hostname"] is False

    def test_tls_version_security(self) -> None:
        """Test TLS version security settings."""
        secure_versions = [TLSVersion.TLS_V1_2, TLSVersion.TLS_V1_3]
        insecure_versions = [TLSVersion.SSL_V23, TLSVersion.TLS_V1, TLSVersion.TLS_V1_1]

        for version in secure_versions + insecure_versions:
            config = TLSConfiguration(tls_version=version)
            params = config.get_ssl_context_params()
            assert params["minimum_version"] == version.value

    def test_cipher_suite_configuration(self) -> None:
        """Test cipher suite configuration."""
        secure_ciphers = "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:ECDHE+AES256:ECDHE+AES128:!aNULL:!MD5:!DSS"

        config = TLSConfiguration(cipher_suites=secure_ciphers)
        params = config.get_ssl_context_params()

        assert params["cipher_suites"] == secure_ciphers

    def test_client_certificate_security(self) -> None:
        """Test client certificate security validation."""
        # Valid client cert configuration
        config = TLSConfiguration(
            cert_file="/path/to/client.pem",
            key_file="/path/to/client.key",
        )
        assert config.has_client_cert() is True

        # Invalid configurations should raise validation errors
        with pytest.raises(ValueError):
            TLSConfiguration(cert_file="/path/to/client.pem")  # Missing key

        with pytest.raises(ValueError):
            TLSConfiguration(key_file="/path/to/client.key")  # Missing cert

    def test_insecure_configuration_warnings(self) -> None:
        """Test insecure configuration identification."""
        # Insecure configuration
        insecure_config = TLSConfiguration(
            verify_mode=TLSVerifyMode.NONE,
            check_hostname=False,
        )

        assert insecure_config.is_verification_enabled() is False

        # Extension using insecure config
        insecure_extension = StartTLSExtension.insecure()
        assert insecure_extension.is_verification_enabled() is False
        assert "no-verify" in str(insecure_extension)


class TestPerformanceValidation:
    """Performance-focused test cases."""

    def test_configuration_creation_performance(self) -> None:
        """Test TLS configuration creation performance."""
        import time

        start_time = time.time()

        # Create many configuration objects
        for i in range(1000):
            TLSConfiguration(
                ca_cert_file=f"/path/to/ca{i}.pem",
                verify_mode=TLSVerifyMode.REQUIRED,
                tls_version=TLSVersion.TLS_V1_2,
            )

        creation_time = time.time() - start_time

        # Should create quickly
        assert creation_time < 1.0  # Less than 1 second for 1000 configs

    def test_extension_creation_performance(self) -> None:
        """Test extension creation performance."""
        import time

        start_time = time.time()

        # Create many extension objects
        for i in range(1000):
            StartTLSExtension.with_ca_verification(f"/path/to/ca{i}.pem")

        creation_time = time.time() - start_time

        # Should create quickly
        assert creation_time < 2.0  # Less than 2 seconds for 1000 extensions

    def test_ssl_context_params_performance(self) -> None:
        """Test SSL context parameters generation performance."""
        import time

        config = TLSConfiguration(
            ca_cert_file="/path/to/ca.pem",
            cert_file="/path/to/client.pem",
            key_file="/path/to/client.key",
            cipher_suites="ECDHE+AESGCM",
        )

        start_time = time.time()

        # Generate parameters many times
        for _ in range(10000):
            config.get_ssl_context_params()

        generation_time = time.time() - start_time

        # Should generate quickly
        assert generation_time < 1.0  # Less than 1 second for 10000 generations


class TestErrorHandling:
    """Error handling test cases."""

    def test_configuration_validation_errors(self) -> None:
        """Test configuration validation error handling."""
        # Test various invalid configurations
        with pytest.raises(ValueError, match="Client certificate requires"):
            TLSConfiguration(cert_file="/path/to/cert.pem")

        with pytest.raises(ValueError, match="Private key requires"):
            TLSConfiguration(key_file="/path/to/key.pem")

    def test_extension_resilience(self) -> None:
        """Test extension resilience to various inputs."""
        # Extension should handle None config gracefully
        extension = StartTLSExtension(tls_config=None)
        assert isinstance(extension.get_tls_config(), TLSConfiguration)

        # Extension should handle encoding/decoding gracefully
        assert extension.encode_request_value() is None

        # Response decoding should handle unexpected data
        result = StartTLSExtension.decode_response_value(None, b"unexpected")
        assert isinstance(result, StartTLSResult)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
