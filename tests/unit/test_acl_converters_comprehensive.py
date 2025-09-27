"""Comprehensive unit tests for flext-ldap ACL converters module.

This module provides complete test coverage for the ACL converters functionality,
focusing on the methods with low coverage.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextModels
from flext_ldap.acl.converters import FlextLdapAclConverters


class TestFlextLdapAclConvertersComprehensive:
    """Comprehensive tests for FlextLdapAclConverters class focusing on low coverage methods."""

    def test_converters_initialization(self) -> None:
        """Test converters initialization."""
        config = FlextModels.CqrsConfig.Handler.create_handler_config(
            handler_type="command",
            default_name="TestAclConverter",
            default_id="test-acl-converter",
        )
        converters = FlextLdapAclConverters(config=config)
        assert converters is not None

    def test_handle_valid_acl_conversion_request(self) -> None:
        """Test handle method with valid ACL conversion request."""
        config = FlextModels.CqrsConfig.Handler.create_handler_config(
            handler_type="command",
            default_name="TestAclConverter",
            default_id="test-acl-converter",
        )
        converters = FlextLdapAclConverters(config=config)

        message = {
            "acl_content": "access to * by * read",
            "source_format": "OPENLDAP",
            "target_format": "ACTIVE_DIRECTORY",
        }

        result = converters.handle(message)
        assert result.is_success
        assert result.data is not None
        assert result.data.is_success

    def test_handle_valid_acl_conversion_request_default_formats(self) -> None:
        """Test handle method with valid ACL conversion request using default formats."""
        config = FlextModels.CqrsConfig.Handler.create_handler_config(
            handler_type="command",
            default_name="TestAclConverter",
            default_id="test-acl-converter",
        )
        converters = FlextLdapAclConverters(config=config)

        message = {"acl_content": "access to * by * read"}

        result = converters.handle(message)
        assert result.is_success
        assert result.data is not None
        assert result.data.is_success

    def test_handle_invalid_message_type(self) -> None:
        """Test handle method with invalid message type."""
        config = FlextModels.CqrsConfig.Handler.create_handler_config(
            handler_type="command",
            default_name="TestAclConverter",
            default_id="test-acl-converter",
        )
        converters = FlextLdapAclConverters(config=config)

        result = converters.handle("invalid_message")
        assert result.is_failure
        assert result.error is not None
        assert "Invalid ACL conversion request" in result.error

    def test_handle_missing_acl_content(self) -> None:
        """Test handle method with missing acl_content."""
        config = FlextModels.CqrsConfig.Handler.create_handler_config(
            handler_type="command",
            default_name="TestAclConverter",
            default_id="test-acl-converter",
        )
        converters = FlextLdapAclConverters(config=config)

        message = {"source_format": "OPENLDAP", "target_format": "ACTIVE_DIRECTORY"}

        result = converters.handle(message)
        assert result.is_failure
        assert result.error is not None
        assert "Invalid ACL conversion request" in result.error

    def test_handle_empty_dict(self) -> None:
        """Test handle method with empty dictionary."""
        config = FlextModels.CqrsConfig.Handler.create_handler_config(
            handler_type="command",
            default_name="TestAclConverter",
            default_id="test-acl-converter",
        )
        converters = FlextLdapAclConverters(config=config)

        result = converters.handle({})
        assert result.is_failure
        assert result.error is not None
        assert "Invalid ACL conversion request" in result.error

    def test_convert_acl_success(self) -> None:
        """Test convert_acl method with successful conversion."""
        config = FlextModels.CqrsConfig.Handler.create_handler_config(
            handler_type="command",
            default_name="TestAclConverter",
            default_id="test-acl-converter",
        )
        converters = FlextLdapAclConverters(config=config)

        result = converters.convert_acl(
            "access to * by * read", "OPENLDAP", "ACTIVE_DIRECTORY"
        )

        assert result.is_success
        assert result.data is not None
        assert (
            "Converted access to * by * read from OPENLDAP to ACTIVE_DIRECTORY"
            in str(result.data)
        )

    def test_convert_acl_different_formats(self) -> None:
        """Test convert_acl method with different format combinations."""
        config = FlextModels.CqrsConfig.Handler.create_handler_config(
            handler_type="command",
            default_name="TestAclConverter",
            default_id="test-acl-converter",
        )
        converters = FlextLdapAclConverters(config=config)

        # Test various format combinations
        test_cases = [
            ("OPENLDAP", "ORACLE"),
            ("ACTIVE_DIRECTORY", "OPENLDAP"),
            ("ORACLE", "ACTIVE_DIRECTORY"),
            ("CUSTOM1", "CUSTOM2"),
        ]

        for source, target in test_cases:
            result = converters.convert_acl("test acl", source, target)
            assert result.is_success
            assert result.data is not None
            assert f"Converted test acl from {source} to {target}" in str(result.data)

    def test_convert_acl_exception_handling(self) -> None:
        """Test convert_acl method exception handling."""
        config = FlextModels.CqrsConfig.Handler.create_handler_config(
            handler_type="command",
            default_name="TestAclConverter",
            default_id="test-acl-converter",
        )
        converters = FlextLdapAclConverters(config=config)

        # Mock an exception by passing None values
        result = converters.convert_acl(None, None, None)
        assert (
            result.is_success
        )  # The current implementation doesn't raise exceptions for None values

        # Test with actual content
        result = converters.convert_acl("valid acl", "source", "target")
        assert result.is_success


class TestFlextLdapAclConvertersOpenLdapConverter:
    """Comprehensive tests for OpenLdapConverter class."""

    def test_to_microsoft_ad_success(self) -> None:
        """Test to_microsoft_ad method with successful conversion."""
        result = FlextLdapAclConverters.OpenLdapConverter.to_microsoft_ad(
            "access to * by * read"
        )

        assert result.is_success
        assert result.data is not None
        assert (
            "Converted OpenLDAP ACL to Microsoft AD format: access to * by * read"
            in result.data
        )

    def test_to_microsoft_ad_empty_content(self) -> None:
        """Test to_microsoft_ad method with empty content."""
        result = FlextLdapAclConverters.OpenLdapConverter.to_microsoft_ad("")

        assert result.is_failure
        assert result.error is not None
        assert "ACL content cannot be empty" in result.error

    def test_to_microsoft_ad_whitespace_only(self) -> None:
        """Test to_microsoft_ad method with whitespace only content."""
        result = FlextLdapAclConverters.OpenLdapConverter.to_microsoft_ad("   ")

        assert result.is_failure
        assert result.error is not None
        assert "ACL content cannot be empty" in result.error

    def test_to_microsoft_ad_none_content(self) -> None:
        """Test to_microsoft_ad method with None content."""
        result = FlextLdapAclConverters.OpenLdapConverter.to_microsoft_ad(None)

        assert result.is_failure
        assert result.error is not None
        assert "ACL content cannot be empty" in result.error

    def test_to_microsoft_ad_complex_acl(self) -> None:
        """Test to_microsoft_ad method with complex ACL content."""
        complex_acl = 'access to dn.subtree="ou=people,dc=example,dc=com" by dn="cn=admin,dc=example,dc=com" write by * read'

        result = FlextLdapAclConverters.OpenLdapConverter.to_microsoft_ad(complex_acl)

        assert result.is_success
        assert result.data is not None
        assert (
            f"Converted OpenLDAP ACL to Microsoft AD format: {complex_acl}"
            in result.data
        )

    def test_to_oracle_success(self) -> None:
        """Test to_oracle method with successful conversion."""
        result = FlextLdapAclConverters.OpenLdapConverter.to_oracle(
            "access to * by * read"
        )

        assert result.is_success
        assert result.data is not None
        assert (
            "Converted OpenLDAP ACL to Oracle format: access to * by * read"
            in result.data
        )

    def test_to_oracle_empty_content(self) -> None:
        """Test to_oracle method with empty content."""
        result = FlextLdapAclConverters.OpenLdapConverter.to_oracle("")

        assert result.is_failure
        assert result.error is not None
        assert "ACL content cannot be empty" in result.error

    def test_to_oracle_whitespace_only(self) -> None:
        """Test to_oracle method with whitespace only content."""
        result = FlextLdapAclConverters.OpenLdapConverter.to_oracle("   ")

        assert result.is_failure
        assert result.error is not None
        assert "ACL content cannot be empty" in result.error

    def test_to_oracle_none_content(self) -> None:
        """Test to_oracle method with None content."""
        result = FlextLdapAclConverters.OpenLdapConverter.to_oracle(None)

        assert result.is_failure
        assert result.error is not None
        assert "ACL content cannot be empty" in result.error

    def test_to_oracle_complex_acl(self) -> None:
        """Test to_oracle method with complex ACL content."""
        complex_acl = 'access to dn.subtree="ou=groups,dc=example,dc=com" by dn="cn=admin,dc=example,dc=com" write by group="cn=managers,ou=groups,dc=example,dc=com" read'

        result = FlextLdapAclConverters.OpenLdapConverter.to_oracle(complex_acl)

        assert result.is_success
        assert result.data is not None
        assert f"Converted OpenLDAP ACL to Oracle format: {complex_acl}" in result.data


class TestFlextLdapAclConvertersMicrosoftAdConverter:
    """Comprehensive tests for MicrosoftAdConverter class."""

    def test_to_openldap_success(self) -> None:
        """Test to_openldap method with successful conversion."""
        result = FlextLdapAclConverters.MicrosoftAdConverter.to_openldap(
            "CN=TestUser,OU=Users,DC=example,DC=com:RP"
        )

        assert result.is_success
        assert result.data is not None
        assert (
            "Converted Microsoft AD ACL to OpenLDAP format: CN=TestUser,OU=Users,DC=example,DC=com:RP"
            in result.data
        )

    def test_to_openldap_empty_content(self) -> None:
        """Test to_openldap method with empty content."""
        result = FlextLdapAclConverters.MicrosoftAdConverter.to_openldap("")

        assert result.is_failure
        assert result.error is not None
        assert "ACL content cannot be empty" in result.error

    def test_to_openldap_whitespace_only(self) -> None:
        """Test to_openldap method with whitespace only content."""
        result = FlextLdapAclConverters.MicrosoftAdConverter.to_openldap("   ")

        assert result.is_failure
        assert result.error is not None
        assert "ACL content cannot be empty" in result.error

    def test_to_openldap_none_content(self) -> None:
        """Test to_openldap method with None content."""
        result = FlextLdapAclConverters.MicrosoftAdConverter.to_openldap(None)

        assert result.is_failure
        assert result.error is not None
        assert "ACL content cannot be empty" in result.error

    def test_to_openldap_complex_acl(self) -> None:
        """Test to_openldap method with complex ACL content."""
        complex_acl = "CN=TestUser,OU=Users,DC=example,DC=com:RPWP;CN=TestGroup,OU=Groups,DC=example,DC=com:RP"

        result = FlextLdapAclConverters.MicrosoftAdConverter.to_openldap(complex_acl)

        assert result.is_success
        assert result.data is not None
        assert (
            f"Converted Microsoft AD ACL to OpenLDAP format: {complex_acl}"
            in result.data
        )

    def test_to_oracle_success(self) -> None:
        """Test to_oracle method with successful conversion."""
        result = FlextLdapAclConverters.MicrosoftAdConverter.to_oracle(
            "CN=TestUser,OU=Users,DC=example,DC=com:RP"
        )

        assert result.is_success
        assert result.data is not None
        assert (
            "Converted Microsoft AD ACL to Oracle format: CN=TestUser,OU=Users,DC=example,DC=com:RP"
            in result.data
        )

    def test_to_oracle_empty_content(self) -> None:
        """Test to_oracle method with empty content."""
        result = FlextLdapAclConverters.MicrosoftAdConverter.to_oracle("")

        assert result.is_failure
        assert result.error is not None
        assert "ACL content cannot be empty" in result.error

    def test_to_oracle_whitespace_only(self) -> None:
        """Test to_oracle method with whitespace only content."""
        result = FlextLdapAclConverters.MicrosoftAdConverter.to_oracle("   ")

        assert result.is_failure
        assert result.error is not None
        assert "ACL content cannot be empty" in result.error

    def test_to_oracle_none_content(self) -> None:
        """Test to_oracle method with None content."""
        result = FlextLdapAclConverters.MicrosoftAdConverter.to_oracle(None)

        assert result.is_failure
        assert result.error is not None
        assert "ACL content cannot be empty" in result.error

    def test_to_oracle_complex_acl(self) -> None:
        """Test to_oracle method with complex ACL content."""
        complex_acl = "CN=TestUser,OU=Users,DC=example,DC=com:RPWP;CN=TestGroup,OU=Groups,DC=example,DC=com:RP"

        result = FlextLdapAclConverters.MicrosoftAdConverter.to_oracle(complex_acl)

        assert result.is_success
        assert result.data is not None
        assert (
            f"Converted Microsoft AD ACL to Oracle format: {complex_acl}" in result.data
        )


class TestFlextLdapAclConvertersOracleConverter:
    """Comprehensive tests for OracleConverter class."""

    def test_to_openldap_success(self) -> None:
        """Test to_openldap method with successful conversion."""
        result = FlextLdapAclConverters.OracleConverter.to_openldap(
            "GRANT READ ON ou=people,dc=example,dc=com TO cn=admin,dc=example,dc=com"
        )

        assert result.is_success
        assert result.data is not None
        assert (
            "Converted Oracle ACL to OpenLDAP format: GRANT READ ON ou=people,dc=example,dc=com TO cn=admin,dc=example,dc=com"
            in result.data
        )

    def test_to_openldap_empty_content(self) -> None:
        """Test to_openldap method with empty content."""
        result = FlextLdapAclConverters.OracleConverter.to_openldap("")

        assert result.is_failure
        assert result.error is not None
        assert "ACL content cannot be empty" in result.error

    def test_to_openldap_whitespace_only(self) -> None:
        """Test to_openldap method with whitespace only content."""
        result = FlextLdapAclConverters.OracleConverter.to_openldap("   ")

        assert result.is_failure
        assert result.error is not None
        assert "ACL content cannot be empty" in result.error

    def test_to_openldap_none_content(self) -> None:
        """Test to_openldap method with None content."""
        result = FlextLdapAclConverters.OracleConverter.to_openldap(None)

        assert result.is_failure
        assert result.error is not None
        assert "ACL content cannot be empty" in result.error

    def test_to_openldap_complex_acl(self) -> None:
        """Test to_openldap method with complex ACL content."""
        complex_acl = "GRANT READ,WRITE ON ou=people,dc=example,dc=com TO cn=admin,dc=example,dc=com,cn=manager,dc=example,dc=com"

        result = FlextLdapAclConverters.OracleConverter.to_openldap(complex_acl)

        assert result.is_success
        assert result.data is not None
        assert f"Converted Oracle ACL to OpenLDAP format: {complex_acl}" in result.data

    def test_to_microsoft_ad_success(self) -> None:
        """Test to_microsoft_ad method with successful conversion."""
        result = FlextLdapAclConverters.OracleConverter.to_microsoft_ad(
            "GRANT READ ON ou=people,dc=example,dc=com TO cn=admin,dc=example,dc=com"
        )

        assert result.is_success
        assert result.data is not None
        assert (
            "Converted Oracle ACL to Microsoft AD format: GRANT READ ON ou=people,dc=example,dc=com TO cn=admin,dc=example,dc=com"
            in result.data
        )

    def test_to_microsoft_ad_empty_content(self) -> None:
        """Test to_microsoft_ad method with empty content."""
        result = FlextLdapAclConverters.OracleConverter.to_microsoft_ad("")

        assert result.is_failure
        assert result.error is not None
        assert "ACL content cannot be empty" in result.error

    def test_to_microsoft_ad_whitespace_only(self) -> None:
        """Test to_microsoft_ad method with whitespace only content."""
        result = FlextLdapAclConverters.OracleConverter.to_microsoft_ad("   ")

        assert result.is_failure
        assert result.error is not None
        assert "ACL content cannot be empty" in result.error

    def test_to_microsoft_ad_none_content(self) -> None:
        """Test to_microsoft_ad method with None content."""
        result = FlextLdapAclConverters.OracleConverter.to_microsoft_ad(None)

        assert result.is_failure
        assert result.error is not None
        assert "ACL content cannot be empty" in result.error

    def test_to_microsoft_ad_complex_acl(self) -> None:
        """Test to_microsoft_ad method with complex ACL content."""
        complex_acl = "GRANT READ,WRITE ON ou=people,dc=example,dc=com TO cn=admin,dc=example,dc=com,cn=manager,dc=example,dc=com"

        result = FlextLdapAclConverters.OracleConverter.to_microsoft_ad(complex_acl)

        assert result.is_success
        assert result.data is not None
        assert (
            f"Converted Oracle ACL to Microsoft AD format: {complex_acl}" in result.data
        )


class TestFlextLdapAclConvertersIntegration:
    """Integration tests for ACL converters."""

    def test_full_conversion_workflow(self) -> None:
        """Test full conversion workflow from OpenLDAP to Microsoft AD to Oracle."""
        # OpenLDAP to Microsoft AD
        result1 = FlextLdapAclConverters.OpenLdapConverter.to_microsoft_ad(
            "access to * by * read"
        )
        assert result1.is_success

        # Microsoft AD to Oracle
        result2 = FlextLdapAclConverters.MicrosoftAdConverter.to_oracle(result1.data)
        assert result2.is_success

        # Oracle back to OpenLDAP
        result3 = FlextLdapAclConverters.OracleConverter.to_openldap(result2.data)
        assert result3.is_success

    def test_converter_error_propagation(self) -> None:
        """Test that errors are properly propagated through the conversion chain."""
        # Start with empty content
        result1 = FlextLdapAclConverters.OpenLdapConverter.to_microsoft_ad("")
        assert result1.is_failure

        # Should not be able to convert empty content
        result2 = FlextLdapAclConverters.MicrosoftAdConverter.to_oracle("")
        assert result2.is_failure

        result3 = FlextLdapAclConverters.OracleConverter.to_openldap("")
        assert result3.is_failure

    def test_converter_handle_method_integration(self) -> None:
        """Test integration with the main handle method."""
        config = FlextModels.CqrsConfig.Handler.create_handler_config(
            handler_type="command",
            default_name="TestAclConverter",
            default_id="test-acl-converter",
        )
        converters = FlextLdapAclConverters(config=config)

        # Test with various format combinations
        test_cases = [
            {
                "acl_content": "access to * by * read",
                "source_format": "OPENLDAP",
                "target_format": "ACTIVE_DIRECTORY",
            },
            {
                "acl_content": "CN=User:RP",
                "source_format": "ACTIVE_DIRECTORY",
                "target_format": "ORACLE",
            },
            {
                "acl_content": "GRANT READ ON ou=people TO cn=admin",
                "source_format": "ORACLE",
                "target_format": "OPENLDAP",
            },
        ]

        for test_case in test_cases:
            result = converters.handle(test_case)
            assert result.is_success
            assert result.data is not None
            assert result.data.is_success
