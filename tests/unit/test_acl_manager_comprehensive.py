"""Comprehensive tests for FlextLdapAclManager class."""

from flext_ldap.acl.manager import FlextLdapAclManager


class TestFlextLdapAclManagerComprehensive:
    """Comprehensive tests for FlextLdapAclManager class."""

    def test_acl_manager_initialization(self) -> None:
        """Test ACL manager initialization."""
        manager = FlextLdapAclManager()
        assert manager is not None
        assert manager.parsers is not None
        assert manager.converters is not None

    def test_handle_invalid_message_type(self) -> None:
        """Test handle method with invalid message type."""
        manager = FlextLdapAclManager()
        result = manager.handle("invalid_message")
        assert result.is_failure
        assert result.error is not None
        assert "Message must be a dictionary" in result.error

    def test_handle_missing_operation(self) -> None:
        """Test handle method with missing operation."""
        manager = FlextLdapAclManager()
        result = manager.handle({})
        assert result.is_failure
        assert result.error is not None
        assert "Operation must be a string" in result.error

    def test_handle_invalid_operation_type(self) -> None:
        """Test handle method with invalid operation type."""
        manager = FlextLdapAclManager()
        result = manager.handle({"operation": 123})
        assert result.is_failure
        assert result.error is not None
        assert "Operation must be a string" in result.error

    def test_handle_unknown_operation(self) -> None:
        """Test handle method with unknown operation."""
        manager = FlextLdapAclManager()
        result = manager.handle({"operation": "unknown"})
        assert result.is_failure
        assert result.error is not None
        assert "Unknown operation: unknown" in result.error

    def test_handle_parse_operation(self) -> None:
        """Test handle method with parse operation."""
        manager = FlextLdapAclManager()
        message = {
            "operation": "parse",
            "acl_string": 'access to dn.base="cn=test" by * read',
            "format": "openldap",
        }
        result = manager.handle(message)
        assert result.is_success
        assert result.data is not None

    def test_handle_convert_operation(self) -> None:
        """Test handle method with convert operation."""
        manager = FlextLdapAclManager()
        message = {
            "operation": "convert",
            "acl_data": 'access to dn.base="cn=test" by * read',
            "source_format": "openldap",
            "target_format": "active_directory",
        }
        result = manager.handle(message)
        assert result.is_success
        assert result.data is not None

    def test_handle_parse_missing_acl_string(self) -> None:
        """Test handle method with parse operation missing acl_string."""
        manager = FlextLdapAclManager()
        message = {"operation": "parse", "format": "openldap"}
        result = manager.handle(message)
        assert result.is_failure
        assert result.error is not None
        assert "ACL string must be provided" in result.error

    def test_handle_parse_invalid_acl_string_type(self) -> None:
        """Test handle method with parse operation invalid acl_string type."""
        manager = FlextLdapAclManager()
        message = {"operation": "parse", "acl_string": 123, "format": "openldap"}
        result = manager.handle(message)
        assert result.is_failure
        assert result.error is not None
        assert "ACL string must be provided" in result.error

    def test_handle_parse_unsupported_format(self) -> None:
        """Test handle method with parse operation unsupported format."""
        manager = FlextLdapAclManager()
        message = {
            "operation": "parse",
            "acl_string": 'access to dn.base="cn=test" by * read',
            "format": "unsupported",
        }
        result = manager.handle(message)
        assert result.is_failure
        assert result.error is not None
        assert "Unsupported ACL format: unsupported" in result.error

    def test_handle_convert_missing_acl_data(self) -> None:
        """Test handle method with convert operation missing acl_data."""
        manager = FlextLdapAclManager()
        message = {"operation": "convert", "target_format": "active_directory"}
        result = manager.handle(message)
        assert result.is_failure
        assert result.error is not None
        assert "ACL data must be a string" in result.error

    def test_handle_convert_invalid_acl_data_type(self) -> None:
        """Test handle method with convert operation invalid acl_data type."""
        manager = FlextLdapAclManager()
        message = {
            "operation": "convert",
            "acl_data": 123,
            "target_format": "active_directory",
        }
        result = manager.handle(message)
        assert result.is_failure
        assert result.error is not None
        assert "ACL data must be a string" in result.error

    def test_handle_convert_missing_target_format(self) -> None:
        """Test handle method with convert operation missing target_format."""
        manager = FlextLdapAclManager()
        message = {
            "operation": "convert",
            "acl_data": 'access to dn.base="cn=test" by * read',
        }
        result = manager.handle(message)
        assert result.is_failure
        assert result.error is not None
        assert "Target format must be specified" in result.error

    def test_handle_convert_invalid_target_format_type(self) -> None:
        """Test handle method with convert operation invalid target_format type."""
        manager = FlextLdapAclManager()
        message = {
            "operation": "convert",
            "acl_data": 'access to dn.base="cn=test" by * read',
            "target_format": 123,
        }
        result = manager.handle(message)
        assert result.is_failure
        assert result.error is not None
        assert "Target format must be specified" in result.error

    def test_handle_exception_handling(self) -> None:
        """Test handle method exception handling."""
        manager = FlextLdapAclManager()
        # Mock an exception by passing invalid data that will cause an error
        result = manager.handle(
            {
                "operation": "parse",
                "acl_string": None,
                "format": "openldap",
            }
        )
        assert result.is_failure
        assert result.error is not None
        assert "ACL string must be provided" in result.error


class TestFlextLdapAclManagerParseAcl:
    """Tests for FlextLdapAclManager.parse_acl method."""

    def test_parse_acl_openldap_success(self) -> None:
        """Test parse_acl method with OpenLDAP format."""
        manager = FlextLdapAclManager()
        acl_string = 'access to dn.base="cn=test" by * read'
        result = manager.parse_acl(acl_string, "openldap")
        assert result.is_success
        assert result.data is not None

    def test_parse_acl_oracle_success(self) -> None:
        """Test parse_acl method with Oracle format."""
        manager = FlextLdapAclManager()
        acl_string = "access to entry by users (read,write)"
        result = manager.parse_acl(acl_string, "oracle")
        assert result.is_success
        assert result.data is not None

    def test_parse_acl_aci_success(self) -> None:
        """Test parse_acl method with ACI format."""
        manager = FlextLdapAclManager()
        acl_string = '(target="cn=test")(version 3.0; acl "test_acl";  allow (read,write) userdn="ldap:///all";)'
        result = manager.parse_acl(acl_string, "aci")
        assert result.is_success
        assert result.data is not None

    def test_parse_acl_unsupported_format(self) -> None:
        """Test parse_acl method with unsupported format."""
        manager = FlextLdapAclManager()
        acl_string = 'access to dn.base="cn=test" by * read'
        result = manager.parse_acl(acl_string, "unsupported")
        assert result.is_failure
        assert result.error is not None
        assert "Unsupported ACL format: unsupported" in result.error

    def test_parse_acl_parsing_failure(self) -> None:
        """Test parse_acl method with invalid ACL string."""
        manager = FlextLdapAclManager()
        acl_string = "invalid acl string"
        result = manager.parse_acl(acl_string, "openldap")
        assert result.is_failure
        assert result.error is not None
        assert "ACL parsing failed:" in result.error

    def test_parse_acl_exception_handling(self) -> None:
        """Test parse_acl method exception handling."""
        manager = FlextLdapAclManager()
        # This should cause an exception due to invalid input
        result = manager.parse_acl("", "openldap")
        assert result.is_failure
        assert result.error is not None
        assert "ACL parsing failed:" in result.error


class TestFlextLdapAclManagerConvertAcl:
    """Tests for FlextLdapAclManager.convert_acl method."""

    def test_convert_acl_success(self) -> None:
        """Test convert_acl method returns not implemented."""
        manager = FlextLdapAclManager()
        acl_data = 'access to dn.base="cn=test" by * read'
        result = manager.convert_acl(acl_data, "openldap", "active_directory")

        # Converters now honestly return not implemented
        assert result.is_failure
        assert result.error is not None and "not implemented" in result.error.lower()

    def test_convert_acl_conversion_failure(self) -> None:
        """Test convert_acl method returns not implemented."""
        manager = FlextLdapAclManager()
        acl_data = ""
        result = manager.convert_acl(acl_data, "openldap", "active_directory")

        # Converters now honestly return not implemented
        assert result.is_failure
        assert result.error is not None and "not implemented" in result.error.lower()

    def test_convert_acl_exception_handling(self) -> None:
        """Test convert_acl method returns not implemented."""
        manager = FlextLdapAclManager()
        # Test with empty string instead of None
        result = manager.convert_acl("", "openldap", "active_directory")

        # Converters now honestly return not implemented
        assert result.is_failure
        assert result.error is not None and "not implemented" in result.error.lower()


class TestFlextLdapAclManagerBatchConvert:
    """Tests for FlextLdapAclManager.batch_convert method."""

    def test_batch_convert_success(self) -> None:
        """Test batch_convert method returns not implemented."""
        manager = FlextLdapAclManager()
        acls = [
            'access to dn.base="cn=test1" by * read',
            'access to dn.base="cn=test2" by * write',
        ]
        result = manager.batch_convert(acls, "openldap", "active_directory")

        # Converters now honestly return not implemented
        assert result.is_failure
        assert result.error is not None and "not implemented" in result.error.lower()

    def test_batch_convert_empty_list(self) -> None:
        """Test batch_convert method with empty ACL list."""
        manager = FlextLdapAclManager()
        result = manager.batch_convert([], "openldap", "active_directory")
        assert result.is_failure
        assert result.error is not None
        assert "ACL list cannot be empty" in result.error

    def test_batch_convert_conversion_failure(self) -> None:
        """Test batch_convert method returns not implemented."""
        manager = FlextLdapAclManager()
        acls = [
            'access to dn.base="cn=test1" by * read',
            "",  # This will be handled gracefully
        ]
        result = manager.batch_convert(acls, "openldap", "active_directory")

        # Converters now honestly return not implemented
        assert result.is_failure
        assert result.error is not None and "not implemented" in result.error.lower()

    def test_batch_convert_exception_handling(self) -> None:
        """Test batch_convert method exception handling."""
        manager = FlextLdapAclManager()
        # Test with empty list instead of None
        result = manager.batch_convert([], "openldap", "active_directory")
        assert result.is_failure
        assert result.error is not None
        assert "ACL list cannot be empty" in result.error


class TestFlextLdapAclManagerValidateAclSyntax:
    """Tests for FlextLdapAclManager.validate_acl_syntax method."""

    def test_validate_acl_syntax_valid_openldap(self) -> None:
        """Test validate_acl_syntax method with valid OpenLDAP ACL."""
        manager = FlextLdapAclManager()
        acl_string = 'access to dn.base="cn=test" by * read'
        result = manager.validate_acl_syntax(acl_string, "openldap")
        assert result.is_success
        assert result.data is True

    def test_validate_acl_syntax_valid_oracle(self) -> None:
        """Test validate_acl_syntax method with valid Oracle ACL."""
        manager = FlextLdapAclManager()
        acl_string = "access to entry by users (read,write)"
        result = manager.validate_acl_syntax(acl_string, "oracle")
        assert result.is_success
        assert result.data is True

    def test_validate_acl_syntax_valid_aci(self) -> None:
        """Test validate_acl_syntax method with valid ACI ACL."""
        manager = FlextLdapAclManager()
        acl_string = '(target="cn=test")(version 3.0; acl "test_acl";  allow (read,write) userdn="ldap:///all";)'
        result = manager.validate_acl_syntax(acl_string, "aci")
        assert result.is_success
        assert result.data is True

    def test_validate_acl_syntax_invalid_acl(self) -> None:
        """Test validate_acl_syntax method with invalid ACL."""
        manager = FlextLdapAclManager()
        acl_string = "invalid acl string"
        result = manager.validate_acl_syntax(acl_string, "openldap")
        assert result.is_failure
        assert result.error is not None
        assert "Invalid ACL syntax:" in result.error

    def test_validate_acl_syntax_unsupported_format(self) -> None:
        """Test validate_acl_syntax method with unsupported format."""
        manager = FlextLdapAclManager()
        acl_string = 'access to dn.base="cn=test" by * read'
        result = manager.validate_acl_syntax(acl_string, "unsupported")
        assert result.is_failure
        assert result.error is not None
        assert "Unsupported ACL format: unsupported" in result.error

    def test_validate_acl_syntax_exception_handling(self) -> None:
        """Test validate_acl_syntax method exception handling."""
        manager = FlextLdapAclManager()
        # This should cause an exception due to invalid input
        result = manager.validate_acl_syntax("", "openldap")
        assert result.is_failure
        assert result.error is not None
        assert "Invalid ACL syntax:" in result.error
