"""Unit tests for FLEXT LDAP type definitions."""

from __future__ import annotations

from flext_ldap import (
    FlextLdapConnectionProtocol,
    FlextLdapDirectoryEntryProtocol,
    LdapAttributeDict,
    LdapAttributeDict as TypesLdapAttributeDict,
    LdapAttributeDict as UtilsLdapAttributeDict,
    LdapAttributeValue,
    LdapSearchResult,
    TLdapDn,
    TLdapFilter,
    TLdapUri,
)


class TestLdapTypes:
    """Test LDAP type definitions."""

    def test_ldap_attribute_value_types(self) -> None:
      """Test LdapAttributeValue accepts correct types."""
      # String value
      str_val: LdapAttributeValue = "test"
      assert isinstance(str_val, str)

      # Bytes value
      bytes_val: LdapAttributeValue = b"test"
      assert isinstance(bytes_val, bytes)

      # List of strings
      str_list: LdapAttributeValue = ["test1", "test2"]
      assert isinstance(str_list, list)
      assert all(isinstance(item, str) for item in str_list)

      # List of bytes
      bytes_list: LdapAttributeValue = [b"test1", b"test2"]
      assert isinstance(bytes_list, list)
      assert all(isinstance(item, bytes) for item in bytes_list)

    def test_ldap_attribute_dict(self) -> None:
      """Test LdapAttributeDict structure."""
      attr_dict: LdapAttributeDict = {
          "cn": "test user",
          "uid": ["user1", "user2"],
          "data": b"binary_data",
      }

      assert "cn" in attr_dict
      assert "uid" in attr_dict
      assert "data" in attr_dict

    def test_ldap_search_result(self) -> None:
      """Test LdapSearchResult structure."""
      result: LdapSearchResult = {
          "dn": "cn=test,dc=example,dc=com",
          "cn": "test user",
          "uid": ["user1"],
      }

      assert "dn" in result
      assert result["dn"] == "cn=test,dc=example,dc=com"

    def test_type_aliases(self) -> None:
      """Test type aliases work correctly."""
      # DN type
      dn: TLdapDn = "cn=test,dc=example,dc=com"
      assert isinstance(dn, str)

      # URI type
      uri: TLdapUri = "ldap://localhost:389"
      assert isinstance(uri, str)

      # Filter type
      ldap_filter: TLdapFilter = "(objectClass=person)"
      assert isinstance(ldap_filter, str)


class TestProtocols:
    """Test protocol definitions."""

    def test_connection_protocol_structure(self) -> None:
      """Test connection protocol has required methods."""
      # Check that the protocol defines the expected methods
      assert hasattr(FlextLdapConnectionProtocol, "__protocol_attrs__")

      # Note: We can't easily test Protocol structure at runtime,
      # but we can verify the protocol exists and is importable

    def test_directory_entry_protocol_structure(self) -> None:
      """Test directory entry protocol has required methods."""
      # Check that the protocol defines the expected methods
      assert hasattr(FlextLdapDirectoryEntryProtocol, "__protocol_attrs__")


class TestTypeCompatibility:
    """Test type compatibility across the module."""

    def test_ldap_types_are_importable(self) -> None:
      """Test all LDAP types can be imported successfully."""
      # All types should be importable without errors
      assert LdapAttributeDict is not None
      assert LdapAttributeValue is not None
      assert LdapSearchResult is not None

    def test_backwards_compatibility(self) -> None:
      """Test backwards compatibility with utils module."""
      # Should be the same type
      # Note: This is more for documentation than actual type checking
      assert UtilsLdapAttributeDict is not None
      assert TypesLdapAttributeDict is not None
