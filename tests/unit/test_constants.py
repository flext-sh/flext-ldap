"""Tests for FlextLdapConstants module."""

import pytest

from flext_ldap.constants import FlextLdapConstants


class TestFlextLdapConstants:
    """Test cases for FlextLdapConstants."""

    def test_constants_initialization(self) -> None:
        """Test constants initialization."""
        constants = FlextLdapConstants()
        assert constants is not None

    def test_protocol_constants(self) -> None:
        """Test protocol constants."""
        assert FlextLdapConstants.Protocol.LDAP == "ldap"
        assert FlextLdapConstants.Protocol.LDAPS == "ldaps"
        assert FlextLdapConstants.Protocol.DEFAULT_PORT == 389
        assert FlextLdapConstants.Protocol.DEFAULT_SSL_PORT == 636
        assert FlextLdapConstants.Protocol.DEFAULT_SERVER_URI == "ldap://localhost"
        assert FlextLdapConstants.Protocol.DEFAULT_SSL_SERVER_URI == "ldaps://localhost"
        assert FlextLdapConstants.Protocol.MAX_DESCRIPTION_LENGTH == 1024

    def test_connection_constants(self) -> None:
        """Test connection constants."""
        assert FlextLdapConstants.Connection.DEFAULT_SEARCH_PAGE_SIZE == 100
        assert FlextLdapConstants.Connection.MAX_PAGE_SIZE_GENERIC == 1000
        assert FlextLdapConstants.Connection.MAX_PAGE_SIZE_AD == 100000

    def test_scopes_constants(self) -> None:
        """Test scopes constants (RFC 4511 standard scopes)."""
        assert FlextLdapConstants.Scopes.BASE == "base"
        assert FlextLdapConstants.Scopes.ONELEVEL == "onelevel"
        assert FlextLdapConstants.Scopes.SUBTREE == "subtree"
        assert FlextLdapConstants.Scopes.CHILDREN == "children"

    def test_attributes_core_constants(self) -> None:
        """Test core attribute constants."""
        assert FlextLdapConstants.LdapAttributeNames.COMMON_NAME == "cn"
        assert FlextLdapConstants.LdapAttributeNames.SURNAME == "sn"
        assert FlextLdapConstants.LdapAttributeNames.GIVEN_NAME == "givenName"
        assert FlextLdapConstants.LdapAttributeNames.DISPLAY_NAME == "displayName"
        assert FlextLdapConstants.LdapAttributeNames.USER_ID == "uid"
        assert FlextLdapConstants.LdapAttributeNames.MAIL == "mail"
        assert FlextLdapConstants.LdapAttributeNames.USER_PASSWORD == "userPassword"

    def test_attributes_group_constants(self) -> None:
        """Test group attribute constants."""
        assert FlextLdapConstants.LdapAttributeNames.MEMBER == "member"
        assert FlextLdapConstants.LdapAttributeNames.UNIQUE_MEMBER == "uniqueMember"
        assert FlextLdapConstants.LdapAttributeNames.MEMBER_OF == "memberOf"
        assert FlextLdapConstants.LdapAttributeNames.OWNER == "owner"

    def test_attributes_minimal_lists(self) -> None:
        """Test minimal attribute lists."""
        assert FlextLdapConstants.LdapAttributeNames.MINIMAL_USER_ATTRS == [
            "uid",
            "cn",
            "mail",
        ]
        assert FlextLdapConstants.LdapAttributeNames.MINIMAL_GROUP_ATTRS == [
            "cn",
            "member",
        ]

    def test_attributes_all_lists(self) -> None:
        """Test comprehensive attribute lists."""
        expected_user_attrs = [
            "objectClass",
            "cn",
            "sn",
            "givenName",
            "displayName",
            "uid",
            "mail",
            "userPassword",
            "description",
            "memberOf",
        ]
        assert (
            expected_user_attrs == FlextLdapConstants.LdapAttributeNames.ALL_USER_ATTRS
        )

        expected_group_attrs = [
            "objectClass",
            "cn",
            "description",
            "member",
            "uniqueMember",
            "owner",
            "memberOf",
        ]
        assert (
            expected_group_attrs
            == FlextLdapConstants.LdapAttributeNames.ALL_GROUP_ATTRS
        )

    def test_attributes_get_group_attributes_method(self) -> None:
        """Test get_group_attributes method returns copy."""
        result = FlextLdapConstants.LdapAttributeNames.get_group_attributes()
        assert result == FlextLdapConstants.LdapAttributeNames.ALL_GROUP_ATTRS
        # Verify it's a copy (modification doesn't affect original)
        result.append("test")
        assert "test" not in FlextLdapConstants.LdapAttributeNames.ALL_GROUP_ATTRS

    def test_ldap_attribute_names_core(self) -> None:
        """Test LDAP attribute names core constants."""
        assert FlextLdapConstants.LdapAttributeNames.DN == "dn"
        assert FlextLdapConstants.LdapAttributeNames.OBJECT_CLASS == "objectClass"
        assert FlextLdapConstants.LdapAttributeNames.CN == "cn"
        assert FlextLdapConstants.LdapAttributeNames.SN == "sn"
        assert FlextLdapConstants.LdapAttributeNames.GIVEN_NAME == "givenName"
        assert FlextLdapConstants.LdapAttributeNames.DISPLAY_NAME == "displayName"
        assert FlextLdapConstants.LdapAttributeNames.UID == "uid"
        assert FlextLdapConstants.LdapAttributeNames.MAIL == "mail"
        assert FlextLdapConstants.LdapAttributeNames.USER_PASSWORD == "userPassword"

    def test_ldap_attribute_names_group(self) -> None:
        """Test LDAP attribute names group constants."""
        assert FlextLdapConstants.LdapAttributeNames.MEMBER == "member"
        assert FlextLdapConstants.LdapAttributeNames.UNIQUE_MEMBER == "uniqueMember"
        assert FlextLdapConstants.LdapAttributeNames.MEMBER_OF == "memberOf"
        assert FlextLdapConstants.LdapAttributeNames.OWNER == "owner"
        assert FlextLdapConstants.LdapAttributeNames.GID_NUMBER == "gidNumber"

    def test_ldap_attribute_names_additional(self) -> None:
        """Test LDAP attribute names additional constants."""
        assert (
            FlextLdapConstants.LdapAttributeNames.TELEPHONE_NUMBER == "telephoneNumber"
        )
        assert FlextLdapConstants.LdapAttributeNames.MOBILE == "mobile"
        assert FlextLdapConstants.LdapAttributeNames.DEPARTMENT == "department"
        assert FlextLdapConstants.LdapAttributeNames.TITLE == "title"
        assert FlextLdapConstants.LdapAttributeNames.OU == "ou"
        assert FlextLdapConstants.LdapAttributeNames.DESCRIPTION == "description"
        assert FlextLdapConstants.LdapAttributeNames.EMPLOYEE_NUMBER == "employeeNumber"
        assert FlextLdapConstants.LdapAttributeNames.EMPLOYEE_TYPE == "employeeType"

    def test_filters_user_constants(self) -> None:
        """Test filter user constants."""
        assert (
            FlextLdapConstants.Filters.DEFAULT_USER_FILTER
            == "(objectClass=inetOrgPerson)"
        )
        assert FlextLdapConstants.Filters.ALL_USERS_FILTER == "(objectClass=person)"
        assert (
            "(objectClass=inetOrgPerson)"
            in FlextLdapConstants.Filters.ACTIVE_USERS_FILTER
        )

    def test_filters_group_constants(self) -> None:
        """Test filter group constants."""
        assert (
            FlextLdapConstants.Filters.DEFAULT_GROUP_FILTER
            == "(objectClass=groupOfNames)"
        )
        assert (
            "(objectClass=groupOfNames)" in FlextLdapConstants.Filters.ALL_GROUPS_FILTER
        )

    def test_filters_common_constants(self) -> None:
        """Test filter common constants."""
        assert FlextLdapConstants.Filters.ALL_ENTRIES_FILTER == "(objectClass=*)"
        assert (
            FlextLdapConstants.Filters.ORGANIZATIONAL_UNITS_FILTER
            == "(objectClass=organizationalUnit)"
        )

    def test_validation_dn_constants(self) -> None:
        """Test validation DN constants."""
        assert FlextLdapConstants.Validation.MIN_DN_PARTS == 2
        assert FlextLdapConstants.Validation.MIN_DN_LENGTH == 3
        assert FlextLdapConstants.Validation.MAX_DN_LENGTH == 2048
        assert isinstance(FlextLdapConstants.Validation.DN_PATTERN, str)
        assert FlextLdapConstants.Validation.DN_PATTERN.startswith("^")

    def test_validation_filter_constants(self) -> None:
        """Test validation filter constants."""
        assert FlextLdapConstants.Validation.MIN_FILTER_LENGTH == 1
        assert FlextLdapConstants.Validation.MAX_FILTER_LENGTH == 8192
        assert FlextLdapConstants.Validation.FILTER_PATTERN == r"^\(.+\)$"

    def test_validation_password_constants(self) -> None:
        """Test validation password constants."""
        assert FlextLdapConstants.Validation.MIN_PASSWORD_LENGTH == 8
        assert FlextLdapConstants.Validation.MAX_PASSWORD_LENGTH == 128

    def test_validation_connection_constants(self) -> None:
        """Test validation connection constants."""
        assert FlextLdapConstants.Validation.MIN_CONNECTION_ARGS == 3

    def test_messages_validation_constants(self) -> None:
        """Test messages validation constants."""
        assert (
            FlextLdapConstants.Messages.HOST_CANNOT_BE_EMPTY == "Host cannot be empty"
        )
        assert FlextLdapConstants.Messages.CONNECTION_FAILED == "Connection failed"
        assert "{0}" in FlextLdapConstants.Messages.FIELD_CANNOT_BE_EMPTY
        assert FlextLdapConstants.Messages.INVALID_DN_FORMAT == "Invalid DN format"
        assert (
            FlextLdapConstants.Messages.INVALID_SEARCH_FILTER
            == "Invalid LDAP search filter"
        )
        assert "{0}" in FlextLdapConstants.Messages.CONNECTION_FAILED_WITH_CONTEXT

    def test_messages_error_constants(self) -> None:
        """Test messages error constants."""
        assert "{error}" in FlextLdapConstants.Messages.EMAIL_VALIDATION_FAILED
        assert FlextLdapConstants.Messages.DN_CANNOT_BE_EMPTY == "DN cannot be empty"
        assert (
            FlextLdapConstants.Messages.CLIENT_NOT_INITIALIZED
            == "Client not initialized"
        )
        assert (
            FlextLdapConstants.Messages.NO_SERVER_OPERATIONS_AVAILABLE
            == "No server operations available"
        )

    def test_errors_ldap_constants(self) -> None:
        """Test LDAP error code constants."""
        assert FlextLdapConstants.Errors.LDAP_BIND_ERROR == "LDAP_BIND_ERROR"
        assert FlextLdapConstants.Errors.LDAP_SEARCH_ERROR == "LDAP_SEARCH_ERROR"
        assert FlextLdapConstants.Errors.LDAP_ADD_ERROR == "LDAP_ADD_ERROR"
        assert FlextLdapConstants.Errors.LDAP_MODIFY_ERROR == "LDAP_MODIFY_ERROR"
        assert FlextLdapConstants.Errors.LDAP_DELETE_ERROR == "LDAP_DELETE_ERROR"
        assert FlextLdapConstants.Errors.LDAP_INVALID_DN == "LDAP_INVALID_DN"
        assert FlextLdapConstants.Errors.LDAP_INVALID_FILTER == "LDAP_INVALID_FILTER"

    def test_defaults_search_constants(self) -> None:
        """Test defaults search constants."""
        assert FlextLdapConstants.Defaults.DEFAULT_SEARCH_FILTER == "(objectClass=*)"
        assert not FlextLdapConstants.Defaults.DEFAULT_SEARCH_BASE
        assert FlextLdapConstants.Defaults.DEFAULT_SERVICE_NAME == "flext-ldap"
        assert FlextLdapConstants.Defaults.DEFAULT_SERVICE_VERSION == "1.0.0"

    def test_defaults_ldap_user_constants(self) -> None:
        """Test defaults LDAP user constants."""
        assert FlextLdapConstants.Defaults.VALID_LDAP_USER_NAME == "testuser"
        assert (
            FlextLdapConstants.Defaults.VALID_LDAP_USER_DESCRIPTION == "Test LDAP User"
        )

    def test_defaults_model_constants(self) -> None:
        """Test defaults model constants."""
        assert FlextLdapConstants.Defaults.DEFAULT_DEPARTMENT == "IT"
        assert FlextLdapConstants.Defaults.DEFAULT_ORGANIZATION == "Company"
        assert FlextLdapConstants.Defaults.DEFAULT_TITLE == "Employee"
        assert FlextLdapConstants.Defaults.DEFAULT_STATUS == "active"

    def test_defaults_limits_constants(self) -> None:
        """Test defaults limits constants."""
        assert FlextLdapConstants.Defaults.ERROR_SUMMARY_MAX_ITEMS == 3
        assert FlextLdapConstants.Defaults.MIN_USERNAME_LENGTH == 3
        assert FlextLdapConstants.Defaults.MIN_GROUP_NAME_LENGTH == 2
        assert FlextLdapConstants.Defaults.MAX_GROUP_DESCRIPTION_LENGTH == 500
        assert FlextLdapConstants.Defaults.MAX_DESCRIPTION_LENGTH == 500
        assert FlextLdapConstants.Defaults.MIN_CONNECTION_ARGS == 3

    def test_ldap_retry_constants(self) -> None:
        """Test LDAP retry constants."""
        assert FlextLdapConstants.LdapRetry.SERVER_READY_RETRY_DELAY == 2
        assert FlextLdapConstants.LdapRetry.SERVER_READY_MAX_RETRIES == 10
        assert FlextLdapConstants.LdapRetry.SERVER_READY_TIMEOUT == 30
        assert FlextLdapConstants.LdapRetry.CONNECTION_RETRY_DELAY == 1.0
        assert FlextLdapConstants.LdapRetry.CONNECTION_MAX_RETRIES == 3

    def test_acl_format_constants(self) -> None:
        """Test ACL format constants."""
        assert FlextLdapConstants.AclFormat.OPENLDAP == "openldap"
        assert FlextLdapConstants.AclFormat.ORACLE == "oracle"
        assert FlextLdapConstants.AclFormat.ACI == "aci"
        assert FlextLdapConstants.AclFormat.ACTIVE_DIRECTORY == "active_directory"
        assert FlextLdapConstants.AclFormat.UNIFIED == "unified"
        assert FlextLdapConstants.AclFormat.AUTO == "auto"

    def test_dict_keys_acl_constants(self) -> None:
        """Test dictionary keys ACL constants."""
        assert FlextLdapConstants.DictKeys.OPERATION == "operation"
        assert FlextLdapConstants.DictKeys.ACL_STRING == "acl_string"
        assert FlextLdapConstants.DictKeys.ACL_DATA == "acl_data"
        assert FlextLdapConstants.DictKeys.TARGET_FORMAT == "target_format"
        assert FlextLdapConstants.DictKeys.FORMAT == "format"

    def test_dict_keys_entry_constants(self) -> None:
        """Test dictionary keys entry constants."""
        assert FlextLdapConstants.DictKeys.DN == "dn"
        assert FlextLdapConstants.DictKeys.UID == "uid"
        assert FlextLdapConstants.DictKeys.CN == "cn"
        assert FlextLdapConstants.DictKeys.SN == "sn"
        assert FlextLdapConstants.DictKeys.MAIL == "mail"
        assert FlextLdapConstants.DictKeys.GIVEN_NAME == "given_name"
        assert FlextLdapConstants.DictKeys.TELEPHONE_NUMBER == "telephoneNumber"
        assert FlextLdapConstants.DictKeys.MOBILE == "mobile"
        assert FlextLdapConstants.DictKeys.DEPARTMENT == "department"
        assert FlextLdapConstants.DictKeys.TITLE == "title"
        assert FlextLdapConstants.DictKeys.ORGANIZATION == "organization"
        assert FlextLdapConstants.DictKeys.ORGANIZATIONAL_UNIT == "organizationalUnit"
        assert FlextLdapConstants.DictKeys.USER_PASSWORD == "user_password"

    def test_dict_keys_connection_constants(self) -> None:
        """Test dictionary keys connection constants."""
        assert FlextLdapConstants.DictKeys.LDAP_SERVER == "ldap_server"
        assert FlextLdapConstants.DictKeys.LDAP_PORT == "ldap_port"
        assert FlextLdapConstants.DictKeys.BIND_DN == "bind_dn"
        assert FlextLdapConstants.DictKeys.BIND_PASSWORD == "bind_password"
        assert FlextLdapConstants.DictKeys.LDAP_BIND_PASSWORD == "ldap_bind_password"

    def test_dict_keys_operation_constants(self) -> None:
        """Test dictionary keys operation constants."""
        assert FlextLdapConstants.DictKeys.OPERATION_TYPE == "operation_type"
        assert FlextLdapConstants.DictKeys.SERVER == "server"
        assert FlextLdapConstants.DictKeys.SERVER_URI == "server_uri"
        assert FlextLdapConstants.DictKeys.PORT == "port"
        assert FlextLdapConstants.DictKeys.ATTRIBUTES == "attributes"
        assert FlextLdapConstants.DictKeys.ATTRIBUTE == "attribute"
        assert FlextLdapConstants.DictKeys.VALUES == "values"

    def test_dict_keys_config_constants(self) -> None:
        """Test dictionary keys config constants."""
        assert FlextLdapConstants.DictKeys.DEFAULT_TIMEOUT == "default_timeout"
        assert FlextLdapConstants.DictKeys.MAX_PAGE_SIZE == "max_page_size"
        assert (
            FlextLdapConstants.DictKeys.SUPPORTS_OPERATIONAL_ATTRS
            == "supports_operational_attrs"
        )
        assert FlextLdapConstants.DictKeys.SCHEMA_SUBENTRY == "schema_subentry"

    def test_dict_keys_acl_specific_constants(self) -> None:
        """Test dictionary keys ACL-specific constants."""
        assert FlextLdapConstants.DictKeys.ACL_ATTRIBUTE == "acl_attribute"
        assert FlextLdapConstants.DictKeys.ACL_FORMAT == "acl_format"
        assert FlextLdapConstants.DictKeys.SOURCE_FORMAT == "source_format"
        assert FlextLdapConstants.DictKeys.PERMISSIONS == "permissions"
        assert FlextLdapConstants.DictKeys.SUBJECT == "subject"
        assert FlextLdapConstants.DictKeys.TARGET == "target"
        assert FlextLdapConstants.DictKeys.TARGET_TYPE == "target_type"
        assert FlextLdapConstants.DictKeys.ACCESS == "access"
        assert FlextLdapConstants.DictKeys.WHO == "who"
        assert FlextLdapConstants.DictKeys.TYPE == "type"
        assert FlextLdapConstants.DictKeys.DESCRIPTION == "description"
        # Note: SUCCESS and GENERIC keys don't exist in current DictKeys definition

    @pytest.mark.skip(reason="Permission is now a Literal type in FlextLdapConstants.Types (Pydantic v2 refactoring)")
    def test_permission_constants(self) -> None:
        """Test permission constants."""
        assert FlextLdapConstants.Permission.READ == "read"
        assert FlextLdapConstants.Permission.WRITE == "write"
        assert FlextLdapConstants.Permission.ADD == "add"
        assert FlextLdapConstants.Permission.DELETE == "delete"
        assert FlextLdapConstants.Permission.SEARCH == "search"
        assert FlextLdapConstants.Permission.COMPARE == "compare"
        assert FlextLdapConstants.Permission.BROWSE == "browse"
        assert FlextLdapConstants.Permission.PROXY == "proxy"
        assert FlextLdapConstants.Permission.AUTH == "auth"
        assert FlextLdapConstants.Permission.ALL == "all"
        assert FlextLdapConstants.Permission.NONE == "none"

    @pytest.mark.skip(reason="SubjectType is now a Literal type in FlextLdapConstants.Types (Pydantic v2 refactoring)")
    def test_subject_type_constants(self) -> None:
        """Test subject type constants."""
        assert FlextLdapConstants.SubjectType.USER == "user"
        assert FlextLdapConstants.SubjectType.GROUP == "group"
        assert FlextLdapConstants.SubjectType.DN == "dn"
        assert FlextLdapConstants.SubjectType.SELF == "self"
        assert FlextLdapConstants.SubjectType.ANONYMOUS == "anonymous"
        assert FlextLdapConstants.SubjectType.AUTHENTICATED == "authenticated"
        assert FlextLdapConstants.SubjectType.ANYONE == "anyone"

    @pytest.mark.skip(reason="TargetType is now a Literal type alias, not a class")
    def test_target_type_constants(self) -> None:
        """Test target type constants.

        NOTE: TargetType was refactored to Literal["dn", "attributes", "entry", "filter"]
        type alias, so attribute access pattern is no longer applicable.
        """

    @pytest.mark.skip(reason="AclKeywords class removed as dead code during constants cleanup")
    def test_openldap_keywords_constants(self) -> None:
        """Test OpenLDAP keywords constants."""
        assert FlextLdapConstants.OpenLdapKeywords.ACCESS_TO == "access to"
        assert FlextLdapConstants.OpenLdapKeywords.BY == "by"
        assert FlextLdapConstants.OpenLdapKeywords.ATTRS == "attrs="
        assert FlextLdapConstants.OpenLdapKeywords.DN_EXACT == "dn.exact="
        assert FlextLdapConstants.OpenLdapKeywords.DN_REGEX == "dn.regex="
        assert FlextLdapConstants.OpenLdapKeywords.FILTER == "filter="

    @pytest.mark.skip(reason="AclKeywords class removed as dead code during constants cleanup")
    def test_oracle_keywords_constants(self) -> None:
        """Test Oracle keywords constants."""
        assert FlextLdapConstants.OracleKeywords.ACCESS_TO == "access to"
        assert FlextLdapConstants.OracleKeywords.ATTR == "attr="
        assert FlextLdapConstants.OracleKeywords.ENTRY == "entry"
        assert FlextLdapConstants.OracleKeywords.BY == "by"
        assert FlextLdapConstants.OracleKeywords.GROUP == "group="
        assert FlextLdapConstants.OracleKeywords.USER == "user="

    @pytest.mark.skip(reason="AclKeywords class removed as dead code during constants cleanup")
    def test_aci_keywords_constants(self) -> None:
        """Test ACI keywords constants."""
        assert FlextLdapConstants.AciKeywords.TARGET == "target"
        assert FlextLdapConstants.AciKeywords.TARGETATTR == "targetattr"
        assert FlextLdapConstants.AciKeywords.TARGETFILTER == "targetfilter"
        assert FlextLdapConstants.AciKeywords.VERSION == "version 3.0"
        assert FlextLdapConstants.AciKeywords.ACL == "acl"
        assert FlextLdapConstants.AciKeywords.ALLOW == "allow"
        assert FlextLdapConstants.AciKeywords.DENY == "deny"
        assert FlextLdapConstants.AciKeywords.USERDN == "userdn"
        assert FlextLdapConstants.AciKeywords.GROUPDN == "groupdn"

    def test_conversion_warnings_constants(self) -> None:
        """Test conversion warnings constants (now in AclParsing)."""
        # After constants cleanup, conversion warnings are in AclParsing class
        assert (
            "{permission}"
            in FlextLdapConstants.AclParsing.ACL_PERMISSION_NOT_SUPPORTED
        )
        assert (
            "{format}" in FlextLdapConstants.AclParsing.ACL_PERMISSION_NOT_SUPPORTED
        )
        assert "{feature}" in FlextLdapConstants.AclParsing.ACL_FEATURE_LOSS
        assert "{format}" in FlextLdapConstants.AclParsing.ACL_FEATURE_LOSS
        assert "Syntax" in FlextLdapConstants.AclParsing.ACL_SYNTAX_MISMATCH

    @pytest.mark.skip(reason="Parsing class was removed from constants")
    def test_parsing_constants(self) -> None:
        """Test parsing constants.

        NOTE: Parsing class has been removed from FlextLdapConstants in the
        refactoring process.
        """

    @pytest.mark.skip(reason="LiteralTypes refactored to module-level type aliases")
    def test_literal_types_search_scope(self) -> None:
        """Test literal types search scope constants.

        NOTE: SearchScope was refactored to module-level type alias:
        type SearchScope = Literal["base", "onelevel", "subtree", "children"]
        """

    @pytest.mark.skip(reason="LiteralTypes refactored to module-level type aliases")
    def test_literal_types_modify_operations(self) -> None:
        """Test literal types modify operation constants.

        NOTE: ModifyOperation was refactored to module-level type alias:
        type ModifyOperation = Literal["add", "delete", "replace"]
        """

    @pytest.mark.skip(reason="LiteralTypes refactored to module-level type aliases")
    def test_literal_types_connection_state(self) -> None:
        """Test literal types connection state constants.

        NOTE: ConnectionState was refactored to module-level type alias:
        type ConnectionState = Literal["unbound", "bound", "closed", "error"]
        """

    @pytest.mark.skip(reason="OperationType is now a Literal type alias, not a class")
    def test_literal_types_operation_types(self) -> None:
        """Test literal types operation type constants.

        NOTE: OperationType was refactored to a Literal type alias, so
        attribute access pattern is no longer applicable.
        """

    @pytest.mark.skip(reason="LiteralTypes refactored to module-level type aliases")
    def test_literal_types_acl_operations(self) -> None:
        """Test literal types ACL operation constants.

        NOTE: ACL operations are now handled differently in the refactored API.
        """

    @pytest.mark.skip(reason="SecurityLevel refactored to module-level type alias")
    def test_literal_types_security(self) -> None:
        """Test literal types security constants.

        NOTE: SecurityLevel was refactored to module-level type alias:
        type SecurityLevel = Literal["none", "simple", "sasl"]
        """

    @pytest.mark.skip(
        reason="AuthenticationMethod refactored to module-level type alias"
    )
    def test_literal_types_authentication(self) -> None:
        """Test literal types authentication constants.

        NOTE: AuthenticationMethod was refactored to module-level type alias:
        type AuthenticationMethod = Literal["simple", "sasl", "external"]
        """

    @pytest.mark.skip(reason="ConnectionInfo refactored to module-level type alias")
    def test_literal_types_connection_info(self) -> None:
        """Test literal types connection info constants.

        NOTE: ConnectionInfo was refactored to module-level type alias:
        type ConnectionInfo = Literal["ALL", "DSA", "NO_INFO", "SCHEMA"]
        """

    @pytest.mark.skip(reason="ConnectionMode refactored to module-level type alias")
    def test_literal_types_connection_mode(self) -> None:
        """Test literal types connection mode constants.

        NOTE: ConnectionMode was refactored to module-level type alias:
        type ConnectionMode = Literal["sync", "async"]
        """

    @pytest.mark.skip(reason="IpMode refactored to module-level type alias")
    def test_literal_types_ip_mode(self) -> None:
        """Test literal types IP mode constants.

        NOTE: IpMode was refactored to module-level type alias:
        type IpMode = Literal["IP_SYSTEM_DEFAULT", "IP_V4_ONLY", "IP_V4_PREFERRED", "IP_V6_ONLY", "IP_V6_PREFERRED"]
        """

    def test_version_constants(self) -> None:
        """Test version constants."""
        assert FlextLdapConstants.Version.CURRENT_VERSION == "0.9.0"
        assert FlextLdapConstants.Version.VERSION_INFO == (0, 9, 0)

    def test_version_get_version_method(self) -> None:
        """Test version get_version method."""
        version = FlextLdapConstants.Version.get_version()
        assert version == "0.9.0"
        assert isinstance(version, str)

    def test_version_get_version_info_method(self) -> None:
        """Test version get_version_info method."""
        version_info = FlextLdapConstants.Version.get_version_info()
        assert version_info == (0, 9, 0)
        assert isinstance(version_info, tuple)
        assert len(version_info) == 3
