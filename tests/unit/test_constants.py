"""Tests for FlextLdapConstants module."""

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
        assert FlextLdapConstants.Attributes.COMMON_NAME == "cn"
        assert FlextLdapConstants.Attributes.SURNAME == "sn"
        assert FlextLdapConstants.Attributes.GIVEN_NAME == "givenName"
        assert FlextLdapConstants.Attributes.DISPLAY_NAME == "displayName"
        assert FlextLdapConstants.Attributes.USER_ID == "uid"
        assert FlextLdapConstants.Attributes.MAIL == "mail"
        assert FlextLdapConstants.Attributes.USER_PASSWORD == "userPassword"

    def test_attributes_group_constants(self) -> None:
        """Test group attribute constants."""
        assert FlextLdapConstants.Attributes.MEMBER == "member"
        assert FlextLdapConstants.Attributes.UNIQUE_MEMBER == "uniqueMember"
        assert FlextLdapConstants.Attributes.MEMBER_OF == "memberOf"
        assert FlextLdapConstants.Attributes.OWNER == "owner"

    def test_attributes_minimal_lists(self) -> None:
        """Test minimal attribute lists."""
        assert FlextLdapConstants.Attributes.MINIMAL_USER_ATTRS == ["uid", "cn", "mail"]
        assert FlextLdapConstants.Attributes.MINIMAL_GROUP_ATTRS == ["cn", "member"]

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
        assert FlextLdapConstants.Attributes.ALL_USER_ATTRS == expected_user_attrs

        expected_group_attrs = [
            "objectClass",
            "cn",
            "description",
            "member",
            "uniqueMember",
            "owner",
            "memberOf",
        ]
        assert FlextLdapConstants.Attributes.ALL_GROUP_ATTRS == expected_group_attrs

    def test_attributes_get_group_attributes_method(self) -> None:
        """Test get_group_attributes method returns copy."""
        result = FlextLdapConstants.Attributes.get_group_attributes()
        assert result == FlextLdapConstants.Attributes.ALL_GROUP_ATTRS
        # Verify it's a copy (modification doesn't affect original)
        result.append("test")
        assert "test" not in FlextLdapConstants.Attributes.ALL_GROUP_ATTRS

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
        assert FlextLdapConstants.LdapAttributeNames.TELEPHONE_NUMBER == "telephoneNumber"
        assert FlextLdapConstants.LdapAttributeNames.MOBILE == "mobile"
        assert FlextLdapConstants.LdapAttributeNames.DEPARTMENT == "department"
        assert FlextLdapConstants.LdapAttributeNames.TITLE == "title"
        assert FlextLdapConstants.LdapAttributeNames.OU == "ou"
        assert FlextLdapConstants.LdapAttributeNames.DESCRIPTION == "description"
        assert FlextLdapConstants.LdapAttributeNames.EMPLOYEE_NUMBER == "employeeNumber"
        assert FlextLdapConstants.LdapAttributeNames.EMPLOYEE_TYPE == "employeeType"

    def test_object_classes_constants(self) -> None:
        """Test object classes constants."""
        assert FlextLdapConstants.ObjectClasses.TOP == "top"
        assert FlextLdapConstants.ObjectClasses.PERSON == "person"
        assert FlextLdapConstants.ObjectClasses.ORGANIZATIONAL_PERSON == "organizationalPerson"
        assert FlextLdapConstants.ObjectClasses.INET_ORG_PERSON == "inetOrgPerson"
        assert FlextLdapConstants.ObjectClasses.ORGANIZATIONAL_UNIT == "organizationalUnit"
        assert FlextLdapConstants.ObjectClasses.GROUP_OF_NAMES == "groupOfNames"
        assert FlextLdapConstants.ObjectClasses.GROUP_OF_UNIQUE_NAMES == "groupOfUniqueNames"

    def test_filters_user_constants(self) -> None:
        """Test filter user constants."""
        assert FlextLdapConstants.Filters.DEFAULT_USER_FILTER == "(objectClass=inetOrgPerson)"
        assert FlextLdapConstants.Filters.ALL_USERS_FILTER == "(objectClass=person)"
        assert "(objectClass=inetOrgPerson)" in FlextLdapConstants.Filters.ACTIVE_USERS_FILTER

    def test_filters_group_constants(self) -> None:
        """Test filter group constants."""
        assert FlextLdapConstants.Filters.DEFAULT_GROUP_FILTER == "(objectClass=groupOfNames)"
        assert "(objectClass=groupOfNames)" in FlextLdapConstants.Filters.ALL_GROUPS_FILTER

    def test_filters_common_constants(self) -> None:
        """Test filter common constants."""
        assert FlextLdapConstants.Filters.ALL_ENTRIES_FILTER == "(objectClass=*)"
        assert FlextLdapConstants.Filters.ORGANIZATIONAL_UNITS_FILTER == "(objectClass=organizationalUnit)"

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
        assert FlextLdapConstants.Messages.HOST_CANNOT_BE_EMPTY == "Host cannot be empty"
        assert FlextLdapConstants.Messages.CONNECTION_FAILED == "Connection failed"
        assert "{0}" in FlextLdapConstants.Messages.FIELD_CANNOT_BE_EMPTY
        assert FlextLdapConstants.Messages.INVALID_DN_FORMAT == "Invalid DN format"
        assert FlextLdapConstants.Messages.INVALID_SEARCH_FILTER == "Invalid LDAP search filter"
        assert "{0}" in FlextLdapConstants.Messages.CONNECTION_FAILED_WITH_CONTEXT

    def test_messages_error_constants(self) -> None:
        """Test messages error constants."""
        assert "{error}" in FlextLdapConstants.Messages.EMAIL_VALIDATION_FAILED
        assert FlextLdapConstants.Messages.DN_CANNOT_BE_EMPTY == "DN cannot be empty"
        assert FlextLdapConstants.Messages.CLIENT_NOT_INITIALIZED == "Client not initialized"
        assert FlextLdapConstants.Messages.NO_SERVER_OPERATIONS_AVAILABLE == "No server operations available"

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
        assert FlextLdapConstants.Defaults.DEFAULT_SEARCH_BASE == ""
        assert FlextLdapConstants.Defaults.DEFAULT_SERVICE_NAME == "flext-ldap"
        assert FlextLdapConstants.Defaults.DEFAULT_SERVICE_VERSION == "1.0.0"

    def test_defaults_ldap_user_constants(self) -> None:
        """Test defaults LDAP user constants."""
        assert FlextLdapConstants.Defaults.VALID_LDAP_USER_NAME == "testuser"
        assert FlextLdapConstants.Defaults.VALID_LDAP_USER_DESCRIPTION == "Test LDAP User"

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
        assert FlextLdapConstants.DictKeys.TELEPHONE_NUMBER == "telephone_number"
        assert FlextLdapConstants.DictKeys.MOBILE == "mobile"
        assert FlextLdapConstants.DictKeys.DEPARTMENT == "department"
        assert FlextLdapConstants.DictKeys.TITLE == "title"
        assert FlextLdapConstants.DictKeys.ORGANIZATION == "organization"
        assert FlextLdapConstants.DictKeys.ORGANIZATIONAL_UNIT == "organizational_unit"
        assert FlextLdapConstants.DictKeys.USER_PASSWORD == "user_password"

    def test_dict_keys_search_constants(self) -> None:
        """Test dictionary keys search constants."""
        assert FlextLdapConstants.DictKeys.BASE_DN == "base_dn"
        assert FlextLdapConstants.DictKeys.FILTER == "filter"
        assert FlextLdapConstants.DictKeys.FILTER_STR == "filter_str"

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
        assert FlextLdapConstants.DictKeys.INDENT == "indent"
        assert FlextLdapConstants.DictKeys.SORT_KEYS == "sort_keys"
        assert FlextLdapConstants.DictKeys.INCLUDE_CREDENTIALS == "include_credentials"
        assert FlextLdapConstants.DictKeys.DEFAULT_TIMEOUT == "default_timeout"
        assert FlextLdapConstants.DictKeys.MAX_PAGE_SIZE == "max_page_size"
        assert FlextLdapConstants.DictKeys.SUPPORTS_OPERATIONAL_ATTRS == "supports_operational_attrs"
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
        assert FlextLdapConstants.DictKeys.SUCCESS == "success"
        assert FlextLdapConstants.DictKeys.GENERIC == "generic"

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

    def test_subject_type_constants(self) -> None:
        """Test subject type constants."""
        assert FlextLdapConstants.SubjectType.USER == "user"
        assert FlextLdapConstants.SubjectType.GROUP == "group"
        assert FlextLdapConstants.SubjectType.DN == "dn"
        assert FlextLdapConstants.SubjectType.SELF == "self"
        assert FlextLdapConstants.SubjectType.ANONYMOUS == "anonymous"
        assert FlextLdapConstants.SubjectType.AUTHENTICATED == "authenticated"
        assert FlextLdapConstants.SubjectType.ANYONE == "anyone"

    def test_target_type_constants(self) -> None:
        """Test target type constants."""
        assert FlextLdapConstants.TargetType.DN == "dn"
        assert FlextLdapConstants.TargetType.ATTRIBUTES == "attributes"
        assert FlextLdapConstants.TargetType.ENTRY == "entry"
        assert FlextLdapConstants.TargetType.FILTER == "filter"

    def test_openldap_keywords_constants(self) -> None:
        """Test OpenLDAP keywords constants."""
        assert FlextLdapConstants.OpenLdapKeywords.ACCESS_TO == "access to"
        assert FlextLdapConstants.OpenLdapKeywords.BY == "by"
        assert FlextLdapConstants.OpenLdapKeywords.ATTRS == "attrs="
        assert FlextLdapConstants.OpenLdapKeywords.DN_EXACT == "dn.exact="
        assert FlextLdapConstants.OpenLdapKeywords.DN_REGEX == "dn.regex="
        assert FlextLdapConstants.OpenLdapKeywords.FILTER == "filter="

    def test_oracle_keywords_constants(self) -> None:
        """Test Oracle keywords constants."""
        assert FlextLdapConstants.OracleKeywords.ACCESS_TO == "access to"
        assert FlextLdapConstants.OracleKeywords.ATTR == "attr="
        assert FlextLdapConstants.OracleKeywords.ENTRY == "entry"
        assert FlextLdapConstants.OracleKeywords.BY == "by"
        assert FlextLdapConstants.OracleKeywords.GROUP == "group="
        assert FlextLdapConstants.OracleKeywords.USER == "user="

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
        """Test conversion warnings constants."""
        assert "{permission}" in FlextLdapConstants.ConversionWarnings.PERMISSION_NOT_SUPPORTED
        assert "{format}" in FlextLdapConstants.ConversionWarnings.PERMISSION_NOT_SUPPORTED
        assert "{feature}" in FlextLdapConstants.ConversionWarnings.FEATURE_LOSS
        assert "{format}" in FlextLdapConstants.ConversionWarnings.FEATURE_LOSS
        assert "Syntax pattern" in FlextLdapConstants.ConversionWarnings.SYNTAX_MISMATCH

    def test_parsing_constants(self) -> None:
        """Test parsing constants."""
        assert FlextLdapConstants.Parsing.MIN_ACL_PARTS == 4
        assert FlextLdapConstants.Parsing.ACL_RULE_PARTS == 2
        assert FlextLdapConstants.Parsing.OPENLDAP_PREFIX_LENGTH == 3
        assert FlextLdapConstants.Parsing.MIN_OC_LENGTH == 3

    def test_literal_types_search_scope(self) -> None:
        """Test literal types search scope constants."""
        assert FlextLdapConstants.LiteralTypes.SEARCH_SCOPE_BASE == "BASE"
        assert FlextLdapConstants.LiteralTypes.SEARCH_SCOPE_LEVEL == "LEVEL"
        assert FlextLdapConstants.LiteralTypes.SEARCH_SCOPE_SUBTREE == "SUBTREE"

    def test_literal_types_modify_operations(self) -> None:
        """Test literal types modify operation constants."""
        assert FlextLdapConstants.LiteralTypes.MODIFY_ADD == "MODIFY_ADD"
        assert FlextLdapConstants.LiteralTypes.MODIFY_DELETE == "MODIFY_DELETE"
        assert FlextLdapConstants.LiteralTypes.MODIFY_REPLACE == "MODIFY_REPLACE"

    def test_literal_types_connection_state(self) -> None:
        """Test literal types connection state constants."""
        assert FlextLdapConstants.LiteralTypes.CONNECTION_STATE_UNBOUND == "unbound"
        assert FlextLdapConstants.LiteralTypes.CONNECTION_STATE_BOUND == "bound"
        assert FlextLdapConstants.LiteralTypes.CONNECTION_STATE_CLOSED == "closed"
        assert FlextLdapConstants.LiteralTypes.CONNECTION_STATE_ERROR == "error"

    def test_literal_types_operation_types(self) -> None:
        """Test literal types operation type constants."""
        assert FlextLdapConstants.LiteralTypes.OPERATION_SEARCH == "search"
        assert FlextLdapConstants.LiteralTypes.OPERATION_ADD == "add"
        assert FlextLdapConstants.LiteralTypes.OPERATION_MODIFY == "modify"
        assert FlextLdapConstants.LiteralTypes.OPERATION_DELETE == "delete"
        assert FlextLdapConstants.LiteralTypes.OPERATION_COMPARE == "compare"
        assert FlextLdapConstants.LiteralTypes.OPERATION_EXTENDED == "extended"

    def test_literal_types_acl_operations(self) -> None:
        """Test literal types ACL operation constants."""
        assert FlextLdapConstants.LiteralTypes.OPERATION_PARSE == "parse"
        assert FlextLdapConstants.LiteralTypes.OPERATION_CONVERT == "convert"

    def test_literal_types_security(self) -> None:
        """Test literal types security constants."""
        assert FlextLdapConstants.LiteralTypes.SECURITY_NONE == "none"
        assert FlextLdapConstants.LiteralTypes.SECURITY_SIMPLE == "simple"
        assert FlextLdapConstants.LiteralTypes.SECURITY_SASL == "sasl"

    def test_literal_types_authentication(self) -> None:
        """Test literal types authentication constants."""
        assert FlextLdapConstants.LiteralTypes.AUTH_SIMPLE == "simple"
        assert FlextLdapConstants.LiteralTypes.AUTH_SASL == "sasl"
        assert FlextLdapConstants.LiteralTypes.AUTH_EXTERNAL == "external"

    def test_literal_types_connection_info(self) -> None:
        """Test literal types connection info constants."""
        assert FlextLdapConstants.LiteralTypes.CONNECTION_INFO_ALL == "ALL"
        assert FlextLdapConstants.LiteralTypes.CONNECTION_INFO_DSA == "DSA"
        assert FlextLdapConstants.LiteralTypes.CONNECTION_INFO_NO_INFO == "NO_INFO"
        assert FlextLdapConstants.LiteralTypes.CONNECTION_INFO_SCHEMA == "SCHEMA"

    def test_literal_types_connection_mode(self) -> None:
        """Test literal types connection mode constants."""
        assert FlextLdapConstants.LiteralTypes.CONNECTION_MODE_SYNC == "sync"
        assert FlextLdapConstants.LiteralTypes.CONNECTION_MODE_ASYNC == "async"

    def test_literal_types_ip_mode(self) -> None:
        """Test literal types IP mode constants."""
        assert FlextLdapConstants.LiteralTypes.IP_MODE_SYSTEM_DEFAULT == "IP_SYSTEM_DEFAULT"
        assert FlextLdapConstants.LiteralTypes.IP_MODE_V4_ONLY == "IP_V4_ONLY"
        assert FlextLdapConstants.LiteralTypes.IP_MODE_V4_PREFERRED == "IP_V4_PREFERRED"
        assert FlextLdapConstants.LiteralTypes.IP_MODE_V6_ONLY == "IP_V6_ONLY"
        assert FlextLdapConstants.LiteralTypes.IP_MODE_V6_PREFERRED == "IP_V6_PREFERRED"

    def test_literal_types_project_types(self) -> None:
        """Test literal types project type constants."""
        assert FlextLdapConstants.LiteralTypes.PROJECT_TYPE_LDAP_SERVICE == "ldap-service"
        assert FlextLdapConstants.LiteralTypes.PROJECT_TYPE_DIRECTORY_SERVICE == "directory-service"
        assert FlextLdapConstants.LiteralTypes.PROJECT_TYPE_LDAP_CLIENT == "ldap-client"
        assert FlextLdapConstants.LiteralTypes.PROJECT_TYPE_IDENTITY_PROVIDER == "identity-provider"
        assert FlextLdapConstants.LiteralTypes.PROJECT_TYPE_LDAP_SYNC == "ldap-sync"
        assert FlextLdapConstants.LiteralTypes.PROJECT_TYPE_DIRECTORY_SYNC == "directory-sync"
        assert FlextLdapConstants.LiteralTypes.PROJECT_TYPE_USER_PROVISIONING == "user-provisioning"
        assert FlextLdapConstants.LiteralTypes.PROJECT_TYPE_LDAP_GATEWAY == "ldap-gateway"
        assert FlextLdapConstants.LiteralTypes.PROJECT_TYPE_AUTHENTICATION_SERVICE == "authentication-service"
        assert FlextLdapConstants.LiteralTypes.PROJECT_TYPE_SSO_SERVICE == "sso-service"
        assert FlextLdapConstants.LiteralTypes.PROJECT_TYPE_DIRECTORY_API == "directory-api"
        assert FlextLdapConstants.LiteralTypes.PROJECT_TYPE_LDAP_PROXY == "ldap-proxy"
        assert FlextLdapConstants.LiteralTypes.PROJECT_TYPE_IDENTITY_MANAGEMENT == "identity-management"
        assert FlextLdapConstants.LiteralTypes.PROJECT_TYPE_USER_DIRECTORY == "user-directory"
        assert FlextLdapConstants.LiteralTypes.PROJECT_TYPE_GROUP_MANAGEMENT == "group-management"
        assert FlextLdapConstants.LiteralTypes.PROJECT_TYPE_LDAP_MIGRATION == "ldap-migration"

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

    def test_servers_constants(self) -> None:
        """Test server type constants."""
        assert FlextLdapConstants.Servers.OPENLDAP1 == "openldap1"
        assert FlextLdapConstants.Servers.OPENLDAP2 == "openldap2"
        assert FlextLdapConstants.Servers.OID == "oid"
        assert FlextLdapConstants.Servers.OUD == "oud"
        assert FlextLdapConstants.Servers.AD == "ad"
        assert FlextLdapConstants.Servers.GENERIC == "generic"
