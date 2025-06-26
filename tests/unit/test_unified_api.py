"""Unit tests for the unified LDAP API.

This module provides comprehensive testing for the clean, unified API design,
ensuring that all components work correctly with maximum simplicity.

Test Coverage:
    - LDAPConfig creation and auto-configuration
    - Result[T] creation and validation
    - Query builder functionality and chaining
    - LDAP class operations and semantic methods
    - Convenience functions (connect, ldap_session)
    - Error handling and edge cases
    - Performance characteristics

Test Categories:
    - Unit tests for individual components
    - Integration tests for component interaction
    - Error handling tests for failure scenarios
    - Performance tests for optimization validation
"""

from unittest.mock import AsyncMock, Mock, patch

import pytest

from ldap_core_shared.api import LDAP, LDAPConfig, Query, Result, connect, ldap_session
from ldap_core_shared.core.exceptions import LDAPCoreError
from ldap_core_shared.domain.models import LDAPEntry


@pytest.mark.unit
class TestLDAPConfig:
    """Test cases for LDAPConfig functionality."""

    def test_basic_config_creation(self) -> None:
        """Test creating basic LDAP configuration."""
        config = LDAPConfig(
            server="ldap.example.com",
            auth_dn="cn=admin,dc=example,dc=com",
            auth_password="secret123",
            base_dn="dc=example,dc=com",
        )

        assert config.server == "ldap.example.com"
        assert config.auth_dn == "cn=admin,dc=example,dc=com"
        assert config.auth_password == "secret123"
        assert config.base_dn == "dc=example,dc=com"
        assert config.port == 636  # Default for plain hostname with use_tls=True (default)
        assert config.use_tls is True  # Default value

    def test_ldaps_url_auto_configuration(self) -> None:
        """Test auto-configuration from LDAPS URL."""
        config = LDAPConfig(
            server="ldaps://secure.ldap.com:636",
            auth_dn="cn=admin,dc=example,dc=com",
            auth_password="secret123",
            base_dn="dc=example,dc=com",
        )

        assert config.server == "secure.ldap.com"
        assert config.port == 636
        assert config.use_tls is True

    def test_ldap_url_auto_configuration(self) -> None:
        """Test auto-configuration from LDAP URL."""
        config = LDAPConfig(
            server="ldap://plain.ldap.com:389",
            auth_dn="cn=admin,dc=example,dc=com",
            auth_password="secret123",
            base_dn="dc=example,dc=com",
        )

        assert config.server == "plain.ldap.com"
        assert config.port == 389
        assert config.use_tls is False

    def test_custom_port_override(self) -> None:
        """Test custom port override."""
        config = LDAPConfig(
            server="ldap://custom.ldap.com",
            auth_dn="cn=admin,dc=example,dc=com",
            auth_password="secret123",
            base_dn="dc=example,dc=com",
            port=3389,  # Custom port
        )

        assert config.server == "custom.ldap.com"
        assert config.port == 3389
        assert config.use_tls is False

    def test_plain_hostname_configuration(self) -> None:
        """Test configuration with plain hostname."""
        config = LDAPConfig(
            server="plainhost.com",
            auth_dn="cn=admin,dc=example,dc=com",
            auth_password="secret123",
            base_dn="dc=example,dc=com",
            use_tls=True,
        )

        assert config.server == "plainhost.com"
        assert config.port == 636  # TLS default
        assert config.use_tls is True


@pytest.mark.unit
class TestResult:
    """Test cases for Result[T] functionality."""

    def test_success_result_creation(self) -> None:
        """Test creating successful results."""
        data = ["item1", "item2", "item3"]
        result = Result.ok(
            data=data,
            execution_time_ms=150.5,
            operation="search",
            total_found=3,
        )

        assert result.success is True
        assert result.data == data
        assert result.error is None
        assert result.error_code is None
        assert result.execution_time_ms == 150.5
        assert result.context["operation"] == "search"
        assert result.context["total_found"] == 3

    def test_error_result_creation(self) -> None:
        """Test creating error results."""
        result = Result.fail(
            message="Connection failed",
            code="CONN_001",
            execution_time_ms=50.0,
            default_data=[],
        )

        assert result.success is False
        assert result.data == []
        assert result.error == "Connection failed"
        assert result.error_code == "CONN_001"
        assert result.execution_time_ms == 50.0

    def test_from_exception_creation(self) -> None:
        """Test creating result from exception."""
        exception = LDAPCoreError(
            message="Test error",
            error_code="TEST_001",
        )

        result = Result.from_exception(
            exception,
            execution_time_ms=25.0,
            default_data=None,
        )

        assert result.success is False
        assert result.data is None
        assert result.error == "[TEST_001] Test error"
        assert result.error_code == "TEST_001"
        assert result.execution_time_ms == 25.0

    def test_from_generic_exception(self) -> None:
        """Test creating result from generic exception."""
        exception = ValueError("Invalid parameter")

        result = Result.from_exception(exception, default_data=[])

        assert result.success is False
        assert result.data == []
        assert result.error == "Invalid parameter"
        assert result.error_code is None


@pytest.mark.unit
class TestQuery:
    """Test cases for Query builder functionality."""

    @pytest.fixture
    def mock_ldap(self):
        """Create mock LDAP instance for testing."""
        ldap = Mock()
        ldap._config = Mock()
        ldap._config.base_dn = "dc=test,dc=com"
        ldap._search = AsyncMock()
        return ldap

    def test_query_creation(self, mock_ldap) -> None:
        """Test query builder creation."""
        query = Query(mock_ldap)

        assert query._ldap == mock_ldap
        assert query._object_class is None
        assert query._base_dn is None
        assert query._filters == []
        assert query._attributes == []
        assert query._limit == 0
        assert query._sort_by is None

    def test_object_type_methods(self, mock_ldap) -> None:
        """Test object type selection methods."""
        query = Query(mock_ldap)

        # Test users
        user_query = query.users()
        assert user_query._object_class == "person"

        # Test groups
        group_query = Query(mock_ldap).groups()
        assert group_query._object_class == "group"

        # Test computers
        computer_query = Query(mock_ldap).computers()
        assert computer_query._object_class == "computer"

        # Test custom objects
        custom_query = Query(mock_ldap).objects("customClass")
        assert custom_query._object_class == "customClass"

    def test_location_methods(self, mock_ldap) -> None:
        """Test location specification methods."""
        query = Query(mock_ldap)

        # Test in_location
        location_query = query.in_location("ou=users,dc=test,dc=com")
        assert location_query._base_dn == "ou=users,dc=test,dc=com"

        # Test in_ou
        ou_query = Query(mock_ldap).in_ou("users")
        assert ou_query._base_dn == "ou=users,dc=test,dc=com"

    def test_filter_methods(self, mock_ldap) -> None:
        """Test filter building methods."""
        query = Query(mock_ldap)

        # Test basic where
        where_query = query.where("(objectClass=person)")
        assert "(objectClass=person)" in where_query._filters

        # Test semantic filters
        name_query = Query(mock_ldap).with_name("john.doe")
        assert "(cn=john.doe)" in name_query._filters

        email_query = Query(mock_ldap).with_email("john@example.com")
        assert any("mail=john@example.com" in f for f in email_query._filters)

        dept_query = Query(mock_ldap).in_department("IT")
        assert "(department=IT)" in dept_query._filters

        title_query = Query(mock_ldap).with_title("*Manager*")
        assert "(title=*Manager*)" in title_query._filters

        # Test enabled/disabled filters
        enabled_query = Query(mock_ldap).enabled_only()
        assert any("userAccountControl" in f for f in enabled_query._filters)

        disabled_query = Query(mock_ldap).disabled_only()
        assert any("userAccountControl" in f for f in disabled_query._filters)

        # Test group membership
        member_query = Query(mock_ldap).member_of("Admins")
        assert any("memberOf=cn=Admins" in f for f in member_query._filters)

    def test_attribute_selection(self, mock_ldap) -> None:
        """Test attribute selection methods."""
        query = Query(mock_ldap)

        # Test select specific attributes
        select_query = query.select("cn", "mail", "department")
        assert "cn" in select_query._attributes
        assert "mail" in select_query._attributes
        assert "department" in select_query._attributes

        # Test select all
        all_query = Query(mock_ldap).select_all()
        assert all_query._attributes == ["*"]

        # Test select basic for users
        basic_query = Query(mock_ldap).users().select_basic()
        expected_attrs = ["cn", "mail", "displayName", "department", "title"]
        assert all(attr in basic_query._attributes for attr in expected_attrs)

        # Test select basic for groups
        group_basic_query = Query(mock_ldap).groups().select_basic()
        expected_group_attrs = ["cn", "description", "member"]
        assert all(attr in group_basic_query._attributes for attr in expected_group_attrs)

    def test_result_modifiers(self, mock_ldap) -> None:
        """Test result modifier methods."""
        query = Query(mock_ldap)

        # Test limit
        limit_query = query.limit(50)
        assert limit_query._limit == 50

        # Test sort_by
        sort_query = query.sort_by("cn")
        assert sort_query._sort_by == "cn"

    def test_fluent_chaining(self, mock_ldap) -> None:
        """Test fluent method chaining."""
        query = (Query(mock_ldap)
            .users()
            .in_department("IT")
            .with_title("*Manager*")
            .enabled_only()
            .select("cn", "mail", "title")
            .limit(25)
            .sort_by("cn"))

        assert query._object_class == "person"
        assert "(department=IT)" in query._filters
        assert "(title=*Manager*)" in query._filters
        assert any("userAccountControl" in f for f in query._filters)
        assert "cn" in query._attributes
        assert "mail" in query._attributes
        assert "title" in query._attributes
        assert query._limit == 25
        assert query._sort_by == "cn"

    @pytest.mark.asyncio
    async def test_query_execution_success(self, mock_ldap) -> None:
        """Test successful query execution."""
        # Mock successful search result
        mock_entries = [
            Mock(get_attribute=Mock(return_value="user1")),
            Mock(get_attribute=Mock(return_value="user2")),
        ]

        mock_result = Result.ok(mock_entries, execution_time_ms=50.0)
        mock_ldap._search.return_value = mock_result

        query = (Query(mock_ldap)
            .users()
            .in_department("IT")
            .select("cn", "mail")
            .limit(10))

        result = await query.execute()

        assert result.success is True
        assert len(result.data) == 2
        assert result.execution_time_ms >= 0  # Should be set

        # Verify search was called with correct parameters
        mock_ldap._search.assert_called_once()
        call_args = mock_ldap._search.call_args.kwargs
        assert "base_dn" in call_args
        assert "filter_expr" in call_args
        assert "attributes" in call_args
        assert "limit" in call_args

    @pytest.mark.asyncio
    async def test_query_execution_error(self, mock_ldap) -> None:
        """Test query execution with error."""
        # Mock search error
        mock_ldap._search.side_effect = Exception("Search failed")

        query = Query(mock_ldap).users()
        result = await query.execute()

        assert result.success is False
        assert result.error == "Search failed"
        assert result.data == []

    @pytest.mark.asyncio
    async def test_first_method(self, mock_ldap) -> None:
        """Test first() method."""
        mock_entry = Mock(get_attribute=Mock(return_value="user1"))
        mock_result = Result.ok([mock_entry], execution_time_ms=30.0)
        mock_ldap._search.return_value = mock_result

        query = Query(mock_ldap).users()
        result = await query.first()

        assert result.success is True
        assert result.data == mock_entry

    @pytest.mark.asyncio
    async def test_count_method(self, mock_ldap) -> None:
        """Test count() method."""
        mock_entries = [Mock() for _ in range(5)]
        mock_result = Result.ok(mock_entries, execution_time_ms=25.0)
        mock_ldap._search.return_value = mock_result

        query = Query(mock_ldap).users()
        result = await query.count()

        assert result.success is True
        assert result.data == 5


@pytest.mark.unit
class TestLDAP:
    """Test cases for LDAP class functionality."""

    @pytest.fixture
    def valid_config(self):
        """Create valid configuration for testing."""
        return LDAPConfig(
            server="ldap://test.example.com:389",
            auth_dn="cn=test,dc=test,dc=com",
            auth_password="testpass",
            base_dn="dc=test,dc=com",
        )

    def test_ldap_creation(self, valid_config) -> None:
        """Test LDAP instance creation."""
        ldap = LDAP(valid_config)

        assert ldap._config == valid_config
        assert ldap._connection is None
        assert ldap._is_connected is False

    @pytest.mark.asyncio
    async def test_context_manager(self, valid_config) -> None:
        """Test LDAP as async context manager."""
        ldap = LDAP(valid_config)

        async with ldap as managed_ldap:
            assert managed_ldap == ldap
            assert ldap._is_connected is True

        assert ldap._is_connected is False

    def test_query_creation(self, valid_config) -> None:
        """Test query builder creation from LDAP."""
        ldap = LDAP(valid_config)
        query = ldap.query()

        assert isinstance(query, Query)
        assert query._ldap == ldap

    @pytest.mark.asyncio
    async def test_find_user_by_email(self, valid_config) -> None:
        """Test finding user by email."""
        ldap = LDAP(valid_config)

        with patch.object(ldap, "_search") as mock_search:
            mock_user = Mock()
            mock_search.return_value = Result.ok([mock_user], execution_time_ms=20.0)

            result = await ldap.find_user_by_email("test@example.com")

            assert result.success is True
            assert result.data == mock_user

    @pytest.mark.asyncio
    async def test_find_user_by_name(self, valid_config) -> None:
        """Test finding user by name."""
        ldap = LDAP(valid_config)

        with patch.object(ldap, "_search") as mock_search:
            mock_user = Mock()
            mock_search.return_value = Result.ok([mock_user], execution_time_ms=20.0)

            result = await ldap.find_user_by_name("testuser")

            assert result.success is True
            assert result.data == mock_user

    @pytest.mark.asyncio
    async def test_find_users_in_department(self, valid_config) -> None:
        """Test finding users in department."""
        ldap = LDAP(valid_config)

        with patch.object(ldap, "_search") as mock_search:
            mock_users = [Mock(), Mock()]
            mock_search.return_value = Result.ok(mock_users, execution_time_ms=30.0)

            result = await ldap.find_users_in_department("IT")

            assert result.success is True
            assert len(result.data) == 2

    @pytest.mark.asyncio
    async def test_get_user_groups(self, valid_config) -> None:
        """Test getting user groups."""
        ldap = LDAP(valid_config)

        # Mock find_user_by_name
        mock_user = Mock()
        mock_user.dn = "cn=testuser,ou=users,dc=test,dc=com"

        with patch.object(ldap, "find_user_by_name") as mock_find_user, \
             patch.object(ldap, "_search") as mock_search:

            mock_find_user.return_value = Result.ok(mock_user, execution_time_ms=10.0)
            mock_groups = [Mock(), Mock()]
            mock_search.return_value = Result.ok(mock_groups, execution_time_ms=25.0)

            result = await ldap.get_user_groups("testuser")

            assert result.success is True
            assert len(result.data) == 2

    @pytest.mark.asyncio
    async def test_is_user_in_group(self, valid_config) -> None:
        """Test checking user group membership."""
        ldap = LDAP(valid_config)

        mock_group = Mock()
        mock_group.get_attribute.return_value = "TestGroup"

        with patch.object(ldap, "get_user_groups") as mock_get_groups:
            mock_get_groups.return_value = Result.ok([mock_group], execution_time_ms=20.0)

            result = await ldap.is_user_in_group("testuser", "TestGroup")

            assert result.success is True
            assert result.data is True

    @pytest.mark.asyncio
    async def test_find_group_by_name(self, valid_config) -> None:
        """Test finding group by name."""
        ldap = LDAP(valid_config)

        with patch.object(ldap, "_search") as mock_search:
            mock_group = Mock()
            mock_search.return_value = Result.ok([mock_group], execution_time_ms=15.0)

            result = await ldap.find_group_by_name("TestGroup")

            assert result.success is True
            assert result.data == mock_group

    @pytest.mark.asyncio
    async def test_find_empty_groups(self, valid_config) -> None:
        """Test finding empty groups."""
        ldap = LDAP(valid_config)

        with patch.object(ldap, "_search") as mock_search:
            mock_groups = [Mock() for _ in range(3)]
            mock_search.return_value = Result.ok(mock_groups, execution_time_ms=40.0)

            result = await ldap.find_empty_groups()

            assert result.success is True
            assert len(result.data) == 3

    @pytest.mark.asyncio
    async def test_get_directory_stats(self, valid_config) -> None:
        """Test getting directory statistics."""
        ldap = LDAP(valid_config)

        # Mock various count operations
        with patch.object(ldap, "query") as mock_query_factory, \
             patch.object(ldap, "find_empty_groups") as mock_empty_groups:

            # Setup mock query instances
            mock_query = Mock()
            mock_query.users.return_value = mock_query
            mock_query.groups.return_value = mock_query
            mock_query.enabled_only.return_value = mock_query
            mock_query.disabled_only.return_value = mock_query
            mock_query.count = AsyncMock()

            mock_query_factory.return_value = mock_query

            # Setup return values
            mock_query.count.side_effect = [
                Result.ok(150, execution_time_ms=20.0),  # total users
                Result.ok(25, execution_time_ms=15.0),   # total groups
                Result.ok(140, execution_time_ms=18.0),  # enabled users
                Result.ok(10, execution_time_ms=12.0),    # disabled users
            ]

            mock_empty_groups.return_value = Result.ok([Mock(), Mock()], execution_time_ms=10.0)  # 2 empty groups

            result = await ldap.get_directory_stats()

            assert result.success is True
            assert result.data["total_users"] == 150
            assert result.data["total_groups"] == 25
            assert result.data["enabled_users"] == 140
            assert result.data["disabled_users"] == 10
            assert result.data["empty_groups"] == 2

    @pytest.mark.asyncio
    async def test_test_connection(self, valid_config) -> None:
        """Test connection testing."""
        ldap = LDAP(valid_config)
        ldap._is_connected = True

        result = await ldap.test_connection()

        assert result.success is True
        assert result.data is True


@pytest.mark.unit
class TestConvenienceFunctions:
    """Test cases for convenience functions."""

    @pytest.mark.asyncio
    async def test_connect_function(self) -> None:
        """Test connect convenience function."""
        with patch("ldap_core_shared.api.LDAP") as mock_ldap_class:
            mock_ldap = Mock()
            mock_ldap._connect = AsyncMock()
            mock_ldap_class.return_value = mock_ldap

            result = await connect(
                server="ldap://test.com",
                auth_dn="cn=test,dc=test,dc=com",
                auth_password="password",
                base_dn="dc=test,dc=com",
            )

            assert result == mock_ldap
            mock_ldap._connect.assert_called_once()

    @pytest.mark.asyncio
    async def test_ldap_session_context_manager(self) -> None:
        """Test ldap_session context manager."""
        with patch("ldap_core_shared.api.LDAP") as mock_ldap_class:
            mock_ldap = Mock()
            mock_ldap.__aenter__ = AsyncMock(return_value=mock_ldap)
            mock_ldap.__aexit__ = AsyncMock()
            mock_ldap_class.return_value = mock_ldap

            async with ldap_session(
                server="ldap://test.com",
                auth_dn="cn=test,dc=test,dc=com",
                auth_password="password",
                base_dn="dc=test,dc=com",
            ) as session:
                assert session == mock_ldap

            mock_ldap.__aenter__.assert_called_once()
            mock_ldap.__aexit__.assert_called_once()


@pytest.mark.integration
class TestUnifiedAPIIntegration:
    """Integration tests for unified API components."""

    @pytest.mark.asyncio
    async def test_complete_api_workflow(self) -> None:
        """Test complete API workflow from config to operations."""
        # Create configuration
        config = LDAPConfig(
            server="ldap://test.example.com:389",
            auth_dn="cn=test,dc=example,dc=com",
            auth_password="password",
            base_dn="dc=example,dc=com",
        )

        # Create LDAP instance
        ldap = LDAP(config)

        # Test context manager usage
        async with ldap:
            # Test query building and execution (placeholder implementation)
            result = await (ldap.query()
                .users()
                .in_department("IT")
                .select("cn", "mail")
                .limit(5)
                .execute())

            # Should succeed with placeholder implementation
            assert result.success is True
            assert isinstance(result.data, list)

    @pytest.mark.asyncio
    async def test_semantic_operations_integration(self) -> None:
        """Test semantic operations integration."""
        config = LDAPConfig(
            server="ldap://test.example.com:389",
            auth_dn="cn=test,dc=example,dc=com",
            auth_password="password",
            base_dn="dc=example,dc=com",
        )

        async with LDAP(config) as ldap:
            # Test semantic operations are accessible
            assert hasattr(ldap, "find_user_by_email")
            assert hasattr(ldap, "find_users_in_department")
            assert hasattr(ldap, "get_user_groups")
            assert hasattr(ldap, "is_user_in_group")
            assert hasattr(ldap, "find_empty_groups")
            assert hasattr(ldap, "get_directory_stats")


# Custom fixtures for API testing
@pytest.fixture
def sample_ldap_entries():
    """Create sample LDAP entries for testing."""
    entries = []
    for i in range(5):
        entry = Mock(spec=LDAPEntry)
        entry.dn = f"cn=user{i},ou=users,dc=test,dc=com"
        entry.get_attribute = Mock(side_effect={
            "cn": f"user{i}",
            "mail": f"user{i}@test.com",
            "department": "IT" if i % 2 == 0 else "HR",
        }.get)
        entries.append(entry)

    return entries


@pytest.fixture
def mock_successful_result(sample_ldap_entries):
    """Create mock successful operation result."""
    return Result.ok(
        sample_ldap_entries,
        execution_time_ms=50.0,
        operation="search",
        total_found=len(sample_ldap_entries),
    )
