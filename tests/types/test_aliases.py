"""Comprehensive tests for type aliases and their usage.

This module tests the type alias definitions to ensure they provide
proper type safety and can be used consistently throughout the library.

Test categories:
- Type alias validation and usage
- Type checker compatibility
- Runtime type checking behavior
- Complex type composition
- Documentation and examples
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from hypothesis import given
from hypothesis import strategies as st

if TYPE_CHECKING:
    from ldap_core_shared.types.aliases import (
        DN,
        OID,
        RDN,
        AggregationSpec,
        APIKey,
        AsyncCallback,
        AttributeName,
        Attributes,
        AttributeValue,
        AuthMechanism,
        CABundle,
        CacheKey,
        CacheTTL,
        Callback,
        Certificate,
        Config,
        ConfigValue,
        CPUUsage,
        EncryptionAlgorithm,
        EntityID,
        EntityVersion,
        Environment,
        ErrorCode,
        ErrorContext,
        ErrorSeverity,
        EventData,
        EventType,
        ExceptionDetails,
        Factory,
        FieldPath,
        FilterExpression,
        FilterSpec,
        HashAlgorithm,
        JWTToken,
        LDIFRecord,
        LDIFRecords,
        LDIFRecordType,
        LogLevel,
        Mapper,
        MemoryUsage,
        Metric,
        MetricLabels,
        MetricName,
        Metrics,
        MetricValue,
        MigrationStats,
        MigrationStatus,
        ModificationOperation,
        ObjectClass,
        OperationResult,
        PageNumber,
        PageSize,
        PaginationMeta,
        PaginationToken,
        PerformanceThreshold,
        Predicate,
        PrivateKey,
        QuerySpec,
        Reducer,
        ResultCode,
        ResultMessage,
        SASLMechanism,
        Schema,
        SchemaElement,
        SearchResult,
        SearchResults,
        SearchScope,
        ServerURI,
        SortDirection,
        SortField,
        SortSpec,
        SortSpecs,
        SpanID,
        Timeout,
        TLSVersion,
        TotalCount,
        TraceID,
        ValidationError,
        ValidationResult,
        ValidationRule,
    )

# ===== BASIC LDAP TYPE TESTS =====


class TestBasicLDAPTypes:
    """Test suite for basic LDAP type aliases."""

    def test_dn_type_alias(self) -> None:
        """Test DN type alias usage."""
        # DN should be string
        dn: DN = "cn=user,dc=example,dc=com"
        assert isinstance(dn, str)
        assert "cn=" in dn

    def test_rdn_type_alias(self) -> None:
        """Test RDN type alias usage."""
        rdn: RDN = "cn=user"
        assert isinstance(rdn, str)
        assert "=" in rdn

    def test_attribute_name_type_alias(self) -> None:
        """Test AttributeName type alias usage."""
        attr_name: AttributeName = "cn"
        assert isinstance(attr_name, str)

    def test_attribute_value_types(self) -> None:
        """Test AttributeValue can handle various types."""
        # String value
        str_value: AttributeValue = "test"
        assert isinstance(str_value, str)

        # Bytes value
        bytes_value: AttributeValue = b"test"
        assert isinstance(bytes_value, bytes)

        # List of strings
        str_list_value: AttributeValue = ["value1", "value2"]
        assert isinstance(str_list_value, list)
        assert all(isinstance(v, str) for v in str_list_value)

        # List of bytes
        bytes_list_value: AttributeValue = [b"value1", b"value2"]
        assert isinstance(bytes_list_value, list)
        assert all(isinstance(v, bytes) for v in bytes_list_value)

    def test_attributes_dictionary(self) -> None:
        """Test Attributes type alias usage."""
        attributes: Attributes = {
            "cn": ["user1", "user2"],
            "mail": "user@example.com",
            "objectClass": ["person", "organizationalPerson"],
            "photo": b"binary_data",
        }

        assert isinstance(attributes, dict)
        assert "cn" in attributes
        assert isinstance(attributes["cn"], list)

    def test_filter_expression(self) -> None:
        """Test FilterExpression type alias."""
        simple_filter: FilterExpression = "(cn=user)"
        complex_filter: FilterExpression = "(&(objectClass=person)(mail=*@example.com))"

        assert isinstance(simple_filter, str)
        assert isinstance(complex_filter, str)
        assert simple_filter.startswith("(")
        assert complex_filter.startswith("(")

    def test_search_scope_literals(self) -> None:
        """Test SearchScope literal values."""
        base_scope: SearchScope = "base"
        onelevel_scope: SearchScope = "onelevel"
        subtree_scope: SearchScope = "subtree"

        assert base_scope == "base"
        assert onelevel_scope == "onelevel"
        assert subtree_scope == "subtree"

    def test_modification_operation_literals(self) -> None:
        """Test ModificationOperation literal values."""
        add_op: ModificationOperation = "add"
        replace_op: ModificationOperation = "replace"
        delete_op: ModificationOperation = "delete"

        assert add_op == "add"
        assert replace_op == "replace"
        assert delete_op == "delete"

    @given(dn_text=st.text(min_size=5))
    def test_dn_property_based(self, dn_text: str) -> None:
        """Property-based test for DN usage."""
        dn: DN = dn_text
        assert isinstance(dn, str)
        assert len(dn) >= 5


# ===== CONNECTION AND AUTHENTICATION TYPE TESTS =====


class TestConnectionAuthTypes:
    """Test suite for connection and authentication type aliases."""

    def test_server_uri_types(self) -> None:
        """Test ServerURI type alias usage."""
        ldap_uri: ServerURI = "ldap://server.example.com:389"
        ldaps_uri: ServerURI = "ldaps://server.example.com:636"

        assert isinstance(ldap_uri, str)
        assert isinstance(ldaps_uri, str)
        assert "ldap" in ldap_uri
        assert "ldaps" in ldaps_uri

    def test_auth_mechanism_literals(self) -> None:
        """Test AuthMechanism literal values."""
        simple: AuthMechanism = "simple"
        sasl: AuthMechanism = "sasl"
        anonymous: AuthMechanism = "anonymous"

        assert simple == "simple"
        assert sasl == "sasl"
        assert anonymous == "anonymous"

    def test_sasl_mechanism_literals(self) -> None:
        """Test SASLMechanism literal values."""
        gssapi: SASLMechanism = "GSSAPI"
        digest_md5: SASLMechanism = "DIGEST-MD5"
        plain: SASLMechanism = "PLAIN"
        external: SASLMechanism = "EXTERNAL"

        assert gssapi == "GSSAPI"
        assert digest_md5 == "DIGEST-MD5"
        assert plain == "PLAIN"
        assert external == "EXTERNAL"

    def test_timeout_type(self) -> None:
        """Test Timeout type alias usage."""
        timeout: Timeout = 30.5
        assert isinstance(timeout, float)
        assert timeout > 0

    def test_tls_version_literals(self) -> None:
        """Test TLSVersion literal values."""
        tls12: TLSVersion = "TLSv1.2"
        tls13: TLSVersion = "TLSv1.3"

        assert tls12 == "TLSv1.2"
        assert tls13 == "TLSv1.3"


# ===== OPERATION RESULT TYPE TESTS =====


class TestOperationResultTypes:
    """Test suite for operation result type aliases."""

    def test_result_code_and_message(self) -> None:
        """Test ResultCode and ResultMessage types."""
        success_code: ResultCode = 0
        error_code: ResultCode = 32
        success_msg: ResultMessage = "Success"
        error_msg: ResultMessage = "No such object"

        assert isinstance(success_code, int)
        assert isinstance(error_code, int)
        assert isinstance(success_msg, str)
        assert isinstance(error_msg, str)

    def test_operation_result_structure(self) -> None:
        """Test OperationResult type alias structure."""
        success_result: OperationResult = {
            "result_code": 0,
            "message": "Success",
            "dn": "cn=user,dc=example,dc=com",
        }

        error_result: OperationResult = {
            "result_code": 32,
            "message": "No such object",
            "dn": None,
        }

        assert isinstance(success_result, dict)
        assert isinstance(error_result, dict)
        assert "result_code" in success_result
        assert "message" in success_result
        assert "dn" in success_result

    def test_search_result_structure(self) -> None:
        """Test SearchResult type alias structure."""
        search_result: SearchResult = {
            "dn": "cn=user,dc=example,dc=com",
            "attributes": {
                "cn": ["user"],
                "mail": ["user@example.com"],
            },
        }

        assert isinstance(search_result, dict)
        assert "dn" in search_result
        assert "attributes" in search_result
        assert isinstance(search_result["attributes"], dict)

    def test_search_results_collection(self) -> None:
        """Test SearchResults type alias as collection."""
        results: SearchResults = [
            {
                "dn": "cn=user1,dc=example,dc=com",
                "attributes": {"cn": ["user1"]},
            },
            {
                "dn": "cn=user2,dc=example,dc=com",
                "attributes": {"cn": ["user2"]},
            },
        ]

        assert isinstance(results, list)
        assert len(results) == 2
        assert all("dn" in result for result in results)


# ===== SCHEMA TYPE TESTS =====


class TestSchemaTypes:
    """Test suite for schema-related type aliases."""

    def test_oid_type(self) -> None:
        """Test OID type alias usage."""
        oid: OID = "1.2.840.113556.1.4.1"
        assert isinstance(oid, str)
        assert "." in oid

    def test_object_class_type(self) -> None:
        """Test ObjectClass type alias usage."""
        obj_class: ObjectClass = "person"
        assert isinstance(obj_class, str)

    def test_schema_element_structure(self) -> None:
        """Test SchemaElement type alias structure."""
        element: SchemaElement = {
            "oid": "1.2.840.113556.1.4.1",
            "name": "cn",
            "syntax": "1.3.6.1.4.1.1466.115.121.1.15",
            "single_value": False,
        }

        assert isinstance(element, dict)
        assert "oid" in element
        assert "name" in element

    def test_schema_structure(self) -> None:
        """Test Schema type alias structure."""
        schema: Schema = {
            "object_classes": [
                {"oid": "2.5.6.6", "name": "person"},
                {"oid": "2.5.6.7", "name": "organizationalPerson"},
            ],
            "attribute_types": [
                {"oid": "2.5.4.3", "name": "cn"},
                {"oid": "2.5.4.4", "name": "sn"},
            ],
            "syntaxes": [
                {"oid": "1.3.6.1.4.1.1466.115.121.1.15", "name": "Directory String"},
            ],
            "matching_rules": [
                {"oid": "2.5.13.2", "name": "caseIgnoreMatch"},
            ],
        }

        assert isinstance(schema, dict)
        assert "object_classes" in schema
        assert "attribute_types" in schema
        assert "syntaxes" in schema
        assert "matching_rules" in schema


# ===== LDIF AND MIGRATION TYPE TESTS =====


class TestLDIFMigrationTypes:
    """Test suite for LDIF and migration type aliases."""

    def test_ldif_record_type_literals(self) -> None:
        """Test LDIFRecordType literal values."""
        entry: LDIFRecordType = "entry"
        modification: LDIFRecordType = "modification"
        delete: LDIFRecordType = "delete"
        moddn: LDIFRecordType = "moddn"

        assert entry == "entry"
        assert modification == "modification"
        assert delete == "delete"
        assert moddn == "moddn"

    def test_ldif_record_structure(self) -> None:
        """Test LDIFRecord type alias structure."""
        entry_record: LDIFRecord = {
            "type": "entry",
            "dn": "cn=user,dc=example,dc=com",
            "attributes": {"cn": ["user"], "objectClass": ["person"]},
            "changes": None,
        }

        modification_record: LDIFRecord = {
            "type": "modification",
            "dn": "cn=user,dc=example,dc=com",
            "attributes": None,
            "changes": [
                {
                    "operation": "replace",
                    "attribute": "mail",
                    "values": ["new@example.com"],
                },
            ],
        }

        assert isinstance(entry_record, dict)
        assert isinstance(modification_record, dict)
        assert entry_record["type"] == "entry"
        assert modification_record["type"] == "modification"

    def test_migration_status_literals(self) -> None:
        """Test MigrationStatus literal values."""
        pending: MigrationStatus = "pending"
        running: MigrationStatus = "running"
        completed: MigrationStatus = "completed"
        failed: MigrationStatus = "failed"
        cancelled: MigrationStatus = "cancelled"

        assert pending == "pending"
        assert running == "running"
        assert completed == "completed"
        assert failed == "failed"
        assert cancelled == "cancelled"

    def test_migration_stats_structure(self) -> None:
        """Test MigrationStats type alias structure."""
        stats: MigrationStats = {
            "total_entries": 1000,
            "successful": 950,
            "failed": 30,
            "skipped": 20,
            "duration": 45.5,
        }

        assert isinstance(stats, dict)
        assert "total_entries" in stats
        assert "successful" in stats
        assert "failed" in stats
        assert "skipped" in stats
        assert "duration" in stats
        assert isinstance(stats["duration"], float)


# ===== CONFIGURATION TYPE TESTS =====


class TestConfigurationTypes:
    """Test suite for configuration type aliases."""

    def test_config_value_types(self) -> None:
        """Test ConfigValue can handle various types."""
        str_config: ConfigValue = "test_value"
        int_config: ConfigValue = 42
        float_config: ConfigValue = 3.14
        bool_config: ConfigValue = True
        list_config: ConfigValue = ["item1", "item2"]
        dict_config: ConfigValue = {"key": "value"}
        none_config: ConfigValue = None

        assert isinstance(str_config, str)
        assert isinstance(int_config, int)
        assert isinstance(float_config, float)
        assert isinstance(bool_config, bool)
        assert isinstance(list_config, list)
        assert isinstance(dict_config, dict)
        assert none_config is None

    def test_config_structure(self) -> None:
        """Test Config type alias structure."""
        config: Config = {
            "host": "ldap.example.com",
            "port": 389,
            "use_tls": True,
            "timeout": 30.0,
            "retry_attempts": 3,
            "features": ["search", "modify", "add"],
            "advanced": {"pool_size": 10, "debug": False},
            "optional_setting": None,
        }

        assert isinstance(config, dict)
        assert isinstance(config["host"], str)
        assert isinstance(config["port"], int)
        assert isinstance(config["use_tls"], bool)

    def test_environment_literals(self) -> None:
        """Test Environment literal values."""
        dev: Environment = "development"
        test: Environment = "testing"
        staging: Environment = "staging"
        prod: Environment = "production"

        assert dev == "development"
        assert test == "testing"
        assert staging == "staging"
        assert prod == "production"

    def test_log_level_literals(self) -> None:
        """Test LogLevel literal values."""
        debug: LogLevel = "DEBUG"
        info: LogLevel = "INFO"
        warning: LogLevel = "WARNING"
        error: LogLevel = "ERROR"
        critical: LogLevel = "CRITICAL"

        assert debug == "DEBUG"
        assert info == "INFO"
        assert warning == "WARNING"
        assert error == "ERROR"
        assert critical == "CRITICAL"


# ===== MONITORING TYPE TESTS =====


class TestMonitoringTypes:
    """Test suite for monitoring and observability type aliases."""

    def test_metric_components(self) -> None:
        """Test metric component types."""
        metric_name: MetricName = "ldap_connections_total"
        metric_value: MetricValue = 42.5
        metric_labels: MetricLabels = {"server": "ldap1", "status": "active"}

        assert isinstance(metric_name, str)
        assert isinstance(metric_value, (int, float))
        assert isinstance(metric_labels, dict)
        assert all(
            isinstance(k, str) and isinstance(v, str) for k, v in metric_labels.items()
        )

    def test_metric_structure(self) -> None:
        """Test Metric type alias structure."""
        metric: Metric = {
            "name": "ldap_search_duration_seconds",
            "value": 0.025,
            "labels": {"operation": "search", "scope": "subtree"},
            "timestamp": 1640995200.0,
        }

        assert isinstance(metric, dict)
        assert "name" in metric
        assert "value" in metric
        assert "labels" in metric
        assert "timestamp" in metric

    def test_event_types(self) -> None:
        """Test event type aliases."""
        event_type: EventType = "user_login"
        event_data: EventData = {
            "user_id": "user123",
            "timestamp": "2025-01-01T12:00:00Z",
        }

        assert isinstance(event_type, str)
        assert isinstance(event_data, dict)

    def test_tracing_ids(self) -> None:
        """Test tracing ID types."""
        trace_id: TraceID = "1234567890abcdef"
        span_id: SpanID = "abcdef1234567890"

        assert isinstance(trace_id, str)
        assert isinstance(span_id, str)


# ===== SECURITY TYPE TESTS =====


class TestSecurityTypes:
    """Test suite for security-related type aliases."""

    def test_certificate_types(self) -> None:
        """Test certificate type aliases."""
        cert: Certificate = (
            "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----"
        )
        key: PrivateKey = (
            "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----"
        )
        ca_bundle: CABundle = (
            "-----BEGIN CERTIFICATE-----\nCA1...\n-----END CERTIFICATE-----"
        )

        assert isinstance(cert, str)
        assert isinstance(key, str)
        assert isinstance(ca_bundle, str)
        assert "BEGIN CERTIFICATE" in cert
        assert "BEGIN PRIVATE KEY" in key

    def test_algorithm_literals(self) -> None:
        """Test algorithm literal values."""
        encryption: EncryptionAlgorithm = "AES-256-GCM"
        encryption2: EncryptionAlgorithm = "ChaCha20-Poly1305"
        hash_alg: HashAlgorithm = "SHA-256"
        hash_alg2: HashAlgorithm = "SHA-512"
        hash_alg3: HashAlgorithm = "BLAKE2b"

        assert encryption == "AES-256-GCM"
        assert encryption2 == "ChaCha20-Poly1305"
        assert hash_alg == "SHA-256"
        assert hash_alg2 == "SHA-512"
        assert hash_alg3 == "BLAKE2b"

    def test_token_types(self) -> None:
        """Test token type aliases."""
        jwt_token: JWTToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
        api_key: APIKey = "sk_test_1234567890abcdef"

        assert isinstance(jwt_token, str)
        assert isinstance(api_key, str)


# ===== ERROR TYPE TESTS =====


class TestErrorTypes:
    """Test suite for error-related type aliases."""

    def test_error_components(self) -> None:
        """Test error component types."""
        error_code: ErrorCode = "LDAP_001"
        error_severity: ErrorSeverity = "high"
        error_context: ErrorContext = {"operation": "search", "dn": "dc=example,dc=com"}

        assert isinstance(error_code, str)
        assert error_severity in ["low", "medium", "high", "critical"]
        assert isinstance(error_context, dict)

    def test_exception_details_structure(self) -> None:
        """Test ExceptionDetails type alias structure."""
        details: ExceptionDetails = {
            "type": "LDAPConnectionError",
            "message": "Failed to connect to LDAP server",
            "traceback": "Traceback (most recent call last):\n...",
            "context": {"server": "ldap.example.com", "port": 389},
        }

        assert isinstance(details, dict)
        assert "type" in details
        assert "message" in details
        assert "traceback" in details
        assert "context" in details


# ===== VALIDATION TYPE TESTS =====


class TestValidationTypes:
    """Test suite for validation type aliases."""

    def test_validation_components(self) -> None:
        """Test validation component types."""
        rule: ValidationRule = "required"
        error: ValidationError = "Field is required"
        field_path: FieldPath = "user.email"

        assert isinstance(rule, str)
        assert isinstance(error, str)
        assert isinstance(field_path, str)

    def test_validation_result_structure(self) -> None:
        """Test ValidationResult type alias structure."""
        success_result: ValidationResult = {
            "valid": True,
            "errors": {},
        }

        error_result: ValidationResult = {
            "valid": False,
            "errors": {
                "name": ["Field is required"],
                "email": ["Invalid email format", "Email already exists"],
            },
        }

        assert isinstance(success_result, dict)
        assert isinstance(error_result, dict)
        assert "valid" in success_result
        assert "errors" in success_result
        assert success_result["valid"] is True
        assert error_result["valid"] is False


# ===== PAGINATION TYPE TESTS =====


class TestPaginationTypes:
    """Test suite for pagination type aliases."""

    def test_pagination_components(self) -> None:
        """Test pagination component types."""
        page_num: PageNumber = 1
        page_size: PageSize = 20
        total: TotalCount = 100
        token: PaginationToken = "eyJwYWdlIjoyLCJzaXplIjoyMH0="

        assert isinstance(page_num, int)
        assert isinstance(page_size, int)
        assert isinstance(total, int)
        assert isinstance(token, str)
        assert page_num >= 1
        assert page_size > 0
        assert total >= 0

    def test_pagination_meta_structure(self) -> None:
        """Test PaginationMeta type alias structure."""
        meta: PaginationMeta = {
            "page": 2,
            "size": 20,
            "total": 100,
            "token": "next_page_token",
        }

        assert isinstance(meta, dict)
        assert "page" in meta
        assert "size" in meta
        assert "total" in meta
        assert "token" in meta

    def test_sort_components(self) -> None:
        """Test sorting component types."""
        field: SortField = "created_at"
        direction: SortDirection = "desc"

        assert isinstance(field, str)
        assert direction in ["asc", "desc"]

    def test_sort_spec_structure(self) -> None:
        """Test SortSpec type alias structure."""
        sort_spec: SortSpec = {
            "field": "name",
            "direction": "asc",
        }

        sort_specs: SortSpecs = [
            {"field": "created_at", "direction": "desc"},
            {"field": "name", "direction": "asc"},
        ]

        assert isinstance(sort_spec, dict)
        assert isinstance(sort_specs, list)
        assert "field" in sort_spec
        assert "direction" in sort_spec


# ===== ENTITY TYPE TESTS =====


class TestEntityTypes:
    """Test suite for entity-related type aliases."""

    def test_entity_components(self) -> None:
        """Test entity component types."""
        entity_id: EntityID = uuid.uuid4()
        version: EntityVersion = 1

        assert isinstance(entity_id, uuid.UUID)
        assert isinstance(version, int)
        assert version >= 1

    def test_query_specs(self) -> None:
        """Test query specification types."""
        query_spec: QuerySpec = {
            "filter": {"status": "active"},
            "sort": [{"field": "created_at", "direction": "desc"}],
            "limit": 50,
        }

        filter_spec: FilterSpec = {
            "name": {"$regex": "^admin"},
            "created_at": {"$gte": "2025-01-01"},
        }

        agg_spec: AggregationSpec = {
            "group_by": ["status"],
            "aggregates": {"count": {"$count": "*"}},
        }

        assert isinstance(query_spec, dict)
        assert isinstance(filter_spec, dict)
        assert isinstance(agg_spec, dict)


# ===== PERFORMANCE TYPE TESTS =====


class TestPerformanceTypes:
    """Test suite for performance-related type aliases."""

    def test_cache_types(self) -> None:
        """Test cache type aliases."""
        cache_key: CacheKey = "user:123:profile"
        cache_ttl: CacheTTL = 300

        assert isinstance(cache_key, str)
        assert isinstance(cache_ttl, int)
        assert cache_ttl >= 0

    def test_performance_metrics(self) -> None:
        """Test performance metric types."""
        threshold: PerformanceThreshold = 100.5
        memory: MemoryUsage = 1024 * 1024 * 100  # 100MB
        cpu: CPUUsage = 75.5

        assert isinstance(threshold, float)
        assert isinstance(memory, int)
        assert isinstance(cpu, float)
        assert threshold >= 0
        assert memory >= 0
        assert 0 <= cpu <= 100


# ===== UTILITY TYPE TESTS =====


class TestUtilityTypes:
    """Test suite for utility type aliases."""

    def test_callback_types(self) -> None:
        """Test callback type aliases."""

        def sync_callback(x: int) -> str:
            return str(x)

        async def async_callback(x: int) -> str:
            return str(x)

        def factory() -> int:
            return 42

        def predicate(x: int) -> bool:
            return x > 0

        def mapper(x: int) -> str:
            return str(x)

        def reducer(acc: int, val: int) -> int:
            return acc + val

        # Type aliases should accept callable objects
        cb: Callback = sync_callback
        async_cb: AsyncCallback = async_callback
        fact: Factory = factory
        pred: Predicate = predicate
        map_func: Mapper = mapper
        red_func: Reducer = reducer

        assert callable(cb)
        assert callable(async_cb)
        assert callable(fact)
        assert callable(pred)
        assert callable(map_func)
        assert callable(red_func)


# ===== INTEGRATION TESTS =====


class TestTypeAliasIntegration:
    """Integration tests for type aliases working together."""

    def test_complete_ldap_operation_types(self) -> None:
        """Test type aliases working together in LDAP operations."""
        # Connection setup
        server_uri: ServerURI = "ldaps://ldap.example.com:636"

        # Search operation

        # Results
        search_result: SearchResult = {
            "dn": "cn=user,dc=example,dc=com",
            "attributes": {
                "cn": ["user"],
                "mail": ["user@example.com"],
                "objectClass": ["person", "organizationalPerson"],
            },
        }

        operation_result: OperationResult = {
            "result_code": 0,
            "message": "Success",
            "dn": search_result["dn"],
        }

        # Verify all types work together
        assert isinstance(server_uri, str)
        assert isinstance(search_result["dn"], str)
        assert isinstance(operation_result["result_code"], int)

    def test_migration_workflow_types(self) -> None:
        """Test type aliases in migration workflow."""
        # Migration setup
        status: MigrationStatus = "running"

        # LDIF processing
        ldif_record: LDIFRecord = {
            "type": "entry",
            "dn": "cn=user,dc=example,dc=com",
            "attributes": {"cn": ["user"], "objectClass": ["person"]},
            "changes": None,
        }

        ldif_records: LDIFRecords = [ldif_record]

        # Migration results
        stats: MigrationStats = {
            "total_entries": 1000,
            "successful": 950,
            "failed": 30,
            "skipped": 20,
            "duration": 120.5,
        }

        # Verify workflow integration
        assert status == "running"
        assert len(ldif_records) == 1
        assert ldif_records[0]["type"] == "entry"
        assert (
            stats["successful"] + stats["failed"] + stats["skipped"]
            == stats["total_entries"]
        )

    def test_observability_types_integration(self) -> None:
        """Test observability type aliases integration."""
        # Metrics
        metric: Metric = {
            "name": "ldap_operations_total",
            "value": 1542,
            "labels": {"operation": "search", "status": "success"},
            "timestamp": 1640995200.0,
        }

        metrics: Metrics = [metric]

        # Events
        event_data: EventData = {
            "server": "ldap1.example.com",
            "user": "cn=app,dc=example,dc=com",
            "timestamp": "2025-01-01T12:00:00Z",
        }

        # Tracing
        trace_id: TraceID = "1234567890abcdef1234567890abcdef"
        span_id: SpanID = "abcdef1234567890"

        # Verify observability integration
        assert len(metrics) == 1
        assert metrics[0]["name"] == "ldap_operations_total"
        assert isinstance(event_data, dict)
        assert len(trace_id) == 32
        assert len(span_id) == 16


# ===== PROPERTY-BASED TESTS =====


class TestTypeAliasProperties:
    """Property-based tests for type aliases."""

    @given(
        server=st.text(min_size=1),
        port=st.integers(min_value=1, max_value=65535),
    )
    def test_server_uri_construction(self, server: str, port: int) -> None:
        """Property test for server URI construction."""
        uri: ServerURI = f"ldap://{server}:{port}"
        assert isinstance(uri, str)
        assert server in uri
        assert str(port) in uri

    @given(
        result_code=st.integers(min_value=0, max_value=255),
        message=st.text(min_size=1),
    )
    def test_operation_result_properties(self, result_code: int, message: str) -> None:
        """Property test for operation result structure."""
        result: OperationResult = {
            "result_code": result_code,
            "message": message,
            "dn": None,
        }

        assert isinstance(result, dict)
        assert result["result_code"] == result_code
        assert result["message"] == message

    @given(
        page=st.integers(min_value=1, max_value=1000),
        size=st.integers(min_value=1, max_value=100),
        total=st.integers(min_value=0, max_value=10000),
    )
    def test_pagination_properties(self, page: int, size: int, total: int) -> None:
        """Property test for pagination structures."""
        meta: PaginationMeta = {
            "page": page,
            "size": size,
            "total": total,
            "token": None,
        }

        assert isinstance(meta, dict)
        assert meta["page"] >= 1
        assert meta["size"] >= 1
        assert meta["total"] >= 0
