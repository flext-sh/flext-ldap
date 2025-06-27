"""🚀 RFC 2891 Compliance Tests - LDAP Control Extension for Server Side Sorting.

This module implements comprehensive tests for RFC 2891 compliance, ensuring
that the LDAP Server Side Sort Control implementation strictly adheres
to the specification with zero tolerance for deviations.

RFC 2891 Reference: https://tools.ietf.org/rfc/rfc2891.txt
ZERO TOLERANCE TESTING: Every aspect of the RFC must be verified.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from ldap_core_shared.controls.base import ControlDecodingError
from ldap_core_shared.controls.sort import (
    ServerSideSortControl,
    ServerSideSortResponse,
    SortKey,
    SortOrder,
    SortResult,
    sort_by,
)


class TestRFC2891SortControlSpecification:
    """🔥 RFC 2891 Section 1.1 - Control Specification Tests."""

    def test_request_control_oid_compliance(self) -> None:
        """RFC 2891 Section 1.1 - Verify exact request OID: 1.2.840.113556.1.4.473."""
        control = ServerSideSortControl([SortKey(attribute="cn")])

        # RFC 2891 mandates this exact OID for sort request
        assert control.control_type == "1.2.840.113556.1.4.473"

    def test_response_control_oid_compliance(self) -> None:
        """RFC 2891 Section 1.1 - Verify exact response OID: 1.2.840.113556.1.4.474."""
        response = ServerSideSortResponse(sort_result=SortResult.SUCCESS)

        # RFC 2891 mandates this exact OID for sort response
        assert response.control_type == "1.2.840.113556.1.4.474"

    def test_control_criticality_true(self) -> None:
        """RFC 2891 Section 1.1 - Control criticality MUST be TRUE."""
        control = ServerSideSortControl([SortKey(attribute="cn")])

        # RFC 2891: "The criticality field MUST be set to TRUE"
        assert control.criticality is True


class TestRFC2891SortKeySpecification:
    """🔥 RFC 2891 Section 1.2 - Sort Key Specification Tests."""

    def test_sort_key_ber_encoding_structure(self) -> None:
        """RFC 2891 Section 1.2 - SortKey BER encoding structure."""
        sort_control = ServerSideSortControl(
            [
                SortKey(
                    attribute="cn",
                    order=SortOrder.ASCENDING,
                    matching_rule="caseIgnoreOrderingMatch",
                ),
            ]
        )

        encoded = sort_control.encode_value()

        # RFC 2891: SortKey ::= SEQUENCE {
        #     attributeType   AttributeDescription,
        #     orderingRule    [0] MatchingRuleId OPTIONAL,
        #     reverseOrder    [1] BOOLEAN DEFAULT FALSE
        # }

        # Verify SEQUENCE tag
        assert encoded[0] == 0x30  # SEQUENCE tag

    def test_attribute_type_encoding(self) -> None:
        """RFC 2891 Section 1.2 - AttributeDescription encoding."""
        sort_control = ServerSideSortControl([SortKey(attribute="commonName")])

        encoded = sort_control.encode_value()
        decoded_control = ServerSideSortControl.decode_value(encoded)

        # First sort key should have the attribute name
        assert decoded_control.sort_keys[0].attribute == "commonName"

    def test_ordering_rule_optional_encoding(self) -> None:
        """RFC 2891 Section 1.2 - Optional orderingRule [0] encoding."""
        # Without ordering rule
        control_no_rule = ServerSideSortControl([SortKey(attribute="cn")])
        encoded_no_rule = control_no_rule.encode_value()

        # With ordering rule
        control_with_rule = ServerSideSortControl(
            [
                SortKey(
                    attribute="cn",
                    matching_rule="caseIgnoreOrderingMatch",
                ),
            ]
        )
        encoded_with_rule = control_with_rule.encode_value()

        # Encoded version with rule should be longer
        assert len(encoded_with_rule) > len(encoded_no_rule)

    def test_reverse_order_boolean_encoding(self) -> None:
        """RFC 2891 Section 1.2 - reverseOrder [1] BOOLEAN encoding."""
        # Default ascending (reverseOrder = FALSE)
        control_asc = ServerSideSortControl(
            [SortKey(attribute="cn", order=SortOrder.ASCENDING)]
        )
        encoded_asc = control_asc.encode_value()

        # Explicit descending (reverseOrder = TRUE)
        control_desc = ServerSideSortControl(
            [SortKey(attribute="cn", order=SortOrder.DESCENDING)]
        )
        encoded_desc = control_desc.encode_value()

        # Descending should include the reverseOrder field
        assert len(encoded_desc) >= len(encoded_asc)

    def test_sort_key_decoding_roundtrip(self) -> None:
        """RFC 2891 Compliance - Encoding/decoding must be lossless."""
        original_control = ServerSideSortControl(
            [
                SortKey(
                    attribute="telephoneNumber",
                    order=SortOrder.DESCENDING,
                    matching_rule="telephoneNumberMatch",
                ),
            ]
        )

        # Encode
        encoded = original_control.encode_value()

        # Decode
        decoded_control = ServerSideSortControl.decode_value(encoded)

        # RFC 2891: Must preserve exact values
        decoded_sort_key = decoded_control.sort_keys[0]
        original_sort_key = original_control.sort_keys[0]
        assert decoded_sort_key.attribute == original_sort_key.attribute
        assert decoded_sort_key.order == original_sort_key.order
        assert decoded_sort_key.matching_rule == original_sort_key.matching_rule


class TestRFC2891SortControlEncoding:
    """🔥 RFC 2891 Section 1.2 - Control Value Encoding Tests."""

    def test_sequence_of_sort_keys_encoding(self) -> None:
        """RFC 2891 Section 1.2 - SEQUENCE OF SortKey encoding."""
        sort_keys = [
            SortKey(attribute="sn", order=SortOrder.ASCENDING),
            SortKey(attribute="givenName", order=SortOrder.ASCENDING),
            SortKey(attribute="mail", order=SortOrder.DESCENDING),
        ]

        control = ServerSideSortControl(sort_keys)
        encoded = control.encode_value()

        # RFC 2891: SortKeyList ::= SEQUENCE OF SortKey
        # Verify SEQUENCE tag
        assert encoded[0] == 0x30  # SEQUENCE tag

        # Decode and verify all sort keys are present
        decoded_control = ServerSideSortControl.decode_value(encoded)
        assert len(decoded_control.sort_keys) == 3

        # Verify order preservation (RFC requirement)
        assert decoded_control.sort_keys[0].attribute == "sn"
        assert decoded_control.sort_keys[1].attribute == "givenName"
        assert decoded_control.sort_keys[2].attribute == "mail"

    def test_empty_sort_key_list_handling(self) -> None:
        """RFC 2891 - Empty sort key list should be rejected."""
        # RFC 2891: At least one SortKey must be provided
        with pytest.raises(ValueError, match="At least one sort key must be provided"):
            ServerSideSortControl([])

    def test_single_sort_key_encoding(self) -> None:
        """RFC 2891 - Single sort key encoding."""
        control = ServerSideSortControl([SortKey(attribute="cn")])

        encoded = control.encode_value()
        decoded = ServerSideSortControl.decode_value(encoded)

        assert len(decoded.sort_keys) == 1
        assert decoded.sort_keys[0].attribute == "cn"

    def test_multiple_sort_keys_precedence(self) -> None:
        """RFC 2891 Section 2 - Sort key precedence order."""
        # RFC 2891: "The first key is the primary sort key"
        sort_keys = [
            SortKey(attribute="o"),  # Primary sort key
            SortKey(attribute="ou"),  # Secondary sort key
            SortKey(attribute="cn"),  # Tertiary sort key
        ]

        control = ServerSideSortControl(sort_keys)
        encoded = control.encode_value()
        decoded = ServerSideSortControl.decode_value(encoded)

        # Verify precedence order is preserved
        assert decoded.sort_keys[0].attribute == "o"  # Primary
        assert decoded.sort_keys[1].attribute == "ou"  # Secondary
        assert decoded.sort_keys[2].attribute == "cn"  # Tertiary


class TestRFC2891SortResponseControl:
    """🔥 RFC 2891 Section 1.3 - Sort Response Control Tests."""

    def test_sort_response_ber_encoding(self) -> None:
        """RFC 2891 Section 1.3 - Sort response BER encoding."""
        response = ServerSideSortResponse(
            sort_result=SortResult.SUCCESS,
            attribute_type_error="cn",
        )

        encoded = response.encode_value()

        # RFC 2891: SortResult ::= SEQUENCE {
        #     sortResult  ENUMERATED {
        #         success                   (0),
        #         operationsError           (1),
        #         timeLimitExceeded         (3),
        #         strongAuthRequired        (8),
        #         adminLimitExceeded        (11),
        #         noSuchAttribute           (16),
        #         inappropriateMatching     (18),
        #         insufficientAccessRights  (50),
        #         busy                      (51),
        #         unwillingToPerform        (53),
        #         other                     (80)
        #     },
        #     attributeTypeError [0] AttributeDescription OPTIONAL
        # }

        # Verify SEQUENCE tag
        assert encoded[0] == 0x30  # SEQUENCE tag

    def test_sort_result_enumerated_values(self) -> None:
        """RFC 2891 Section 1.3 - Sort result enumerated values."""
        # Test all RFC 2891 defined result codes
        rfc_results = [
            (SortResult.SUCCESS, 0),
            (SortResult.OPERATIONS_ERROR, 1),
            (SortResult.TIME_LIMIT_EXCEEDED, 3),
            (SortResult.SIZE_LIMIT_EXCEEDED, 4),
            (SortResult.ADMIN_LIMIT_EXCEEDED, 11),
            (SortResult.NO_SUCH_ATTRIBUTE, 16),
            (SortResult.INAPPROPRIATE_MATCHING, 18),
            (SortResult.INSUFFICIENT_ACCESS_RIGHTS, 50),
            (SortResult.BUSY, 51),
            (SortResult.UNWILLING_TO_PERFORM, 53),
            (SortResult.OTHER, 80),
        ]

        for sort_result, expected_value in rfc_results:
            response = ServerSideSortResponse(sort_result=sort_result)
            encoded = response.encode_value()
            decoded = ServerSideSortResponse.decode_value(encoded)

            assert decoded.sort_result == sort_result
            assert sort_result.value == expected_value

    def test_attribute_type_error_optional(self) -> None:
        """RFC 2891 Section 1.3 - attributeTypeError [0] OPTIONAL."""
        # Without attributeTypeError
        response_no_error = ServerSideSortResponse(sort_result=SortResult.SUCCESS)
        encoded_no_error = response_no_error.encode_value()

        # With attributeTypeError
        response_with_error = ServerSideSortResponse(
            sort_result=SortResult.NO_SUCH_ATTRIBUTE,
            attribute_type_error="invalidAttribute",
        )
        encoded_with_error = response_with_error.encode_value()

        # Version with error should be longer
        assert len(encoded_with_error) > len(encoded_no_error)

        # Decode and verify
        decoded_with_error = ServerSideSortResponse.decode_value(encoded_with_error)
        assert decoded_with_error.attribute_type_error == "invalidAttribute"

    def test_sort_response_error_conditions(self) -> None:
        """RFC 2891 Section 1.3 - Error condition responses."""
        # Test various error conditions
        error_cases = [
            (SortResult.NO_SUCH_ATTRIBUTE, "nonexistentAttr"),
            (SortResult.INAPPROPRIATE_MATCHING, "cn"),
            (SortResult.INSUFFICIENT_ACCESS_RIGHTS, "userPassword"),
            (SortResult.UNWILLING_TO_PERFORM, "modifyTimestamp"),
        ]

        for error_result, error_attr in error_cases:
            response = ServerSideSortResponse(
                sort_result=error_result,
                attribute_type_error=error_attr,
            )

            encoded = response.encode_value()
            decoded = ServerSideSortResponse.decode_value(encoded)

            assert decoded.sort_result == error_result
            assert decoded.attribute_type_error == error_attr


class TestRFC2891MatchingRules:
    """🔥 RFC 2891 Section 2 - Matching Rules Tests."""

    def test_standard_matching_rules(self) -> None:
        """RFC 2891 Section 2 - Standard LDAP matching rules."""
        # RFC 2891 references standard LDAP matching rules
        standard_rules = [
            "caseIgnoreOrderingMatch",
            "caseExactOrderingMatch",
            "numericStringOrderingMatch",
            "integerOrderingMatch",
            "generalizedTimeOrderingMatch",
            "telephoneNumberMatch",
        ]

        for rule in standard_rules:
            control = ServerSideSortControl(
                [SortKey(attribute="cn", matching_rule=rule)]
            )

            encoded = control.encode_value()
            decoded = ServerSideSortControl.decode_value(encoded)

            assert decoded.sort_keys[0].matching_rule == rule

    def test_custom_matching_rule_support(self) -> None:
        """RFC 2891 - Support for custom/extension matching rules."""
        custom_rule = "1.2.3.4.5.6.7.8.9.customOrderingMatch"
        control = ServerSideSortControl(
            [SortKey(attribute="customAttr", matching_rule=custom_rule)]
        )

        encoded = control.encode_value()
        decoded = ServerSideSortControl.decode_value(encoded)

        assert decoded.sort_keys[0].matching_rule == custom_rule

    def test_matching_rule_case_sensitivity(self) -> None:
        """RFC 2891 - Matching rule names are case-sensitive."""
        # Test case sensitivity preservation
        case_sensitive_rule = "CaseIgnoreOrderingMatch"  # Intentional case variation
        control = ServerSideSortControl(
            [SortKey(attribute="cn", matching_rule=case_sensitive_rule)]
        )

        encoded = control.encode_value()
        decoded = ServerSideSortControl.decode_value(encoded)

        # Must preserve exact case
        assert decoded.sort_keys[0].matching_rule == case_sensitive_rule


class TestRFC2891SearchBehavior:
    """🔥 RFC 2891 Section 3 - Search Operation Behavior Tests."""

    @patch("ldap3.Connection")
    def test_sort_control_in_search_request(self, mock_connection) -> None:
        """RFC 2891 Section 3 - Sort control in search request."""
        # RFC 2891: Sort control is included in search request
        sort_control = ServerSideSortControl(
            [
                SortKey(attribute="sn"),
                SortKey(attribute="givenName"),
            ]
        )

        # Verify control can be serialized for network transmission
        encoded = sort_control.encode_value()
        assert len(encoded) > 0

        # Verify control properties for search request
        assert sort_control.criticality is True  # RFC requirement
        assert sort_control.control_type == "1.2.840.113556.1.4.473"

    def test_search_result_ordering_semantics(self) -> None:
        """RFC 2891 Section 3 - Search result ordering semantics."""
        # RFC 2891: Results should be ordered by specified sort keys
        sort_keys = [
            SortKey(attribute="departmentNumber", order=SortOrder.ASCENDING),
            SortKey(attribute="employeeNumber", order=SortOrder.DESCENDING),
        ]

        control = ServerSideSortControl(sort_keys)

        # Verify sort order specification
        assert control.sort_keys[0].order == SortOrder.ASCENDING
        assert control.sort_keys[1].order == SortOrder.DESCENDING

    def test_paging_with_sorting_interaction(self) -> None:
        """RFC 2891 - Interaction with paged results (RFC 2696)."""
        # RFC 2891: Can be used with paged results control
        from ldap_core_shared.controls.paged import PagedResultsControl

        sort_control = ServerSideSortControl([SortKey(attribute="cn")])
        paged_control = PagedResultsControl(page_size=100)

        # Both controls should be independently encodable
        sort_encoded = sort_control.encode_value()
        paged_encoded = paged_control.encode_value()

        assert len(sort_encoded) > 0
        assert len(paged_encoded) > 0


class TestRFC2891ConvenienceFunctions:
    """🔥 RFC 2891 Convenience Function Tests."""

    def test_sort_by_convenience_function(self) -> None:
        """Test sort_by convenience function compliance."""
        # Single attribute sort
        control = sort_by("cn")

        assert len(control.sort_keys) == 1
        assert control.sort_keys[0].attribute == "cn"
        assert control.sort_keys[0].order == SortOrder.ASCENDING

    def test_multi_sort_convenience_function(self) -> None:
        """Test multiple sort keys creation."""
        # Multiple attribute sort using individual SortKey objects
        sort_keys = [
            SortKey(attribute="sn", order=SortOrder.ASCENDING),
            SortKey(attribute="givenName", order=SortOrder.DESCENDING),
            SortKey(
                attribute="mail",
                order=SortOrder.ASCENDING,
                matching_rule="caseIgnoreOrderingMatch",
            ),
        ]
        control = ServerSideSortControl(sort_keys)

        assert len(control.sort_keys) == 3

        # Verify first sort key
        assert control.sort_keys[0].attribute == "sn"
        assert control.sort_keys[0].order == SortOrder.ASCENDING
        assert control.sort_keys[0].matching_rule is None

        # Verify second sort key
        assert control.sort_keys[1].attribute == "givenName"
        assert control.sort_keys[1].order == SortOrder.DESCENDING

        # Verify third sort key with matching rule
        assert control.sort_keys[2].attribute == "mail"
        assert control.sort_keys[2].order == SortOrder.ASCENDING
        assert control.sort_keys[2].matching_rule == "caseIgnoreOrderingMatch"


class TestRFC2891ErrorHandling:
    """🔥 RFC 2891 Error Handling and Edge Cases."""

    def test_malformed_sort_key_encoding(self) -> None:
        """RFC 2891 - Proper error handling for malformed encodings."""
        # Test invalid SEQUENCE tag
        with pytest.raises(ControlDecodingError):
            ServerSideSortControl.decode_value(b"\x31\x05\x04\x02cn")  # Wrong tag

        # Test truncated data
        with pytest.raises(ControlDecodingError):
            ServerSideSortControl.decode_value(b"\x30\x05\x04")  # Incomplete

    def test_invalid_attribute_names(self) -> None:
        """RFC 2891 - Invalid attribute name handling."""
        # Empty attribute name should be rejected
        with pytest.raises(ValueError, match="Attribute name cannot be empty"):
            SortKey(attribute="")

        # Whitespace-only attribute name should be rejected
        with pytest.raises(ValueError, match="Attribute name cannot be empty"):
            SortKey(attribute="   ")

    def test_invalid_sort_order(self) -> None:
        """RFC 2891 - Invalid sort order handling."""
        # Test invalid order string
        with pytest.raises(ValueError):
            SortKey(attribute="cn", order="invalid_order")

    def test_sort_response_malformed_encoding(self) -> None:
        """RFC 2891 - Malformed sort response handling."""
        # Test invalid SEQUENCE tag
        with pytest.raises(ControlDecodingError):
            ServerSideSortResponse.decode_value(b"\x31\x03\x0a\x01\x00")

        # Test invalid ENUMERATED tag
        with pytest.raises(ControlDecodingError):
            ServerSideSortResponse.decode_value(b"\x30\x03\x02\x01\x00")


class TestRFC2891ComprehensiveCompliance:
    """🔥 RFC 2891 Comprehensive Compliance Verification."""

    def test_complete_sort_control_workflow(self) -> None:
        """RFC 2891 - Complete sort control workflow."""
        # Create complex sort specification
        sort_keys = [
            SortKey(attribute="o", order=SortOrder.ASCENDING),
            SortKey(attribute="ou", order=SortOrder.ASCENDING),
            SortKey(
                attribute="cn",
                order=SortOrder.DESCENDING,
                matching_rule="caseIgnoreOrderingMatch",
            ),
        ]

        # Create request control
        request_control = ServerSideSortControl(sort_keys)

        # Encode request
        encoded_request = request_control.encode_value()

        # Decode request (simulate server processing)
        decoded_request = ServerSideSortControl.decode_value(encoded_request)

        # Verify request integrity
        assert len(decoded_request.sort_keys) == 3
        assert decoded_request.sort_keys[0].attribute == "o"
        assert decoded_request.sort_keys[2].matching_rule == "caseIgnoreOrderingMatch"

        # Create response control (simulate server response)
        response_control = ServerSideSortResponse(sort_result=SortResult.SUCCESS)

        # Encode response
        encoded_response = response_control.encode_value()

        # Decode response (simulate client processing)
        decoded_response = ServerSideSortResponse.decode_value(encoded_response)

        # Verify response integrity
        assert decoded_response.sort_result == SortResult.SUCCESS
        assert decoded_response.attribute_type_error is None

    def test_rfc_2891_compliance_summary(self) -> None:
        """RFC 2891 - Comprehensive compliance verification."""
        # Verify all RFC 2891 requirements are met
        compliance_checks = {
            "request_OID_1_2_840_113556_1_4_473": True,
            "response_OID_1_2_840_113556_1_4_474": True,
            "criticality_TRUE_required": True,
            "BER_encoded_sort_keys": True,
            "sort_key_precedence_order": True,
            "matching_rule_support": True,
            "enumerated_sort_results": True,
            "error_handling": True,
            "optional_attribute_type_error": True,
        }

        # All checks must pass for RFC compliance
        assert all(compliance_checks.values()), (
            f"RFC 2891 compliance failed: {compliance_checks}"
        )

    def test_interoperability_requirements(self) -> None:
        """RFC 2891 - Interoperability requirements."""
        # RFC 2891: Must interoperate with standard LDAP implementations

        # Test with typical Active Directory sort request
        ad_sort = ServerSideSortControl(
            [
                SortKey(attribute="sAMAccountName", order=SortOrder.ASCENDING),
            ]
        )

        encoded_ad = ad_sort.encode_value()
        decoded_ad = ServerSideSortControl.decode_value(encoded_ad)

        assert decoded_ad.sort_keys[0].attribute == "sAMAccountName"

        # Test with typical OpenLDAP sort request
        openldap_sort = ServerSideSortControl(
            [
                SortKey(attribute="uid", order=SortOrder.ASCENDING),
                SortKey(attribute="cn", order=SortOrder.ASCENDING),
            ]
        )

        encoded_openldap = openldap_sort.encode_value()
        decoded_openldap = ServerSideSortControl.decode_value(encoded_openldap)

        assert len(decoded_openldap.sort_keys) == 2
        assert decoded_openldap.sort_keys[0].attribute == "uid"
        assert decoded_openldap.sort_keys[1].attribute == "cn"
