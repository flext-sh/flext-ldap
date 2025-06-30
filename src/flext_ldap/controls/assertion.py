"""LDAP Assertion Control Implementation.

This module implements the LDAP Assertion Control as defined in RFC 4528.
The assertion control allows clients to specify that a directory operation
should only be processed if an assertion applied to the target entry
is true.

RFC 4528 defines the Assertion Control which enables conditional operations:
- "test and set" operations
- "test and clear" operations
- Other conditional operations based on entry state

The control can be used with:
- Add operations: Only add if condition is true
- Delete operations: Only delete if condition is true
- Modify operations: Only modify if condition is true
- ModifyDN operations: Only rename if condition is true
- Search operations: Assert condition on base object before searching
- Compare operations: Extend compare with complex assertions

Usage Example:
    >>> from flext_ldap.controls.assertion import AssertionControl
    >>>
    >>> # Only modify if employeeType is 'contractor'
    >>> assertion = AssertionControl(filter_expr="(employeeType=contractor)")
    >>>
    >>> # Perform conditional modify
    >>> result = connection.modify(
    ...     dn="cn=john.doe,ou=people,dc=example,dc=com",
    ...     changes=[("replace", "title", ["Senior Contractor"])],
    ...     controls=[assertion],
    ... )
    >>>
    >>> # Complex assertion with AND/OR logic
    >>> complex_assertion = AssertionControl(
    ...     filter_expr="(&(department=IT)(!(accountLocked=TRUE)))"
    ... )

References:
    - RFC 4528: Lightweight Directory Access Protocol (LDAP) Assertion Control
    - OID: 1.3.6.1.1.12
    - RFC 4511: LDAP Filter encoding
"""

from __future__ import annotations

from flext_ldapn1_encoder import ASN1Decoder, ASN1Encoder
from flext_ldapse import (
    ControlDecodingError,
    ControlEncodingError,
    ControlOIDs,
    LDAPControl,
)
from pydantic import Field, validator


class AssertionControl(LDAPControl):
    """LDAP Assertion Control (RFC 4528).

    This control specifies a condition that must be true for the operation
    to be processed normally. The assertion is an LDAP filter applied to
    the target entry of the operation.

    The control causes the operation to fail with assertionFailed (122)
    if the assertion evaluates to false or undefined.

    Attributes:
        filter_expr: LDAP filter expression that must evaluate to true
        criticality: Whether this control is critical (recommended: True)

    Note:
        The filter is applied to the target entry before the operation.
        For search operations, it's applied to the base object.

        This control is typically marked as critical since the application
        depends on the conditional behavior.
    """

    control_type = ControlOIDs.ASSERTION

    filter_expr: str = Field(
        description="LDAP filter expression for the assertion",
        min_length=1,
    )

    # Override default criticality to True for assertion controls
    criticality: bool = Field(
        default=True,
        description="Whether this control is critical (recommended: True)",
    )

    @validator("filter_expr")
    def validate_filter_expression(self, v: str) -> str:
        """Validate LDAP filter expression syntax."""
        if not v or not v.strip():
            msg = "Filter expression cannot be empty"
            raise ValueError(msg)

        v = v.strip()

        # Basic validation for LDAP filter format
        if not (v.startswith("(") and v.endswith(")")):
            msg = "Filter expression must be enclosed in parentheses"
            raise ValueError(msg)

        # Check for balanced parentheses
        paren_count = 0
        for char in v:
            if char == "(":
                paren_count += 1
            elif char == ")":
                paren_count -= 1
                if paren_count < 0:
                    msg = "Unbalanced parentheses in filter expression"
                    raise ValueError(msg)

        if paren_count != 0:
            msg = "Unbalanced parentheses in filter expression"
            raise ValueError(msg)

        return v

    def encode_value(self) -> bytes:
        """Encode assertion control value as ASN.1 per RFC 4528.

        The control value is the BER encoding of an LDAP filter (AssertionValue).

        RFC 4528 Section 3:
        The controlValue is the BER encoding of an AssertionValue:

        AssertionValue ::= LDAPString

        However, the filter is encoded using the LDAP filter encoding
        rules from RFC 4511 Section 4.5.1.

        Returns:
            ASN.1 BER encoded filter expression

        Raises:
            ControlEncodingError: If encoding fails
        """
        try:
            # For now, encode the filter as a UTF8String
            # TODO: Implement proper LDAP filter BER encoding per RFC 4511
            # This requires parsing and encoding the filter according to
            # the Filter BNF grammar in RFC 4511 Section 4.5.1

            # Simple encoding as UTF8String (adequate for basic filters)
            return ASN1Encoder.encode_utf8_string(self.filter_expr)

        except Exception as e:
            msg = f"Failed to encode assertion control: {e}"
            raise ControlEncodingError(msg) from e

    @classmethod
    def decode_value(cls, control_value: bytes | None) -> AssertionControl:
        """Decode assertion control value per RFC 4528.

        Args:
            control_value: ASN.1 encoded control value

        Returns:
            AssertionControl instance

        Raises:
            ControlDecodingError: If decoding fails
        """
        if not control_value:
            msg = "Assertion control requires a value"
            raise ControlDecodingError(msg)

        try:
            # For now, decode as UTF8String
            # TODO: Implement proper LDAP filter BER decoding per RFC 4511
            filter_expr, _ = ASN1Decoder.decode_utf8_string(control_value, 0)

            return cls(filter_expr=filter_expr)

        except Exception as e:
            msg = f"Failed to decode assertion control: {e}"
            raise ControlDecodingError(msg) from e

    def is_simple_equality(self) -> bool:
        """Check if this is a simple equality assertion.

        Returns:
            True if filter is a simple equality like (attr=value)
        """
        if not self.filter_expr.startswith("(") or not self.filter_expr.endswith(")"):
            return False

        inner = self.filter_expr[1:-1]
        return "=" in inner and not any(
            op in inner for op in ["&", "|", "!", ">=", "<=", "~=", "*"]
        )

    def get_assertion_attribute(self) -> str | None:
        """Get the attribute name for simple equality assertions.

        Returns:
            Attribute name if this is a simple equality assertion, None otherwise
        """
        if not self.is_simple_equality():
            return None

        inner = self.filter_expr[1:-1]
        if "=" in inner:
            return inner.split("=", 1)[0].strip()
        return None

    def get_assertion_value(self) -> str | None:
        """Get the assertion value for simple equality assertions.

        Returns:
            Assertion value if this is a simple equality assertion, None otherwise
        """
        if not self.is_simple_equality():
            return None

        inner = self.filter_expr[1:-1]
        if "=" in inner:
            return inner.split("=", 1)[1].strip()
        return None

    @classmethod
    def simple_equality(
        cls,
        attribute: str,
        value: str,
        critical: bool = True,
    ) -> AssertionControl:
        """Create assertion control for simple equality test.

        Args:
            attribute: Attribute name to test
            value: Value to test for
            critical: Whether control is critical

        Returns:
            AssertionControl for equality test

        Example:
            >>> ctrl = AssertionControl.simple_equality("employeeType", "contractor")
            >>> # Creates filter: (employeeType=contractor)
        """
        filter_expr = f"({attribute}={value})"
        return cls(filter_expr=filter_expr, criticality=critical)

    @classmethod
    def attribute_exists(
        cls,
        attribute: str,
        critical: bool = True,
    ) -> AssertionControl:
        """Create assertion control to test if attribute exists.

        Args:
            attribute: Attribute name to test for existence
            critical: Whether control is critical

        Returns:
            AssertionControl for existence test

        Example:
            >>> ctrl = AssertionControl.attribute_exists("employeeNumber")
            >>> # Creates filter: (employeeNumber=*)
        """
        filter_expr = f"({attribute}=*)"
        return cls(filter_expr=filter_expr, criticality=critical)

    @classmethod
    def attribute_not_exists(
        cls,
        attribute: str,
        critical: bool = True,
    ) -> AssertionControl:
        """Create assertion control to test if attribute does not exist.

        Args:
            attribute: Attribute name to test for non-existence
            critical: Whether control is critical

        Returns:
            AssertionControl for non-existence test

        Example:
            >>> ctrl = AssertionControl.attribute_not_exists("accountLocked")
            >>> # Creates filter: (!(accountLocked=*))
        """
        filter_expr = f"(!({attribute}=*))"
        return cls(filter_expr=filter_expr, criticality=critical)

    @classmethod
    def multiple_conditions(
        cls,
        conditions: list[str],
        operator: str = "AND",
        critical: bool = True,
    ) -> AssertionControl:
        """Create assertion control with multiple conditions.

        Args:
            conditions: List of filter conditions (without outer parentheses)
            operator: Logical operator ("AND" or "OR")
            critical: Whether control is critical

        Returns:
            AssertionControl for combined conditions

        Example:
            >>> conditions = ["department=IT", "!(accountLocked=TRUE)"]
            >>> ctrl = AssertionControl.multiple_conditions(conditions, "AND")
            >>> # Creates filter: (&(department=IT)(!(accountLocked=TRUE)))
        """
        if not conditions:
            msg = "At least one condition is required"
            raise ValueError(msg)

        if len(conditions) == 1:
            # Single condition
            filter_expr = f"({conditions[0]})"
        else:
            # Multiple conditions
            op_char = "&" if operator.upper() == "AND" else "|"
            condition_parts = [
                f"({cond})" if not cond.startswith("(") else cond for cond in conditions
            ]
            filter_expr = f"({op_char}{''.join(condition_parts)})"

        return cls(filter_expr=filter_expr, criticality=critical)

    def __str__(self) -> str:
        """String representation of assertion control."""
        return f"AssertionControl(filter='{self.filter_expr}', critical={self.criticality})"

    def __repr__(self) -> str:
        """Detailed representation of assertion control."""
        return (
            f"AssertionControl("
            f"filter_expr='{self.filter_expr}', "
            f"criticality={self.criticality})"
        )


# Convenience functions for common assertion patterns
def assert_equals(
    attribute: str,
    value: str,
    critical: bool = True,
) -> AssertionControl:
    """Create assertion that attribute equals value.

    Args:
        attribute: Attribute name
        value: Expected value
        critical: Whether control is critical

    Returns:
        AssertionControl for equality test
    """
    return AssertionControl.simple_equality(attribute, value, critical)


def assert_exists(attribute: str, critical: bool = True) -> AssertionControl:
    """Create assertion that attribute exists.

    Args:
        attribute: Attribute name
        critical: Whether control is critical

    Returns:
        AssertionControl for existence test
    """
    return AssertionControl.attribute_exists(attribute, critical)


def assert_not_exists(attribute: str, critical: bool = True) -> AssertionControl:
    """Create assertion that attribute does not exist.

    Args:
        attribute: Attribute name
        critical: Whether control is critical

    Returns:
        AssertionControl for non-existence test
    """
    return AssertionControl.attribute_not_exists(attribute, critical)


def assert_and(*conditions: str, critical: bool = True) -> AssertionControl:
    """Create assertion with AND logic.

    Args:
        *conditions: Filter conditions
        critical: Whether control is critical

    Returns:
        AssertionControl with AND logic
    """
    return AssertionControl.multiple_conditions(list(conditions), "AND", critical)


def assert_or(*conditions: str, critical: bool = True) -> AssertionControl:
    """Create assertion with OR logic.

    Args:
        *conditions: Filter conditions
        critical: Whether control is critical

    Returns:
        AssertionControl with OR logic
    """
    return AssertionControl.multiple_conditions(list(conditions), "OR", critical)


# TODO: Future enhancements for RFC compliance:
#
# 1. LDAP Filter BER Encoding:
#    - Implement proper filter parsing according to RFC 4511 Section 4.5.1
#    - Convert string filters to proper ASN.1 Filter structures
#    - Support all LDAP filter operators (=, >=, <=, ~=, presence, substrings)
#    - Handle complex nested filters with proper precedence
#
# 2. Filter Validation:
#    - Complete filter syntax validation
#    - Validate attribute names against schema
#    - Validate filter values for proper escaping
#    - Support extensible matching rules
#
# 3. Error Handling:
#    - Map assertion failures to proper LDAP result codes
#    - Provide detailed error messages for filter syntax errors
#    - Handle server capabilities for assertion support
#
# 4. Performance Optimizations:
#    - Cache parsed filter structures
#    - Optimize filter encoding for frequently used patterns
#    - Support filter compilation for repeated use
#
# 5. Integration Points:
#    - Connection manager integration for assertion result handling
#    - Search engine integration for base object assertions
#    - Transaction manager integration for atomic operations
