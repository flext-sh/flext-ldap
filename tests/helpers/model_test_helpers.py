"""Generic model test helpers for flext-ldap tests.

Provides reusable helpers for model validation, factory methods, and
common test patterns that can be shared across multiple test modules.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Protocol, TypeVar, runtime_checkable

from flext_core import FlextResult
from flext_tests import FlextTestsUtilities

TModel = TypeVar("TModel")
TValue = TypeVar("TValue")
TModelCo_co = TypeVar("TModelCo_co", covariant=True)


@runtime_checkable
class ModelFactory(Protocol[TModelCo_co]):
    """Protocol for model factory methods."""

    def __call__(self, **kwargs: object) -> TModelCo_co:
        """Create a model instance from kwargs."""
        ...


class ModelTestHelpers:
    """Generic helpers for model testing with reusable patterns."""

    @staticmethod
    def assert_model_creation_success(
        factory_method: ModelFactory[TModel],
        expected_attrs: dict[str, object],
        **factory_kwargs: object,
    ) -> TModel:
        """Assert successful model creation and validate attributes.

        Args:
            factory_method: Factory method to create the model
            expected_attrs: Expected attribute values to validate
            **factory_kwargs: Arguments for the factory method

        Returns:
            Created model instance

        Raises:
            AssertionError: If creation fails or attributes don't match

        """
        instance = factory_method(**factory_kwargs)

        for attr, expected_value in expected_attrs.items():
            actual_value = getattr(instance, attr)
            assert actual_value == expected_value, (
                f"Attribute '{attr}' mismatch: expected {expected_value}, got {actual_value}"
            )

        return instance

    @staticmethod
    def assert_model_validation_failure(
        factory_method: ModelFactory[TModel],
        expected_error_patterns: list[str],
        **factory_kwargs: object,
    ) -> None:
        """Assert model creation fails with expected validation errors.

        Args:
            factory_method: Factory method that should raise ValueError
            expected_error_patterns: Patterns that should be in the error message
            **factory_kwargs: Arguments for the factory method

        Raises:
            AssertionError: If validation doesn't fail or error doesn't match patterns

        """
        try:
            factory_method(**factory_kwargs)
            msg = "Expected ValueError but model creation succeeded"
            raise AssertionError(msg)
        except ValueError as e:
            error_msg = str(e)
            for pattern in expected_error_patterns:
                assert pattern in error_msg, (
                    f"Expected error pattern '{pattern}' not found in: {error_msg}"
                )

    @staticmethod
    def parametrize_model_scenarios(
        scenarios: dict[str, dict[str, object]],
    ) -> list[tuple[str, dict[str, object]]]:
        """Create parametrized test cases from scenario dictionaries.

        Args:
            scenarios: Dictionary mapping scenario names to test parameters

        Returns:
            List of (scenario_name, params) tuples for pytest.mark.parametrize

        """
        return list(scenarios.items())

    @staticmethod
    def create_computed_property_test_cases(
        model_factory: ModelFactory[TModel],
        property_name: str,
        test_cases: list[tuple[dict[str, object], TValue]],
    ) -> list[tuple[TModel, TValue]]:
        """Create test cases for computed properties.

        Args:
            model_factory: Factory to create model instances
            property_name: Name of the computed property to test
            test_cases: List of (factory_kwargs, expected_value) tuples

        Returns:
            List of (model_instance, expected_value) tuples

        """
        result_cases = []
        for factory_kwargs, expected_value in test_cases:
            instance = model_factory(**factory_kwargs)
            result_cases.append((instance, expected_value))
        return result_cases

    @staticmethod
    def assert_result_type_and_value(
        result: FlextResult[TModel],
        expected_success: bool,
        expected_value: TModel | None = None,
    ) -> None:
        """Assert FlextResult type and value.

        Args:
            result: Result to validate
            expected_success: Whether result should be successful
            expected_value: Expected value for success results

        """
        if expected_success:
            FlextTestsUtilities.TestUtilities.assert_result_success(result)
            if expected_value is not None:
                assert result.value == expected_value
        else:
            FlextTestsUtilities.TestUtilities.assert_result_failure(result)

    @staticmethod
    def batch_create_models(
        factory_method: ModelFactory[TModel],
        count: int,
        base_kwargs: dict[str, object],
        variations: list[dict[str, object]] | None = None,
    ) -> list[TModel]:
        """Create a batch of model instances with variations.

        Args:
            factory_method: Factory method to create models
            count: Number of instances to create
            base_kwargs: Base kwargs for all instances
            variations: Optional list of variation kwargs (cycled if fewer than count)

        Returns:
            List of created model instances

        """
        instances = []
        for i in range(count):
            kwargs = base_kwargs.copy()
            if variations:
                variation = variations[i % len(variations)]
                kwargs.update(variation)
            instances.append(factory_method(**kwargs))
        return instances
