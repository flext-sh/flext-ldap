"""Generic Rules Engine for LDAP Migration - ZERO TOLERANCE for hardcoded logic.

This module provides a generic rules engine that can be extended by specific
migration projects. Contains ONLY generic rule processing with NO business logic.

Key Principles:
- Generic rule definition and validation
- Pluggable rule processors
- Business-agnostic rule execution
- Type-safe rule configuration

Business Logic Location:
- Project-specific rules MUST be defined in project configuration files
- Business logic MUST be implemented in project-specific rule processors
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol, TypeVar

from loguru import logger

from flext_ldap.domain.results import Result

if TYPE_CHECKING:
    from pathlib import Path

T = TypeVar("T")


@dataclass
class GenericRule:
    """Generic rule definition - NO business logic.

    This is a data container for rule information.
    Business logic is implemented in rule processors.
    """

    rule_id: str
    rule_type: str
    priority: int
    conditions: dict[str, Any]
    actions: dict[str, Any]
    metadata: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        """Validate generic rule structure."""
        if not self.rule_id:
            msg = "rule_id cannot be empty"
            raise ValueError(msg)
        if not self.rule_type:
            msg = "rule_type cannot be empty"
            raise ValueError(msg)
        if self.priority < 0:
            msg = "priority must be non-negative"
            raise ValueError(msg)


@dataclass
class RuleExecutionContext:
    """Context for rule execution - generic information only."""

    entry: dict[str, Any]
    entry_index: int
    total_entries: int
    execution_metadata: dict[str, Any]


class RuleProcessor(Protocol):
    """Protocol for rule processors - ZERO TOLERANCE for implementation details."""

    def can_process(self, rule: GenericRule) -> bool:
        """Check if processor can handle this rule type."""
        ...

    def process_rule(
        self,
        rule: GenericRule,
        context: RuleExecutionContext,
    ) -> Result[dict[str, Any]]:
        """Process rule against context and return result."""
        ...


class GenericRulesEngine:
    """Generic rules engine - NO business logic, only framework.

    This class provides the framework for rule processing.
    Business-specific processors MUST be registered separately.
    """

    def __init__(self) -> None:
        """Initialize generic rules engine."""
        self.rules: list[GenericRule] = []
        self.processors: list[RuleProcessor] = []
        self.execution_stats: dict[str, Any] = {}

        logger.debug("✅ Generic rules engine initialized")

    def register_processor(self, processor: RuleProcessor) -> None:
        """Register a rule processor.

        Args:
            processor: Rule processor implementing the protocol
        """
        self.processors.append(processor)
        logger.debug("➕ Registered rule processor: %s", type(processor).__name__)

    def load_rules_from_file(self, rules_file: Path) -> Result[int]:
        """Load rules from JSON configuration file.

        Args:
            rules_file: Path to rules configuration file

        Returns:
            Result containing number of rules loaded or error
        """
        try:
            if not rules_file.exists():
                return Result.fail(f"Rules file does not exist: {rules_file}")

            with open(rules_file, encoding="utf-8") as f:
                rules_data = json.load(f)

            return self._parse_rules_data(rules_data)

        except json.JSONDecodeError as e:
            return Result.fail(f"Invalid JSON in rules file: {e}")
        except Exception as e:
            return Result.fail(f"Failed to load rules file: {e}")

    def _parse_rules_data(self, rules_data: dict[str, Any]) -> Result[int]:
        """Parse rules data from configuration.

        Args:
            rules_data: Rules data from configuration file

        Returns:
            Result containing number of rules parsed or error
        """
        try:
            rules_list = []

            # Parse rules from different sections
            for section_name, section_data in rules_data.items():
                if isinstance(section_data, dict) and "rules" in section_data:
                    section_rules = section_data["rules"]
                    if isinstance(section_rules, list):
                        for rule_data in section_rules:
                            rule = self._create_rule_from_data(rule_data, section_name)
                            if rule:
                                rules_list.append(rule)

            # Sort rules by priority
            rules_list.sort(key=lambda r: r.priority)
            self.rules = rules_list

            logger.info("✅ Loaded %s rules from configuration", len(self.rules))
            return Result.ok(len(self.rules))

        except Exception as e:
            return Result.fail(f"Failed to parse rules data: {e}")

    def _create_rule_from_data(
        self,
        rule_data: dict[str, Any],
        section_name: str,
    ) -> GenericRule | None:
        """Create a generic rule from data.

        Args:
            rule_data: Rule data from configuration
            section_name: Name of configuration section

        Returns:
            GenericRule instance or None if invalid
        """
        try:
            rule_id = rule_data.get("id", f"{section_name}_{len(self.rules)}")
            rule_type = rule_data.get("type", section_name)
            priority = rule_data.get("priority", 999)
            conditions = rule_data.get("conditions", {})
            actions = rule_data.get("actions", {})
            metadata = rule_data.get("metadata", {})

            return GenericRule(
                rule_id=rule_id,
                rule_type=rule_type,
                priority=priority,
                conditions=conditions,
                actions=actions,
                metadata=metadata,
            )

        except Exception as e:
            logger.warning("⚠️ Failed to create rule from data: %s", e)
            return None

    def execute_rules(
        self,
        entries: list[dict[str, Any]],
    ) -> Result[list[dict[str, Any]]]:
        """Execute rules against entries.

        Args:
            entries: List of entries to process

        Returns:
            Result containing processed entries or error
        """
        if not self.rules:
            logger.warning("⚠️ No rules loaded, returning entries unchanged")
            return Result.ok(entries)

        if not self.processors:
            return Result.fail("No rule processors registered")

        try:
            processed_entries = []
            execution_stats = {
                "total_entries": len(entries),
                "rules_executed": 0,
                "processing_errors": 0,
                "rule_stats": {},
            }

            for entry_index, entry in enumerate(entries):
                context = RuleExecutionContext(
                    entry=entry,
                    entry_index=entry_index,
                    total_entries=len(entries),
                    execution_metadata={},
                )

                processed_entry = self._execute_rules_for_entry(
                    context,
                    execution_stats,
                )
                processed_entries.append(processed_entry)

            self.execution_stats = execution_stats
            logger.info("✅ Executed rules for %s entries", len(processed_entries))

            return Result.ok(processed_entries)

        except Exception as e:
            return Result.fail(f"Rule execution failed: {e}")

    def _execute_rules_for_entry(
        self,
        context: RuleExecutionContext,
        execution_stats: dict[str, Any],
    ) -> dict[str, Any]:
        """Execute rules for a single entry.

        Args:
            context: Rule execution context
            execution_stats: Execution statistics to update

        Returns:
            Processed entry
        """
        entry = context.entry.copy()

        for rule in self.rules:
            processor = self._find_processor_for_rule(rule)
            if not processor:
                continue

            try:
                result = processor.process_rule(rule, context)
                execution_stats["rules_executed"] += 1

                if result.success and result.data:
                    # Update entry with processed data
                    entry.update(result.data)

                    # Update statistics
                    rule_type = rule.rule_type
                    if rule_type not in execution_stats["rule_stats"]:
                        execution_stats["rule_stats"][rule_type] = 0
                    execution_stats["rule_stats"][rule_type] += 1
                elif not result.success:
                    execution_stats["processing_errors"] += 1
                    logger.warning("⚠️ Rule {rule.rule_id} failed: %s", result.error)

            except Exception as e:
                execution_stats["processing_errors"] += 1
                logger.warning("⚠️ Rule {rule.rule_id} processing error: %s", e)

        return entry

    def _find_processor_for_rule(self, rule: GenericRule) -> RuleProcessor | None:
        """Find processor that can handle the rule.

        Args:
            rule: Rule to find processor for

        Returns:
            Compatible processor or None
        """
        for processor in self.processors:
            if processor.can_process(rule):
                return processor
        return None

    def validate_rules(self) -> Result[list[str]]:
        """Validate loaded rules and return issues.

        Returns:
            Result containing list of validation issues (empty if valid)
        """
        issues = []

        try:
            if not self.rules:
                issues.append("No rules loaded")
                return Result.ok(issues)

            # Check for duplicate rule IDs
            rule_ids = [rule.rule_id for rule in self.rules]
            duplicates = {rid for rid in rule_ids if rule_ids.count(rid) > 1}
            if duplicates:
                issues.append(f"Duplicate rule IDs found: {duplicates}")

            # Validate individual rules
            for rule in self.rules:
                rule_issues = self._validate_rule(rule)
                issues.extend(rule_issues)

            return Result.ok(issues)

        except Exception as e:
            return Result.fail(f"Rules validation failed: {e}")

    def _validate_rule(self, rule: GenericRule) -> list[str]:
        """Validate a single rule.

        Args:
            rule: Rule to validate

        Returns:
            List of validation issues for this rule
        """
        issues = []

        try:
            # Check if any processor can handle this rule
            processor = self._find_processor_for_rule(rule)
            if not processor:
                issues.append(
                    f"No processor found for rule {rule.rule_id} of type {rule.rule_type}",
                )

            # Validate rule structure
            if not rule.conditions and not rule.actions:
                issues.append(f"Rule {rule.rule_id} has no conditions or actions")

            # Additional validation can be added here

        except Exception as e:
            issues.append(f"Error validating rule {rule.rule_id}: {e}")

        return issues

    def get_execution_statistics(self) -> dict[str, Any]:
        """Get rule execution statistics.

        Returns:
            Dictionary with execution statistics
        """
        return self.execution_stats.copy()

    def get_rules_summary(self) -> dict[str, Any]:
        """Get summary of loaded rules.

        Returns:
            Dictionary with rules summary
        """
        rule_types = {}
        for rule in self.rules:
            rule_type = rule.rule_type
            if rule_type not in rule_types:
                rule_types[rule_type] = 0
            rule_types[rule_type] += 1

        return {
            "total_rules": len(self.rules),
            "rule_types": rule_types,
            "processors_registered": len(self.processors),
        }


class GenericRuleProcessor(ABC):
    """Base class for rule processors - NO business logic.

    Provides common functionality for rule processing without business-specific logic.
    """

    def __init__(self, supported_types: list[str]) -> None:
        """Initialize generic rule processor.

        Args:
            supported_types: List of rule types this processor can handle
        """
        self.supported_types = supported_types
        self.processing_stats: dict[str, Any] = {}

    def can_process(self, rule: GenericRule) -> bool:
        """Check if processor can handle this rule type.

        Args:
            rule: Rule to check

        Returns:
            True if processor can handle this rule type
        """
        return rule.rule_type in self.supported_types

    @abstractmethod
    def process_rule(
        self,
        rule: GenericRule,
        context: RuleExecutionContext,
    ) -> Result[dict[str, Any]]:
        """Process rule against context - MUST be implemented by subclasses.

        Args:
            rule: Rule to process
            context: Execution context

        Returns:
            Result with processed data or error
        """
        ...

    def get_processing_statistics(self) -> dict[str, Any]:
        """Get processing statistics.

        Returns:
            Dictionary with processing statistics
        """
        return self.processing_stats.copy()


def create_rules_engine() -> GenericRulesEngine:
    """Create a new generic rules engine instance.

    Returns:
        New GenericRulesEngine instance
    """
    return GenericRulesEngine()


def validate_rules_file(rules_file: Path) -> Result[dict[str, Any]]:
    """Validate rules file structure and content.

    Args:
        rules_file: Path to rules file to validate

    Returns:
        Result containing validation summary or error
    """
    try:
        if not rules_file.exists():
            return Result.fail(f"Rules file does not exist: {rules_file}")

        with open(rules_file, encoding="utf-8") as f:
            rules_data = json.load(f)

        # Basic structure validation
        if not isinstance(rules_data, dict):
            return Result.fail("Rules file must contain a JSON object")

        # Count rules in different sections
        total_rules = 0
        sections = []

        for section_name, section_data in rules_data.items():
            if isinstance(section_data, dict) and "rules" in section_data:
                section_rules = section_data["rules"]
                if isinstance(section_rules, list):
                    total_rules += len(section_rules)
                    sections.append(section_name)

        validation_summary = {
            "valid": True,
            "total_sections": len(sections),
            "sections": sections,
            "total_rules": total_rules,
            "file_size_bytes": rules_file.stat().st_size,
        }

        return Result.ok(validation_summary)

    except json.JSONDecodeError as e:
        return Result.fail(f"Invalid JSON in rules file: {e}")
    except Exception as e:
        return Result.fail(f"Rules file validation failed: {e}")


__all__ = [
    "GenericRule",
    "GenericRuleProcessor",
    "GenericRulesEngine",
    "RuleExecutionContext",
    "RuleProcessor",
    "create_rules_engine",
    "validate_rules_file",
]
