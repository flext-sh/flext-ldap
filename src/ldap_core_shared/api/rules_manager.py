"""Generic rules management system for LDAP migration projects.

This module provides a generic rules management framework that can be extended
by specific migration projects to load and manage configuration-driven rules.
"""

from __future__ import annotations

import json
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional

from loguru import logger


@dataclass(frozen=True, slots=True)
class BaseRules:
    """Base class for rules configuration."""
    
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


@dataclass(frozen=True, slots=True)
class CategoryRule:
    """Generic categorization rule."""
    
    name: str
    filters: List[Dict[str, Any]] = field(default_factory=list)
    priority: int = 0
    enabled: bool = True


@dataclass(frozen=True, slots=True)
class TransformationRule:
    """Generic transformation rule."""
    
    name: str
    source_pattern: str
    target_pattern: str
    transformation_type: str = "simple"
    enabled: bool = True


class BaseRulesManager(ABC):
    """Abstract base class for rules management."""
    
    def __init__(self, rules_path: Optional[Path] = None) -> None:
        """Initialize rules manager."""
        self.rules_path = rules_path or Path("rules.json")
        self._raw_rules: Optional[Dict[str, Any]] = None
        self._cache_lock = threading.Lock()
        self._last_loaded: Optional[float] = None
    
    @property
    def raw_rules(self) -> Dict[str, Any]:
        """Get raw rules dictionary with caching."""
        if self._raw_rules is None or self._should_reload():
            with self._cache_lock:
                if self._raw_rules is None or self._should_reload():
                    self._load_rules()
        return self._raw_rules or {}
    
    def _should_reload(self) -> bool:
        """Check if rules should be reloaded."""
        if not self.rules_path.exists():
            return False
        
        if self._last_loaded is None:
            return True
        
        # Check if file was modified since last load
        file_mtime = self.rules_path.stat().st_mtime
        return file_mtime > self._last_loaded
    
    def _load_rules(self) -> None:
        """Load rules from file."""
        if not self.rules_path.exists():
            logger.warning(f"Rules file not found: {self.rules_path}")
            self._raw_rules = {}
            return
        
        try:
            with open(self.rules_path, "r", encoding="utf-8") as f:
                self._raw_rules = json.load(f)
            
            self._last_loaded = time.time()
            logger.info(f"✅ Loaded rules from {self.rules_path}")
            
        except Exception as e:
            logger.error(f"Failed to load rules from {self.rules_path}: {e}")
            self._raw_rules = {}
    
    @abstractmethod
    def get_categorization_rules(self) -> List[CategoryRule]:
        """Get categorization rules."""
        pass
    
    @abstractmethod
    def get_transformation_rules(self) -> List[TransformationRule]:
        """Get transformation rules."""
        pass
    
    def get_rule_section(self, section_name: str) -> Dict[str, Any]:
        """Get a specific rules section."""
        return self.raw_rules.get(section_name, {})
    
    def evaluate_category_filters(
        self,
        entry: Dict[str, Any],
        filters: List[Dict[str, Any]]
    ) -> bool:
        """Evaluate if entry matches category filters."""
        for filter_rule in filters:
            if self._evaluate_single_filter(entry, filter_rule):
                return True
        return False
    
    def _evaluate_single_filter(
        self,
        entry: Dict[str, Any],
        filter_rule: Dict[str, Any]
    ) -> bool:
        """Evaluate a single filter rule."""
        filter_type = filter_rule.get("type", "")
        filter_values = filter_rule.get("values", [])
        
        if filter_type == "objectclass":
            return self._check_objectclass_filter(entry, filter_values)
        elif filter_type == "dn_pattern":
            return self._check_dn_pattern_filter(entry, filter_values)
        elif filter_type == "attribute":
            attribute_name = filter_rule.get("attribute", "")
            return attribute_name in entry
        
        return False
    
    def _check_objectclass_filter(
        self,
        entry: Dict[str, Any],
        filter_values: List[str]
    ) -> bool:
        """Check objectClass filter."""
        object_classes = entry.get("objectClass", [])
        if isinstance(object_classes, str):
            object_classes = [object_classes]
        
        object_classes_lower = [oc.lower() for oc in object_classes]
        return any(value.lower() in object_classes_lower for value in filter_values)
    
    def _check_dn_pattern_filter(
        self,
        entry: Dict[str, Any],
        filter_values: List[str]
    ) -> bool:
        """Check DN pattern filter."""
        dn = entry.get("dn", "").lower()
        return any(pattern.lower() in dn for pattern in filter_values)
    
    def clear_cache(self) -> None:
        """Clear the rules cache."""
        with self._cache_lock:
            self._raw_rules = None
            self._last_loaded = None
    
    def reload_rules(self) -> None:
        """Force reload of rules."""
        self.clear_cache()
        # Trigger reload
        _ = self.raw_rules


class GenericRulesManager(BaseRulesManager):
    """Generic implementation of rules manager."""
    
    @lru_cache(maxsize=1)
    def get_categorization_rules(self) -> List[CategoryRule]:
        """Get categorization rules from configuration."""
        rules = []
        categorization_config = self.get_rule_section("categorization_rules")
        
        for category_name, category_config in categorization_config.items():
            if isinstance(category_config, dict):
                rule = CategoryRule(
                    name=category_name,
                    filters=category_config.get("filters", []),
                    priority=category_config.get("priority", 0),
                    enabled=category_config.get("enabled", True),
                )
                rules.append(rule)
        
        # Sort by priority
        return sorted(rules, key=lambda r: r.priority, reverse=True)
    
    @lru_cache(maxsize=1)
    def get_transformation_rules(self) -> List[TransformationRule]:
        """Get transformation rules from configuration."""
        rules = []
        transformation_config = self.get_rule_section("transformation_rules")
        
        for rule_name, rule_config in transformation_config.items():
            if isinstance(rule_config, dict):
                rule = TransformationRule(
                    name=rule_name,
                    source_pattern=rule_config.get("source_pattern", ""),
                    target_pattern=rule_config.get("target_pattern", ""),
                    transformation_type=rule_config.get("type", "simple"),
                    enabled=rule_config.get("enabled", True),
                )
                rules.append(rule)
        
        return rules
    
    def categorize_entry(self, entry: Dict[str, Any]) -> str:
        """Categorize an entry based on rules."""
        categorization_rules = self.get_categorization_rules()
        
        for rule in categorization_rules:
            if not rule.enabled:
                continue
                
            if self.evaluate_category_filters(entry, rule.filters):
                return rule.name
        
        return "uncategorized"
    
    def get_file_mapping(self) -> Dict[str, str]:
        """Get file mapping configuration."""
        return self.get_rule_section("file_mapping")
    
    def get_processing_config(self) -> Dict[str, Any]:
        """Get processing configuration."""
        return self.get_rule_section("processing_config")


def create_rules_manager(
    rules_path: Optional[Path] = None,
    manager_class: type = GenericRulesManager
) -> BaseRulesManager:
    """Create a rules manager instance.
    
    Args:
        rules_path: Path to rules configuration file
        manager_class: Rules manager class to instantiate
        
    Returns:
        Rules manager instance
    """
    return manager_class(rules_path)


def validate_rules_file(rules_path: Path) -> Dict[str, Any]:
    """Validate a rules configuration file.
    
    Args:
        rules_path: Path to rules file
        
    Returns:
        Validation results dictionary
        
    Raises:
        FileNotFoundError: If rules file doesn't exist
        ValueError: If rules file is invalid
    """
    if not rules_path.exists():
        raise FileNotFoundError(f"Rules file not found: {rules_path}")
    
    try:
        with open(rules_path, "r", encoding="utf-8") as f:
            rules_data = json.load(f)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in rules file: {e}") from e
    
    validation_results = {
        "valid": True,
        "warnings": [],
        "errors": [],
        "sections_found": list(rules_data.keys()),
    }
    
    # Check for required sections
    recommended_sections = [
        "metadata",
        "categorization_rules",
        "transformation_rules",
        "file_mapping",
    ]
    
    for section in recommended_sections:
        if section not in rules_data:
            validation_results["warnings"].append(f"Recommended section '{section}' not found")
    
    # Validate categorization rules
    if "categorization_rules" in rules_data:
        categorization_rules = rules_data["categorization_rules"]
        if not isinstance(categorization_rules, dict):
            validation_results["errors"].append("categorization_rules must be a dictionary")
        else:
            for rule_name, rule_config in categorization_rules.items():
                if not isinstance(rule_config, dict):
                    validation_results["errors"].append(
                        f"Categorization rule '{rule_name}' must be a dictionary"
                    )
                elif "filters" not in rule_config:
                    validation_results["warnings"].append(
                        f"Categorization rule '{rule_name}' has no filters"
                    )
    
    if validation_results["errors"]:
        validation_results["valid"] = False
    
    return validation_results