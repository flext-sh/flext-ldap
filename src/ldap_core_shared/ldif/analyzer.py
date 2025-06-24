"""LDIF Analyzer - Advanced LDIF content analysis and statistics.

This module provides comprehensive LDIF analysis capabilities including
content statistics, entry classification, and data quality assessment.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from ..domain.results import LDAPOperationResult
from .processor import LDIFEntry

logger = logging.getLogger(__name__)


class LDIFAnalysisResult(BaseModel):
    """Results from LDIF analysis operations."""
    
    model_config = ConfigDict(strict=True, extra="forbid")

    total_entries: int = Field(default=0, description="Total number of entries")
    object_class_distribution: dict[str, int] = Field(default_factory=dict, description="Distribution of object classes")
    attribute_distribution: dict[str, int] = Field(default_factory=dict, description="Distribution of attributes")
    dn_depth_distribution: dict[int, int] = Field(default_factory=dict, description="DN depth distribution")
    average_attributes_per_entry: float = Field(default=0.0, description="Average attributes per entry")
    largest_entry_dn: str = Field(default="", description="DN of entry with most attributes")
    smallest_entry_dn: str = Field(default="", description="DN of entry with least attributes")
    unique_attribute_names: set[str] = Field(default_factory=set, description="All unique attribute names")
    binary_attributes: set[str] = Field(default_factory=set, description="Attributes with binary content")
    data_quality_score: float = Field(default=0.0, ge=0.0, le=100.0, description="Overall data quality score")


class LDIFAnalyzer:
    """Advanced LDIF analyzer for content analysis and statistics."""

    def __init__(self) -> None:
        """Initialize LDIF analyzer."""
        pass

    def analyze_file(self, file_path: Path | str) -> LDAPOperationResult[LDIFAnalysisResult]:
        """Analyze complete LDIF file and return statistics.
        
        Args:
            file_path: Path to LDIF file to analyze
            
        Returns:
            Operation result with analysis statistics
        """
        try:
            from .processor import LDIFProcessor
            
            processor = LDIFProcessor()
            result = processor.parse_file(file_path)
            
            if not result.success:
                return LDAPOperationResult[LDIFAnalysisResult](
                    success=False,
                    error_message=f"Failed to parse LDIF: {result.error_message}",
                    operation="analyze_file"
                )
            
            analysis = self.analyze_entries(result.data or [])
            
            return LDAPOperationResult[LDIFAnalysisResult](
                success=True,
                data=analysis,
                operation="analyze_file",
                metadata={"file_path": str(file_path)}
            )
            
        except Exception as e:
            logger.exception(f"Failed to analyze LDIF file: {file_path}")
            return LDAPOperationResult[LDIFAnalysisResult](
                success=False,
                error_message=f"Analysis failed: {str(e)}",
                operation="analyze_file",
                metadata={"file_path": str(file_path)}
            )

    def analyze_entries(self, entries: list[LDIFEntry]) -> LDIFAnalysisResult:
        """Analyze list of LDIF entries and generate statistics.
        
        Args:
            entries: List of LDIF entries to analyze
            
        Returns:
            Analysis results with comprehensive statistics
        """
        if not entries:
            return LDIFAnalysisResult()
        
        # Initialize counters
        object_class_counts = defaultdict(int)
        attribute_counts = defaultdict(int)
        dn_depth_counts = defaultdict(int)
        unique_attributes = set()
        binary_attributes = set()
        
        total_attributes = 0
        max_attrs = 0
        min_attrs = float('inf')
        max_attrs_dn = ""
        min_attrs_dn = ""
        
        # Analyze each entry
        for entry in entries:
            # Count attributes in this entry
            entry_attr_count = sum(len(values) for values in entry.attributes.values())
            total_attributes += entry_attr_count
            
            # Track entries with most/least attributes
            if entry_attr_count > max_attrs:
                max_attrs = entry_attr_count
                max_attrs_dn = entry.dn
            if entry_attr_count < min_attrs:
                min_attrs = entry_attr_count
                min_attrs_dn = entry.dn
            
            # Analyze object classes
            for obj_class in entry.get_object_classes():
                object_class_counts[obj_class.lower()] += 1
            
            # Analyze attributes
            for attr_name, attr_values in entry.attributes.items():
                unique_attributes.add(attr_name.lower())
                attribute_counts[attr_name.lower()] += len(attr_values)
                
                # Check for binary content
                for value in attr_values:
                    if self._is_binary_content(value):
                        binary_attributes.add(attr_name.lower())
                        break
            
            # Analyze DN depth
            dn_depth = self._calculate_dn_depth(entry.dn)
            dn_depth_counts[dn_depth] += 1
        
        # Calculate statistics
        avg_attrs_per_entry = total_attributes / len(entries) if entries else 0
        data_quality_score = self._calculate_data_quality_score(entries, unique_attributes)
        
        return LDIFAnalysisResult(
            total_entries=len(entries),
            object_class_distribution=dict(object_class_counts),
            attribute_distribution=dict(attribute_counts),
            dn_depth_distribution=dict(dn_depth_counts),
            average_attributes_per_entry=avg_attrs_per_entry,
            largest_entry_dn=max_attrs_dn,
            smallest_entry_dn=min_attrs_dn if min_attrs != float('inf') else "",
            unique_attribute_names=unique_attributes,
            binary_attributes=binary_attributes,
            data_quality_score=data_quality_score
        )

    def generate_report(self, analysis: LDIFAnalysisResult) -> str:
        """Generate human-readable analysis report.
        
        Args:
            analysis: Analysis results to format
            
        Returns:
            Formatted analysis report
        """
        report = []
        report.append("LDIF Analysis Report")
        report.append("=" * 50)
        report.append("")
        
        # Basic statistics
        report.append(f"Total Entries: {analysis.total_entries:,}")
        report.append(f"Unique Attributes: {len(analysis.unique_attribute_names):,}")
        report.append(f"Average Attributes per Entry: {analysis.average_attributes_per_entry:.2f}")
        report.append(f"Data Quality Score: {analysis.data_quality_score:.1f}/100")
        report.append("")
        
        # Object class distribution
        if analysis.object_class_distribution:
            report.append("Top Object Classes:")
            sorted_ocs = sorted(
                analysis.object_class_distribution.items(),
                key=lambda x: x[1],
                reverse=True
            )
            for oc, count in sorted_ocs[:10]:
                percentage = (count / analysis.total_entries) * 100
                report.append(f"  {oc}: {count:,} entries ({percentage:.1f}%)")
            report.append("")
        
        # Attribute distribution
        if analysis.attribute_distribution:
            report.append("Top Attributes:")
            sorted_attrs = sorted(
                analysis.attribute_distribution.items(),
                key=lambda x: x[1],
                reverse=True
            )
            for attr, count in sorted_attrs[:10]:
                report.append(f"  {attr}: {count:,} values")
            report.append("")
        
        # DN depth distribution
        if analysis.dn_depth_distribution:
            report.append("DN Depth Distribution:")
            sorted_depths = sorted(analysis.dn_depth_distribution.items())
            for depth, count in sorted_depths:
                percentage = (count / analysis.total_entries) * 100
                report.append(f"  Depth {depth}: {count:,} entries ({percentage:.1f}%)")
            report.append("")
        
        # Binary attributes
        if analysis.binary_attributes:
            report.append("Binary Attributes:")
            for attr in sorted(analysis.binary_attributes):
                report.append(f"  {attr}")
            report.append("")
        
        # Extremes
        if analysis.largest_entry_dn:
            report.append(f"Entry with most attributes: {analysis.largest_entry_dn}")
        if analysis.smallest_entry_dn:
            report.append(f"Entry with least attributes: {analysis.smallest_entry_dn}")
        
        return "\n".join(report)

    def _calculate_dn_depth(self, dn: str) -> int:
        """Calculate the depth of a DN (number of RDN components)."""
        if not dn:
            return 0
        return len([rdn.strip() for rdn in dn.split(",") if rdn.strip()])

    def _is_binary_content(self, value: str) -> bool:
        """Check if attribute value contains binary content."""
        try:
            # Try to encode as ASCII - if it fails, likely binary
            value.encode("ascii")
            return False
        except UnicodeEncodeError:
            return True

    def _calculate_data_quality_score(self, entries: list[LDIFEntry], unique_attrs: set[str]) -> float:
        """Calculate overall data quality score based on various factors.
        
        Args:
            entries: List of entries to evaluate
            unique_attrs: Set of unique attribute names
            
        Returns:
            Quality score from 0.0 to 100.0
        """
        if not entries:
            return 0.0
        
        score = 100.0
        
        # Penalize for missing object classes
        entries_without_oc = sum(1 for entry in entries if not entry.get_object_classes())
        if entries_without_oc > 0:
            score -= (entries_without_oc / len(entries)) * 30
        
        # Penalize for very short or very long DNs
        dn_lengths = [len(entry.dn) for entry in entries]
        avg_dn_length = sum(dn_lengths) / len(dn_lengths)
        if avg_dn_length < 20:  # Very short DNs might indicate poor structure
            score -= 10
        elif avg_dn_length > 200:  # Very long DNs might indicate over-complexity
            score -= 10
        
        # Reward attribute diversity
        attr_diversity = len(unique_attrs) / len(entries) if entries else 0
        if attr_diversity > 5:  # Good attribute diversity
            score += min(5, attr_diversity - 5)
        elif attr_diversity < 2:  # Poor attribute diversity
            score -= 10
        
        return max(0.0, min(100.0, score)) 
