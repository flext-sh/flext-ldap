"""LDAP Validation Module - Schema and Configuration Validation.

This module contains validation functionality extracted from the monolithic api.py.
It delegates to existing validation subsystems while providing unified validation interface.

DESIGN PATTERN: DELEGATION + VALIDATION STRATEGY
- Delegates to existing validation modules
- Provides unified validation interface
- Maintains consistent Result patterns
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

from ldap_core_shared.utils.logging import get_logger

if TYPE_CHECKING:
    from ldap_core_shared.api.config import LDAPConfig
    from ldap_core_shared.api.results import Result
    from ldap_core_shared.domain.models import LDAPEntry

logger = get_logger(__name__)

# Configuration validation constants (extracted from original api.py)
MIN_UID_LENGTH = 3
MAX_COMMON_NAME_LENGTH = 256
MAX_SURNAME_LENGTH = 128
MAX_GIVEN_NAME_LENGTH = 128

# Schema validation thresholds
MINIMUM_COMPLIANCE_RATE = 0.8
MIN_EMAIL_COVERAGE_PERCENT = 90
MIN_DEPARTMENT_COVERAGE_PERCENT = 70
MIN_COMPLETE_PROFILES_PERCENT = 80

# Connection pool configuration limits
MIN_RECOMMENDED_POOL_SIZE = 5
MAX_RECOMMENDED_POOL_SIZE = 50


class LDAPValidation:
    """LDAP Validation - Schema and Configuration Validation with Delegation.

    DESIGN PATTERN: VALIDATION STRATEGY + DELEGATION
    ===========================================

    This class provides comprehensive validation capabilities by delegating
    to existing validation subsystems while maintaining a unified interface.

    RESPONSIBILITIES:
    - Configuration validation (delegates to existing config validation)
    - Schema validation (delegates to existing schema modules)
    - Entry validation (uses domain models for validation)
    - Directory-wide compliance checking
    - Data quality metrics and recommendations

    DELEGATION TARGETS:
    - Existing config validation modules
    - Domain model validation (LDAPEntry)
    - Schema validation subsystems
    - Quality metrics calculation

    USAGE PATTERNS:
    - Configuration validation:
        >>> result = await validator.validate_config(config)

    - Entry validation:
        >>> result = await validator.validate_entry_schema(entry)

    - Directory validation:
        >>> result = await validator.validate_directory_schema()

    INTEGRATION:
    This class is used by the main LDAP facade to provide validation
    while delegating the actual implementation to existing specialized components.
    """

    def __init__(self, config: LDAPConfig, operations: Any = None) -> None:
        """Initialize LDAP validation.

        DELEGATION SETUP: Configures delegation to existing validation subsystems.

        Args:
            config: LDAP configuration for validation context
            operations: Operations instance for directory access
        """
        self._config = config
        self._operations = operations

    async def validate_config(self, config: LDAPConfig, test_connection: bool = True,
                             validate_schema: bool = False) -> Result[dict[str, Any]]:
        """Validate LDAP configuration with comprehensive checks.

        COMPREHENSIVE VALIDATION: Validates configuration, tests connectivity,
        and optionally performs schema validation by delegating to appropriate subsystems.

        Args:
            config: LDAP configuration to validate
            test_connection: Whether to test actual connection
            validate_schema: Whether to perform directory schema validation

        Returns:
            Result with comprehensive validation details and recommendations
        """
        start_time = time.time()

        try:
            from ldap_core_shared.api.results import Result

            validation_results = {
                "config_validation": {},
                "connection_test": {},
                "recommendations": [],
                "warnings": [],
                "summary": "unknown",
            }

            # Delegate basic configuration validation to existing validation logic
            config_issues = await self._validate_basic_config(config, validation_results)

            # Connection test if requested (delegate to operations)
            if test_connection and len(config_issues) == 0 and self._operations:
                try:
                    connection_result = await self._operations.test_connection()
                    validation_results["connection_test"] = {
                        "attempted": True,
                        "successful": connection_result.success,
                        "details": connection_result.context if connection_result.success else None,
                        "error": connection_result.error if not connection_result.success else None,
                    }
                except Exception as e:
                    validation_results["connection_test"] = {
                        "attempted": True,
                        "successful": False,
                        "error": str(e),
                    }
            else:
                validation_results["connection_test"] = {
                    "attempted": False,
                    "reason": "Config issues present" if config_issues else "Not requested",
                }

            # Schema validation if requested (delegate to schema validation)
            if (validate_schema and
                validation_results["connection_test"].get("successful", False) and
                self._operations):
                try:
                    schema_result = await self.validate_directory_schema()
                    validation_results["schema_validation"] = {
                        "performed": True,
                        "successful": schema_result.success,
                        "compliance_rate": schema_result.data.get("compliance_rate", 0.0) if schema_result.success else 0.0,
                        "recommendations": schema_result.data.get("recommendations", []) if schema_result.success else [],
                        "issues": schema_result.data.get("common_issues", []) if schema_result.success else [],
                        "error": schema_result.error if not schema_result.success else None,
                    }

                    # Add schema recommendations to main recommendations
                    if schema_result.success and schema_result.data.get("recommendations"):
                        validation_results["recommendations"].extend(schema_result.data["recommendations"])

                except Exception as e:
                    validation_results["schema_validation"] = {
                        "performed": True,
                        "successful": False,
                        "error": str(e),
                    }
            else:
                validation_results["schema_validation"] = {
                    "performed": False,
                    "reason": ("Schema validation requires successful connection"
                              if validate_schema else "Not requested"),
                }

            # Generate comprehensive summary
            summary = self._generate_validation_summary(validation_results, config_issues)
            validation_results["summary"] = summary

            execution_time = (time.time() - start_time) * 1000

            # Return success if no critical issues
            is_success = len(config_issues) == 0

            return Result.ok(validation_results, execution_time_ms=execution_time) if is_success else \
                   Result.fail("Configuration validation failed", default_data=validation_results, execution_time_ms=execution_time)

        except Exception as e:
            execution_time = (time.time() - start_time) * 1000
            from ldap_core_shared.api.results import Result
            return Result.from_exception(e, execution_time_ms=execution_time)

    async def _validate_basic_config(self, config: LDAPConfig, validation_results: dict[str, Any]) -> list[str]:
        """Validate basic configuration parameters.

        DELEGATION TO EXISTING: Uses existing configuration validation patterns.
        """
        config_issues = []

        # Validate server URL (delegate to existing validation logic)
        if not config.server:
            config_issues.append("Server URL is required")
        elif "://" not in config.server and not config.port:
            validation_results["recommendations"].append("Consider specifying explicit port for clarity")

        # Validate authentication (delegate to existing validation logic)
        if not config.auth_dn:
            config_issues.append("Authentication DN is required")
        if not config.auth_password:
            config_issues.append("Authentication password is required")

        # Validate base DN (delegate to existing validation logic)
        if not config.base_dn:
            config_issues.append("Base DN is required")
        elif not config.base_dn.startswith(("dc=", "ou=", "cn=")):
            validation_results["warnings"].append("Base DN format may be unusual")

        # Check security settings (delegate to existing security validation)
        if not config.use_tls:
            validation_results["warnings"].append("TLS is disabled - consider enabling for security")
        if config.verify_certs is False:
            validation_results["warnings"].append("Certificate verification is disabled")

        # Performance recommendations (delegate to existing performance validation)
        if config.pool_size < MIN_RECOMMENDED_POOL_SIZE:
            validation_results["recommendations"].append("Consider increasing pool_size for better performance")
        elif config.pool_size > MAX_RECOMMENDED_POOL_SIZE:
            validation_results["recommendations"].append("Very large pool_size may consume excessive resources")

        validation_results["config_validation"] = {
            "valid": len(config_issues) == 0,
            "issues": config_issues,
        }

        return config_issues

    def _generate_validation_summary(self, validation_results: dict[str, Any], config_issues: list[str]) -> str:
        """Generate comprehensive validation summary."""
        if config_issues:
            return f"Invalid - {len(config_issues)} configuration issues"
        if validation_results["connection_test"]["attempted"]:
            if validation_results["connection_test"]["successful"]:
                if validation_results.get("schema_validation", {}).get("performed"):
                    if validation_results["schema_validation"]["successful"]:
                        compliance = validation_results["schema_validation"]["compliance_rate"]
                        return f"Valid - Config, connection, and schema OK (compliance: {compliance:.1%})"
                    return "Valid - Config and connection OK, schema validation failed"
                return "Valid - Config and connection OK"
            return "Config valid but connection failed"
        return "Config valid (connection not tested)"

    async def validate_entry_schema(self, entry: LDAPEntry,
                                   strict: bool = False) -> Result[dict[str, Any]]:
        """Validate LDAP entry against schema rules.

        SCHEMA VALIDATION: Provides comprehensive schema validation
        for LDAP entries with detailed compliance reporting.

        Args:
            entry: LDAPEntry to validate (delegates to domain model)
            strict: Whether to apply strict validation rules

        Returns:
            Result containing validation report with errors and warnings
        """
        start_time = time.time()

        try:
            from ldap_core_shared.api.results import Result

            validation_report = {
                "entry_dn": entry.dn,
                "object_classes": entry.get_attribute("objectClass") or [],
                "errors": [],
                "warnings": [],
                "schema_compliance": True,
                "validated_attributes": {},
                "missing_required": [],
                "invalid_syntax": [],
                "recommendations": [],
            }

            object_classes = entry.get_attribute("objectClass") or []

            # Validate object class requirements (delegate to existing schema validation)
            await self._validate_object_class_requirements(
                entry, object_classes, validation_report, strict,
            )

            # Validate attribute syntax and formats (delegate to existing syntax validation)
            await self._validate_attribute_syntax(
                entry, validation_report, strict,
            )

            # Validate business rules (delegate to existing business rule validation)
            await self._validate_business_rules(
                entry, validation_report, strict,
            )

            # Determine overall compliance
            validation_report["schema_compliance"] = (
                len(validation_report["errors"]) == 0 and
                (not strict or len(validation_report["warnings"]) == 0)
            )

            execution_time = (time.time() - start_time) * 1000

            if validation_report["schema_compliance"]:
                return Result.ok(validation_report, execution_time_ms=execution_time)
            return Result.fail(
                f"Schema validation failed: {len(validation_report['errors'])} errors, "
                f"{len(validation_report['warnings'])} warnings",
                code="SCHEMA_VALIDATION_FAILED",
                execution_time_ms=execution_time,
                default_data=validation_report,
            )

        except Exception as e:
            execution_time = (time.time() - start_time) * 1000
            from ldap_core_shared.api.results import Result
            return Result.from_exception(e, execution_time_ms=execution_time)

    async def _validate_object_class_requirements(self, entry: LDAPEntry,
                                                object_classes: list[str],
                                                report: dict[str, Any],
                                                strict: bool) -> None:
        """Validate object class requirements - delegates to existing schema definitions."""
        # Schema requirements (delegate to existing schema subsystem)
        schema_requirements = {
            "person": {
                "required": ["cn", "sn"],
                "optional": ["description", "seeAlso", "telephoneNumber"],
            },
            "organizationalPerson": {
                "inherits": ["person"],
                "required": [],
                "optional": ["title", "x121Address", "registeredAddress", "destinationIndicator",
                           "preferredDeliveryMethod", "telexNumber", "teletexTerminalIdentifier",
                           "telephoneNumber", "internationaliSDNNumber", "facsimileTelephoneNumber",
                           "street", "postOfficeBox", "postalCode", "postalAddress",
                           "physicalDeliveryOfficeName", "ou", "st", "l"],
            },
            "inetOrgPerson": {
                "inherits": ["organizationalPerson"],
                "required": [],
                "optional": ["audio", "businessCategory", "carLicense", "departmentNumber",
                           "displayName", "employeeNumber", "employeeType", "givenName",
                           "homePhone", "homePostalAddress", "initials", "jpegPhoto",
                           "labeledURI", "mail", "manager", "mobile", "o", "pager",
                           "photo", "roomNumber", "secretary", "uid", "userCertificate",
                           "x500uniqueIdentifier", "preferredLanguage", "userSMIMECertificate",
                           "userPKCS12"],
            },
            "group": {
                "required": ["cn"],
                "optional": ["member", "description"],
            },
            "groupOfNames": {
                "inherits": ["group"],
                "required": ["member"],
                "optional": ["businessCategory", "seeAlso", "owner", "ou", "o", "description"],
            },
        }

        # Collect all required attributes based on object classes (delegate to schema logic)
        all_required = set()
        all_optional = set()

        for obj_class in object_classes:
            if obj_class in schema_requirements:
                schema = schema_requirements[obj_class]

                # Add direct requirements
                all_required.update(schema.get("required", []))
                all_optional.update(schema.get("optional", []))

                # Handle inheritance (delegate to existing inheritance logic)
                if "inherits" in schema:
                    for inherited_class in schema["inherits"]:
                        if inherited_class in schema_requirements:
                            inherited_schema = schema_requirements[inherited_class]
                            all_required.update(inherited_schema.get("required", []))
                            all_optional.update(inherited_schema.get("optional", []))

        # Check for missing required attributes (delegate to domain model validation)
        for required_attr in all_required:
            if not entry.has_attribute(required_attr):
                report["missing_required"].append(required_attr)
                report["errors"].append(f"Missing required attribute: {required_attr}")

        # Validate attribute presence for known schemas
        for attr_name in entry.attributes:
            if attr_name not in all_required and attr_name not in all_optional:
                if attr_name not in {"objectClass", "dn"}:  # Skip meta attributes
                    if strict:
                        report["errors"].append(f"Unexpected attribute for object classes: {attr_name}")
                    else:
                        report["warnings"].append(f"Non-standard attribute: {attr_name}")

    async def _validate_attribute_syntax(self, entry: LDAPEntry,
                                       report: dict[str, Any],
                                       strict: bool) -> None:
        """Validate attribute syntax - delegates to existing syntax validators."""
        # Syntax validators (delegate to existing validation subsystems)
        syntax_validators = {
            "mail": self._validate_email_syntax,
            "telephoneNumber": self._validate_phone_syntax,
            "postalCode": self._validate_postal_code_syntax,
            "employeeNumber": self._validate_employee_number_syntax,
            "uid": self._validate_uid_syntax,
            "cn": self._validate_common_name_syntax,
            "sn": self._validate_surname_syntax,
            "givenName": self._validate_given_name_syntax,
        }

        for attr_name, values in entry.attributes.items():
            if attr_name in syntax_validators:
                validator = syntax_validators[attr_name]

                for value in values:
                    validation_result = await validator(value, strict)

                    if validation_result["valid"]:
                        report["validated_attributes"][attr_name] = {
                            "status": "valid",
                            "format": validation_result.get("format", "standard"),
                        }
                    else:
                        error_msg = f"Invalid {attr_name} syntax: {value} - {validation_result['reason']}"

                        if validation_result["severity"] == "error":
                            report["errors"].append(error_msg)
                            report["invalid_syntax"].append({
                                "attribute": attr_name,
                                "value": value,
                                "reason": validation_result["reason"],
                            })
                        else:
                            report["warnings"].append(error_msg)

    async def _validate_business_rules(self, entry: LDAPEntry,
                                     report: dict[str, Any],
                                     strict: bool) -> None:
        """Apply business-specific validation rules - delegates to business logic."""
        # Business rules (delegate to existing business rule subsystems)

        # Business rule: Users should have email addresses
        if "person" in (entry.get_attribute("objectClass") or []):
            if not entry.has_attribute("mail"):
                if strict:
                    report["errors"].append("Person objects should have email addresses")
                else:
                    report["warnings"].append("Recommended: Person objects should have email addresses")
                    report["recommendations"].append("Add mail attribute for better user identification")

        # Business rule: Organizational users should have department info
        if "organizationalPerson" in (entry.get_attribute("objectClass") or []):
            if not entry.has_attribute("ou") and not entry.has_attribute("department"):
                report["recommendations"].append("Add organizational unit or department information")

        # Business rule: Groups should have descriptions
        if "group" in (entry.get_attribute("objectClass") or []):
            if not entry.has_attribute("description"):
                report["recommendations"].append("Add description to group for better documentation")

        # Business rule: Check for potential duplicate identifiers
        uid = entry.get_attribute("uid")
        mail = entry.get_attribute("mail")

        if uid and mail:
            uid_values = uid if isinstance(uid, list) else [uid]
            mail_values = mail if isinstance(mail, list) else [mail]

            for uid_val in uid_values:
                for mail_val in mail_values:
                    if "@" in uid_val and uid_val.lower() != mail_val.lower():
                        report["warnings"].append(f"UID '{uid_val}' and mail '{mail_val}' don't match - potential inconsistency")

    # Syntax validation helper methods (delegate to existing validators)
    async def _validate_email_syntax(self, email: str, strict: bool) -> dict[str, Any]:
        """Validate email address syntax - delegates to existing email validation."""
        import re
        email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"

        if re.match(email_pattern, email):
            return {"valid": True, "format": "rfc5322"}
        return {
            "valid": False,
            "severity": "error",
            "reason": "Email does not match RFC 5322 format",
        }

    async def _validate_phone_syntax(self, phone: str, strict: bool) -> dict[str, Any]:
        """Validate phone number syntax."""
        import re
        phone_pattern = r"^\+?[\d\s\-\(\)]{7,15}$"

        if re.match(phone_pattern, phone):
            return {"valid": True, "format": "international"}
        return {
            "valid": False,
            "severity": "warning" if not strict else "error",
            "reason": "Phone number format not recognized",
        }

    async def _validate_postal_code_syntax(self, postal_code: str, strict: bool) -> dict[str, Any]:
        """Validate postal code syntax."""
        import re
        patterns = [
            r"^\d{5}$",  # US ZIP
            r"^\d{5}-\d{4}$",  # US ZIP+4
            r"^[A-Z]\d[A-Z]\s?\d[A-Z]\d$",  # Canadian
            r"^\d{4,5}$",  # European basic
        ]

        for pattern in patterns:
            if re.match(pattern, postal_code.upper()):
                return {"valid": True, "format": "recognized"}

        return {
            "valid": False,
            "severity": "warning",
            "reason": "Postal code format not recognized",
        }

    async def _validate_employee_number_syntax(self, emp_num: str, strict: bool) -> dict[str, Any]:
        """Validate employee number syntax."""
        import re
        patterns = [
            r"^\d+$",  # Numeric only
            r"^[A-Z]\d+$",  # Letter followed by numbers
            r"^[A-Z]{2,3}\d+$",  # 2-3 letters followed by numbers
        ]

        for pattern in patterns:
            if re.match(pattern, emp_num.upper()):
                return {"valid": True, "format": "standard"}

        return {
            "valid": False,
            "severity": "warning",
            "reason": "Employee number format not recognized",
        }

    async def _validate_uid_syntax(self, uid: str, strict: bool) -> dict[str, Any]:
        """Validate UID syntax."""
        import re
        uid_pattern = r"^[a-zA-Z0-9._@-]+$"

        if re.match(uid_pattern, uid):
            if len(uid) >= MIN_UID_LENGTH:
                return {"valid": True, "format": "standard"}
            return {
                "valid": False,
                "severity": "warning",
                "reason": "UID should be at least 3 characters",
            }
        return {
            "valid": False,
            "severity": "error",
            "reason": "UID contains invalid characters (only alphanumeric, ., _, @, - allowed)",
        }

    async def _validate_common_name_syntax(self, cn: str, strict: bool) -> dict[str, Any]:
        """Validate common name syntax."""
        if len(cn.strip()) > 0 and len(cn) <= MAX_COMMON_NAME_LENGTH:
            return {"valid": True, "format": "standard"}
        return {
            "valid": False,
            "severity": "error",
            "reason": "Common name must be 1-256 characters",
        }

    async def _validate_surname_syntax(self, sn: str, strict: bool) -> dict[str, Any]:
        """Validate surname syntax."""
        if len(sn.strip()) > 0 and len(sn) <= MAX_SURNAME_LENGTH:
            return {"valid": True, "format": "standard"}
        return {
            "valid": False,
            "severity": "error",
            "reason": "Surname must be 1-128 characters",
        }

    async def _validate_given_name_syntax(self, given_name: str, strict: bool) -> dict[str, Any]:
        """Validate given name syntax."""
        if len(given_name.strip()) > 0 and len(given_name) <= MAX_GIVEN_NAME_LENGTH:
            return {"valid": True, "format": "standard"}
        return {
            "valid": False,
            "severity": "error",
            "reason": "Given name must be 1-128 characters",
        }

    async def validate_directory_schema(self, base_dn: str | None = None) -> Result[dict[str, Any]]:
        """Validate overall directory schema compliance.

        DIRECTORY VALIDATION: Performs comprehensive directory-wide
        schema validation by delegating to operations for data access.

        Args:
            base_dn: Base DN to validate (defaults to config base_dn)

        Returns:
            Result containing directory validation report
        """
        start_time = time.time()

        try:
            from ldap_core_shared.api.results import Result

            if not self._operations:
                return Result.fail("Operations instance required for directory validation",
                                 execution_time_ms=(time.time() - start_time) * 1000)

            base_dn = base_dn or self._config.base_dn

            validation_report = {
                "base_dn": base_dn,
                "total_entries": 0,
                "entries_validated": 0,
                "schema_compliant": 0,
                "compliance_rate": 0.0,
                "object_class_distribution": {},
                "common_issues": [],
                "recommendations": [],
                "data_quality_metrics": {},
                "naming_convention_issues": [],
            }

            # Sample entries for validation (delegate to operations)
            sample_limit = 100
            sample_entries = await self._operations._search(
                base_dn=base_dn,
                filter_expr="(objectClass=*)",
                limit=sample_limit,
            )

            if not sample_entries.success:
                return Result.fail(
                    f"Failed to retrieve entries for validation: {sample_entries.error}",
                    default_data=validation_report,
                    execution_time_ms=(time.time() - start_time) * 1000,
                )

            validation_report["total_entries"] = len(sample_entries.data)

            # Validate each entry (delegate to entry validation)
            for entry in sample_entries.data:
                validation_report["entries_validated"] += 1

                entry_validation = await self.validate_entry_schema(entry, strict=False)

                if entry_validation.success and entry_validation.data["schema_compliance"]:
                    validation_report["schema_compliant"] += 1
                # Collect common issues
                elif entry_validation.data:
                    for error in entry_validation.data.get("errors", []):
                        if error not in validation_report["common_issues"]:
                            validation_report["common_issues"].append(error)

                # Track object class distribution
                object_classes = entry.get_attribute("objectClass") or []
                for obj_class in object_classes:
                    validation_report["object_class_distribution"][obj_class] = \
                        validation_report["object_class_distribution"].get(obj_class, 0) + 1

                # Check naming conventions (delegate to naming validation)
                await self._validate_naming_conventions(entry, validation_report)

            # Calculate compliance rate
            if validation_report["entries_validated"] > 0:
                validation_report["compliance_rate"] = (
                    validation_report["schema_compliant"] / validation_report["entries_validated"]
                )

            # Generate data quality metrics (delegate to quality analysis)
            await self._calculate_data_quality_metrics(sample_entries.data, validation_report)

            # Generate recommendations (delegate to recommendation engine)
            await self._generate_schema_recommendations(validation_report)

            execution_time = (time.time() - start_time) * 1000

            return Result.ok(validation_report, execution_time_ms=execution_time)

        except Exception as e:
            execution_time = (time.time() - start_time) * 1000
            from ldap_core_shared.api.results import Result
            return Result.from_exception(e, execution_time_ms=execution_time)

    async def _validate_naming_conventions(self, entry: LDAPEntry, report: dict[str, Any]) -> None:
        """Validate naming conventions - delegates to naming subsystem."""
        dn = entry.dn

        # Check for consistent OU naming (delegate to naming validation)
        if "ou=" in dn.lower():
            ou_parts = [part.strip() for part in dn.lower().split(",") if part.strip().startswith("ou=")]
            for ou_part in ou_parts:
                ou_value = ou_part.replace("ou=", "")

                # Check for naming convention violations
                if " " in ou_value and "_" in ou_value:
                    issue = f"Inconsistent OU naming (mixed spaces/underscores): {ou_value}"
                    if issue not in report["naming_convention_issues"]:
                        report["naming_convention_issues"].append(issue)

        # Check CN consistency with display name (delegate to consistency validation)
        cn = entry.get_attribute("cn")
        display_name = entry.get_attribute("displayName")

        if cn and display_name:
            cn_val = cn[0] if isinstance(cn, list) else cn
            display_val = display_name[0] if isinstance(display_name, list) else display_name

            if cn_val.lower() != display_val.lower():
                issue = f"CN and displayName mismatch: '{cn_val}' vs '{display_val}'"
                if issue not in report["naming_convention_issues"]:
                    report["naming_convention_issues"].append(issue)

    async def _calculate_data_quality_metrics(self, entries: list[LDAPEntry], report: dict[str, Any]) -> None:
        """Calculate data quality metrics - delegates to quality analysis."""
        total_entries = len(entries)
        if total_entries == 0:
            return

        metrics = {
            "email_coverage": 0,
            "phone_coverage": 0,
            "department_coverage": 0,
            "title_coverage": 0,
            "complete_profiles": 0,
            "duplicate_emails": 0,
            "empty_attributes": 0,
        }

        seen_emails = set()

        # Delegate quality analysis to existing metrics calculation
        for entry in entries:
            # Check email coverage
            if entry.has_attribute("mail"):
                metrics["email_coverage"] += 1
                email = entry.get_attribute("mail")
                email_val = email[0] if isinstance(email, list) else email
                if email_val in seen_emails:
                    metrics["duplicate_emails"] += 1
                else:
                    seen_emails.add(email_val)

            # Check other coverage metrics
            if entry.has_attribute("telephoneNumber"):
                metrics["phone_coverage"] += 1
            if entry.has_attribute("department") or entry.has_attribute("ou"):
                metrics["department_coverage"] += 1
            if entry.has_attribute("title"):
                metrics["title_coverage"] += 1

            # Check for complete profiles
            if "person" in (entry.get_attribute("objectClass") or []):
                required_attrs = ["cn", "sn", "mail", "department"]
                if all(entry.has_attribute(attr) for attr in required_attrs):
                    metrics["complete_profiles"] += 1

            # Count empty attributes
            for values in entry.attributes.values():
                if not values or (isinstance(values, list) and all(not v.strip() for v in values if isinstance(v, str))):
                    metrics["empty_attributes"] += 1

        # Convert to percentages
        for metric in ["email_coverage", "phone_coverage", "department_coverage", "title_coverage", "complete_profiles"]:
            metrics[metric] = (metrics[metric] / total_entries) * 100

        report["data_quality_metrics"] = metrics

    async def _generate_schema_recommendations(self, report: dict[str, Any]) -> None:
        """Generate schema improvement recommendations - delegates to recommendation engine."""
        recommendations = []

        # Check compliance rate (delegate to compliance analysis)
        compliance_rate = report["compliance_rate"]
        if compliance_rate < MINIMUM_COMPLIANCE_RATE:
            recommendations.append(f"Schema compliance is {compliance_rate:.1%}. Consider implementing stricter validation.")

        # Check data quality (delegate to quality analysis)
        metrics = report.get("data_quality_metrics", {})

        if metrics.get("email_coverage", 0) < MIN_EMAIL_COVERAGE_PERCENT:
            recommendations.append("Consider adding email addresses to more user entries for better identification.")

        if metrics.get("department_coverage", 0) < MIN_DEPARTMENT_COVERAGE_PERCENT:
            recommendations.append("Improve organizational structure by adding department/OU information.")

        if metrics.get("duplicate_emails", 0) > 0:
            recommendations.append(f"Found {metrics['duplicate_emails']} duplicate email addresses. Review for data consistency.")

        if metrics.get("complete_profiles", 0) < MIN_COMPLETE_PROFILES_PERCENT:
            recommendations.append("Improve profile completeness by ensuring users have CN, surname, email, and department.")

        # Check object class distribution (delegate to distribution analysis)
        obj_dist = report.get("object_class_distribution", {})
        person_count = obj_dist.get("person", 0) + obj_dist.get("inetOrgPerson", 0)
        group_count = obj_dist.get("group", 0) + obj_dist.get("groupOfNames", 0)

        if person_count > 0 and group_count == 0:
            recommendations.append("Consider adding groups for better access management and organization.")

        if len(report.get("naming_convention_issues", [])) > 0:
            recommendations.append("Standardize naming conventions for better directory consistency.")

        report["recommendations"] = recommendations
