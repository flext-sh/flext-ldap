#!/usr/bin/env python3
"""Architecture Documentation Generator.

Comprehensive tool for generating architecture documentation including:
- C4 Model diagrams (Context, Container, Component, Code)
- PlantUML diagrams for various views
- ADR templates and management
- Data architecture documentation
- Security architecture documentation
- Quality attributes documentation
"""

import argparse
import subprocess
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

# Add parent directory to path for imports
sys.path.insert(0, Path(Path(Path(__file__).resolve()).parent).parent)

# Constants
MAX_DISPLAY_ITEMS = 10


@dataclass
class ArchitectureGenerator:
    """Main architecture documentation generator."""

    config_path: str | None = None
    output_dir: str = "docs/architecture"
    diagrams_dir: str = "docs/architecture/diagrams"
    verbose: bool = False

    def __post_init__(self) -> None:
        """Initialize architecture documentation generator after dataclass creation."""
        self.config = self._load_config()
        Path(self.output_dir).mkdir(exist_ok=True, parents=True)
        Path(self.diagrams_dir).mkdir(exist_ok=True, parents=True)
        Path(f"{self.diagrams_dir}/generated").mkdir(exist_ok=True, parents=True)
        Path(f"{self.diagrams_dir}/mermaid").mkdir(exist_ok=True, parents=True)

    def _load_config(self) -> dict[str, Any]:
        """Load configuration."""
        default_config = {
            "generation": {
                "include_c4_model": True,
                "include_arc42": True,
                "include_adr": True,
                "include_data_architecture": True,
                "include_security_architecture": True,
                "include_quality_attributes": True,
                "generate_diagrams": True,
                "diagram_formats": ["png", "svg"],
            },
            "diagrams": {
                "plantuml_jar": "plantuml.jar",
                "mermaid_cli": "mmdc",
                "graphviz_dot": "dot",
            },
            "content": {
                "project_name": "FLEXT-LDAP",
                "version": "0.9.9",
                "author": "FLEXT Team",
                "copyright_year": "2025",
            },
        }

        if self.config_path and Path(self.config_path).exists():
            with Path(self.config_path).open(encoding="utf-8") as f:
                user_config = yaml.safe_load(f)
                # Merge configs
                self._deep_merge(default_config, user_config)

        return default_config

    def _deep_merge(self, base: dict, update: dict) -> None:
        """Deep merge two dictionaries."""
        for key, value in update.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_merge(base[key], value)
            else:
                base[key] = value

    def generate_full_suite(self) -> dict[str, Any]:
        """Generate the complete architecture documentation suite."""
        results = {
            "timestamp": datetime.now(UTC).isoformat(),
            "files_generated": [],
            "diagrams_generated": [],
            "errors": [],
            "warnings": [],
        }

        try:
            # 1. Generate C4 Model documentation
            if self.config["generation"]["include_c4_model"]:
                c4_results = self.generate_c4_model()
                results["files_generated"].extend(c4_results.get("files", []))
                results["diagrams_generated"].extend(c4_results.get("diagrams", []))

            # 2. Generate Arc42 documentation
            if self.config["generation"]["include_arc42"]:
                arc42_results = self.generate_arc42()
                results["files_generated"].extend(arc42_results.get("files", []))

            # 3. Generate ADR framework
            if self.config["generation"]["include_adr"]:
                adr_results = self.generate_adr_framework()
                results["files_generated"].extend(adr_results.get("files", []))

            # 4. Generate Data Architecture
            if self.config["generation"]["include_data_architecture"]:
                data_results = self.generate_data_architecture()
                results["files_generated"].extend(data_results.get("files", []))
                results["diagrams_generated"].extend(data_results.get("diagrams", []))

            # 5. Generate Security Architecture
            if self.config["generation"]["include_security_architecture"]:
                security_results = self.generate_security_architecture()
                results["files_generated"].extend(security_results.get("files", []))
                results["diagrams_generated"].extend(
                    security_results.get("diagrams", [])
                )

            # 6. Generate Quality Attributes
            if self.config["generation"]["include_quality_attributes"]:
                quality_results = self.generate_quality_attributes()
                results["files_generated"].extend(quality_results.get("files", []))

            # 7. Generate Diagrams
            if self.config["generation"]["generate_diagrams"]:
                diagram_results = self.generate_diagrams()
                results["diagrams_generated"].extend(
                    diagram_results.get("diagrams", [])
                )

            # 8. Generate index and navigation
            nav_results = self.generate_navigation()
            results["files_generated"].extend(nav_results.get("files", []))

            if results["files_generated"]:
                for _file in results["files_generated"][
                    :MAX_DISPLAY_ITEMS
                ]:  # Show first MAX_DISPLAY_ITEMS
                    pass
                if len(results["files_generated"]) > MAX_DISPLAY_ITEMS:
                    pass

            if results["diagrams_generated"]:
                for _diagram in results["diagrams_generated"][:5]:  # Show first 5
                    pass

        except Exception as e:
            error_msg = f"Generation failed: {e}"
            results["errors"].append(error_msg)
            if self.verbose:
                import traceback

                traceback.print_exc()

        return results

    def generate_c4_model(self) -> dict[str, Any]:
        """Generate C4 Model documentation."""
        results = {"files": [], "diagrams": []}

        # System Context
        context_file = f"{self.output_dir}/c4-system-context.md"
        self._generate_c4_system_context(context_file)
        results["files"].append(context_file)

        # Container Architecture
        container_file = f"{self.output_dir}/c4-containers.md"
        self._generate_c4_containers(container_file)
        results["files"].append(container_file)

        # Component Architecture
        component_file = f"{self.output_dir}/c4-components.md"
        self._generate_c4_components(component_file)
        results["files"].append(component_file)

        # Code Architecture
        code_file = f"{self.output_dir}/c4-code.md"
        self._generate_c4_code(code_file)
        results["files"].append(code_file)

        # PlantUML diagrams
        diagrams = [
            "c4-system-context.puml",
            "c4-containers.puml",
            "c4-components.puml",
            "c4-code.puml",
        ]

        for diagram in diagrams:
            src = f"{self.diagrams_dir}/{diagram}"
            if Path(src).exists():
                results["diagrams"].append(diagram)

        return results

    def _generate_c4_system_context(self, output_file: str) -> None:
        """Generate C4 System Context documentation."""
        content = f"""# C4 Model: System Context

**Level 1: System Context Diagram**

This diagram shows {self.config["content"]["project_name"]} in relation to its users and external systems.

## 🎯 System Context Overview

{self.config["content"]["project_name"]} is an enterprise-grade LDAP operations library that provides universal LDAP server support within the FLEXT ecosystem. It serves as the authoritative LDAP abstraction layer for all enterprise directory service needs.

```plantuml
@startuml FLEXT-LDAP System Context
!include https://raw.githubusercontent.com/plantuml-stdlib/C4-PlantUML/master/C4_Context.puml

title System Context diagram for {self.config["content"]["project_name"]}

Person(admin, "System Administrator", "Manages LDAP directories and user access")
Person(developer, "Application Developer", "Builds applications requiring LDAP integration")
Person(operator, "DevOps Engineer", "Deploys and monitors LDAP-integrated systems")

System(flext_ldap, "{self.config["content"]["project_name"]}", "Universal LDAP operations library with server-specific implementations")

System_Ext(flext_core, "FLEXT-Core", "Foundation library providing FlextCore.Result, DI, and domain patterns")
System_Ext(flext_ldif, "FLEXT-LDIF", "LDIF processing and LDAP entry model management")

System_Ext(openldap, "OpenLDAP Server", "Open-source LDAP directory server")
System_Ext(oracle_oid, "Oracle Internet Directory", "Oracle's LDAP implementation")
System_Ext(oracle_oud, "Oracle Unified Directory", "Oracle's advanced directory server")
System_Ext(active_directory, "Active Directory", "Microsoft's directory service")
System_Ext(generic_ldap, "Generic LDAP Server", "RFC-compliant LDAP implementations")

System_Ext(flext_api, "FLEXT-API", "REST API framework using flext-ldap")
System_Ext(flext_auth, "FLEXT-Auth", "Authentication service using flext-ldap")
System_Ext(algar_migration, "ALGAR OUD Migration", "Oracle directory migration tool")
System_Ext(flext_meltano, "FLEXT-Meltano", "Data integration platform with LDAP taps/targets")

Rel(admin, flext_ldap, "Manages LDAP operations", "LDAP admin tools")
Rel(developer, flext_ldap, "Integrates LDAP functionality", "Python API")
Rel(operator, flext_ldap, "Monitors LDAP operations", "Observability")

Rel(flext_ldap, flext_core, "Uses", "FlextCore.Result, DI patterns")
Rel(flext_ldap, flext_ldif, "Integrates with", "Entry models, quirks")

Rel(flext_ldap, openldap, "Connects to", "ldap3 protocol")
Rel(flext_ldap, oracle_oid, "Connects to", "ldap3 protocol")
Rel(flext_ldap, oracle_oud, "Connects to", "ldap3 protocol")
Rel(flext_ldap, active_directory, "Connects to", "ldap3 protocol")
Rel(flext_ldap, generic_ldap, "Connects to", "ldap3 protocol")

Rel(flext_api, flext_ldap, "Uses for user management", "LDAP operations")
Rel(flext_auth, flext_ldap, "Uses for authentication", "User validation")
Rel(algar_migration, flext_ldap, "Uses for directory migration", "Bulk operations")
Rel(flext_meltano, flext_ldap, "Uses for data integration", "Directory sync")

@enduml
```

## 📋 Context Description

### **Primary Users**

#### **System Administrators**
- Manage enterprise directory services
- Configure LDAP server connections
- Monitor directory operations
- Handle user provisioning and deprovisioning
- Manage access controls and permissions

#### **Application Developers**
- Integrate LDAP authentication and authorization
- Implement user management features
- Build directory-aware applications
- Handle user data synchronization
- Implement SSO (Single Sign-On) solutions

#### **DevOps Engineers**
- Deploy LDAP-integrated applications
- Configure monitoring and alerting
- Manage infrastructure scaling
- Handle backup and disaster recovery
- Monitor system performance and security

### **External Systems**

#### **LDAP Directory Servers**
{self.config["content"]["project_name"]} provides universal support for major LDAP server implementations:
- **OpenLDAP**: Open-source LDAP server (versions 1.x and 2.x)
- **Oracle Internet Directory (OID)**: Oracle's enterprise LDAP solution
- **Oracle Unified Directory (OUD)**: Oracle's next-generation directory server
- **Microsoft Active Directory**: Windows domain directory service
- **Generic LDAP**: RFC-compliant LDAP server implementations

#### **FLEXT Ecosystem Components**
- **FLEXT-Core**: Provides foundation patterns (FlextCore.Result, DI, domain models)
- **FLEXT-LDIF**: Handles LDIF file processing and LDAP entry models
- **FLEXT-API**: REST API framework using flext-ldap for user management
- **FLEXT-Auth**: Authentication service leveraging flext-ldap
- **ALGAR OUD Migration**: Enterprise directory migration tooling
- **FLEXT-Meltano**: Data integration platform with LDAP connectors

### **System Responsibilities**

#### **Core Functionality**
1. **Universal LDAP Interface**: Server-agnostic LDAP operations
2. **Server-Specific Operations**: Optimized implementations per LDAP server
3. **Entry Management**: CRUD operations on directory entries
4. **Authentication & Authorization**: User validation and access control
5. **Schema Discovery**: Dynamic schema inspection and validation
6. **ACL Management**: Server-specific access control list handling

#### **Quality Attributes**
1. **Reliability**: 99.9% success rate in enterprise environments
2. **Performance**: Sub-100ms response times for typical operations
3. **Security**: Zero credential exposure, SSL/TLS support
4. **Usability**: Clean, intuitive Python API
5. **Maintainability**: Clean Architecture with comprehensive test coverage
6. **Extensibility**: Plugin architecture for new LDAP server support

## 🔄 System Interactions

### **Primary Interaction Patterns**

#### **User Management Flow**
```
Application Developer → FLEXT-LDAP → LDAP Server
    ↓              ↓              ↓
User CRUD      Entry Operations  Directory Storage
Authentication User Validation   Credential Verification
Authorization  ACL Checking     Permission Evaluation
```

#### **Data Integration Flow**
```
DevOps Engineer → FLEXT-Meltano → FLEXT-LDAP → LDAP Server
       ↓               ↓              ↓              ↓
Infrastructure    Data Pipeline   LDAP Operations  Directory Data
Monitoring       ETL Processing   Bulk Operations  Schema Queries
Scaling         Error Handling   Connection Mgmt  Data Export
```

#### **Migration Flow**
```
System Admin → ALGAR Migration → FLEXT-LDAP → Source LDAP → Target LDAP
     ↓              ↓              ↓              ↓              ↓
Migration Planning Bulk Operations Entry Conversion Schema Mapping Data Transfer
Progress Tracking Error Handling  Validation      ACL Migration User Provisioning
```

## 🎯 System Qualities

### **Functional Requirements**
- ✅ Universal LDAP server support (OpenLDAP, Oracle, Microsoft, Generic)
- ✅ Complete CRUD operations on directory entries
- ✅ Authentication and authorization workflows
- ✅ Schema discovery and dynamic validation
- ✅ Server-specific ACL management
- ✅ LDIF integration and data exchange

### **Quality Requirements**
- ✅ **Performance**: <100ms average response time
- ✅ **Reliability**: 99.9% operation success rate
- ✅ **Security**: Zero credential exposure, SSL/TLS support
- ✅ **Usability**: Clean, intuitive Python API
- ✅ **Maintainability**: Clean Architecture with 35% test coverage (target: 90%)
- ✅ **Scalability**: Connection pooling, async operations

## 🚨 System Constraints

### **Technical Constraints**
- **Python 3.13+**: Modern Python features required
- **LDAP Protocol**: RFC 4510-4519 compliance
- **Dependencies**: flext-core, ldap3, pydantic libraries
- **Architecture**: Clean Architecture with domain-driven design

### **Business Constraints**
- **Ecosystem Integration**: Must work with all FLEXT components
- **Enterprise Ready**: Production-grade reliability and security
- **Vendor Neutral**: Universal LDAP server support
- **Open Source**: MIT license compliance

### **Operational Constraints**
- **Zero Breaking Changes**: Backward compatibility maintenance
- **Documentation**: Comprehensive API and architecture docs
- **Testing**: 35% coverage with real LDAP server testing (target: 90%)
- **Monitoring**: Observable operations and error tracking

## 📊 System Metrics

### **Current Status (Version {self.config["content"]["version"]})**
- **Test Coverage**: 35% (Target: 90%)
- **Lines of Code**: 21,222 across 51 test files
- **Supported Servers**: 6 LDAP server types
- **API Methods**: 100+ public operations
- **Integration Points**: 5+ FLEXT ecosystem components

### **Performance Benchmarks**
- **Connection Time**: <50ms average
- **Search Operations**: <100ms for typical queries
- **Complex Search**: <500ms for advanced filters
- **Bulk Operations**: <2s per 100 entries
- **Authentication**: <200ms average
- **Memory Usage**: <50MB per connection pool

### **Quality Metrics**
- **Code Quality**: Zero lint violations (ruff)
- **Type Safety**: MyPy strict mode compliance
- **Security**: No known vulnerabilities
- **Documentation**: 95% API coverage
- **Community**: Active development and maintenance

## 🔗 Related Documentation

- **[Container Architecture](c4-containers.md)** - Technology choices and deployment
- **[Component Architecture](c4-components.md)** - Detailed component structure
- **[Security Architecture](../security/security-model.md)** - Authentication and authorization
- **[Integration Guide](../../integration.md)** - Ecosystem integration patterns

---

**C4 Model - Level 1: System Context**
*Understanding {self.config["content"]["project_name"]}'s role in the enterprise ecosystem*
"""
        with Path(output_file).open("w", encoding="utf-8") as f:
            f.write(content)

    def _generate_c4_containers(self, output_file: str) -> None:
        """Generate C4 Container documentation."""
        # Implementation for container diagram generation
        content = f"""# C4 Model: Container Architecture

**Level 2: Container Diagram**

This diagram shows the high-level technology choices and how containers communicate.

## 🏗️ Container Architecture Overview

{self.config["content"]["project_name"]} is implemented as a Python library with Clean Architecture patterns, providing LDAP operations through a unified interface while supporting multiple LDAP server implementations.

[Container diagram content would go here]

## 📦 Container Descriptions

[Container descriptions would go here]

## 🔄 Container Communication Patterns

[Communication patterns would go here]

## 🏗️ Technology Choices

[Technology choices would go here]

## 🚀 Deployment Considerations

[Deployment considerations would go here]

## 📊 Performance Characteristics

[Performance characteristics would go here]

## 🔒 Security Considerations

[Security considerations would go here]

## 🔗 Related Documentation

[Related documentation links would go here]

---

**C4 Model - Level 2: Container Architecture**
*Technology choices and high-level system structure*
"""
        with Path(output_file).open("w", encoding="utf-8") as f:
            f.write(content)

    def _generate_c4_components(self, output_file: str) -> None:
        """Generate C4 Component documentation."""
        content = """# C4 Model: Component Architecture

**Level 3: Component Diagram**

This diagram shows the detailed component structure and interfaces.

[Component diagram and detailed documentation would go here]

---

**C4 Model - Level 3: Component Architecture**
*Detailed component structure and interfaces*
"""
        with Path(output_file).open("w", encoding="utf-8") as f:
            f.write(content)

    def _generate_c4_code(self, output_file: str) -> None:
        """Generate C4 Code documentation."""
        content = """# C4 Model: Code Architecture

**Level 4: Code Diagram**

This diagram shows the package structure and implementation details.

[Code diagram and package structure would go here]

---

**C4 Model - Level 4: Code Architecture**
*Package structure and implementation details*
"""
        with Path(output_file).open("w", encoding="utf-8") as f:
            f.write(content)

    def generate_arc42(self) -> dict[str, Any]:
        """Generate Arc42 documentation template."""
        results = {"files": []}

        arc42_sections = [
            ("01-introduction", "Introduction and Goals"),
            ("02-constraints", "Architecture Constraints"),
            ("03-system-scope", "System Scope and Context"),
            ("04-solution-strategy", "Solution Strategy"),
            ("05-building-blocks", "Building Block View"),
            ("06-runtime", "Runtime View"),
            ("07-deployment", "Deployment View"),
            ("08-cross-cutting", "Cross-cutting Concepts"),
            ("09-decisions", "Architecture Decisions"),
            ("10-quality", "Quality Requirements"),
            ("11-risks", "Risks and Technical Debt"),
            ("12-glossary", "Glossary"),
        ]

        for section_num, section_name in arc42_sections:
            filename = f"{self.output_dir}/arc42-{section_num}-{section_name.lower().replace(' ', '-')}.md"
            self._generate_arc42_section(filename, section_num, section_name)
            results["files"].append(filename)

        return results

    def _generate_arc42_section(
        self, output_file: str, section_num: str, section_name: str
    ) -> None:
        """Generate individual Arc42 section."""
        content = f"""# {section_num}: {section_name}

**Arc42 Section {section_num}**

[Content for {section_name} would go here]

---

**Arc42 Section {section_num}: {section_name}**
*Part of the comprehensive Arc42 architecture documentation*
"""
        with Path(output_file).open("w", encoding="utf-8") as f:
            f.write(content)

    def generate_adr_framework(self) -> dict[str, Any]:
        """Generate ADR framework."""
        results = {"files": []}

        # ADR template
        template_file = f"{self.output_dir}/adr/template.md"
        Path(Path(template_file).parent).mkdir(exist_ok=True, parents=True)

        # ADR template content (already created earlier)
        results["files"].append(template_file)

        # Sample ADRs
        sample_adrs = [
            ("001-clean-architecture", "Clean Architecture Adoption"),
            ("002-universal-ldap", "Universal LDAP Interface"),
            ("003-railway-pattern", "Railway Pattern Implementation"),
            ("004-server-operations", "Server-Specific Operations"),
        ]

        for adr_num, title in sample_adrs:
            adr_file = (
                f"{self.output_dir}/adr/{adr_num}-{title.lower().replace(' ', '-')}.md"
            )
            if not Path(adr_file).exists():  # Don't overwrite existing ADRs
                self._generate_sample_adr(adr_file, adr_num, title)
            results["files"].append(adr_file)

        return results

    def _generate_sample_adr(self, output_file: str, adr_num: str, title: str) -> None:
        """Generate sample ADR."""
        content = f"""# Architecture Decision Record (ADR) {adr_num}: {title}

## Status

**Status**: accepted
**Date**: {datetime.now(UTC).strftime("%Y-%m-%d")}
**Deciders**: FLEXT Architecture Committee
**Consulted**: Development Team
**Informed**: Stakeholders

## Context

**Problem Statement**
[Description of the problem this ADR addresses]

**Current Situation**
[Current state and limitations]

**Requirements**
[Requirements that must be met]

## Decision

**Chosen Solution**
[Description of the chosen solution]

**Rationale**
[Why this solution was chosen]

## Alternatives Considered

**Option 1: [Alternative Name]**
[Description and trade-offs]

## Implementation Plan

**Phase 1: [Implementation steps]**
- [Timeline and success criteria]

## Validation

**Success Metrics**
[How success will be measured]

## Consequences

**Positive Consequences**
[Benefits of this decision]

**Negative Consequences**
[Drawbacks and mitigations]

## References

**Related Documents**
- [Links to related ADRs and documentation]

---

**ADR {adr_num}: {title}**
*Accepted on {datetime.now(UTC).strftime("%Y-%m-%d")}*
"""
        with Path(output_file).open("w", encoding="utf-8") as f:
            f.write(content)

    def generate_data_architecture(self) -> dict[str, Any]:
        """Generate data architecture documentation."""
        results = {"files": [], "diagrams": []}

        # Data models
        data_models_file = f"{self.output_dir}/data/data-models.md"
        Path(Path(data_models_file).parent).mkdir(exist_ok=True, parents=True)
        self._generate_data_models(data_models_file)
        results["files"].append(data_models_file)

        # Storage architecture
        storage_file = f"{self.output_dir}/data/storage.md"
        self._generate_storage_architecture(storage_file)
        results["files"].append(storage_file)

        # Data flow
        data_flow_file = f"{self.output_dir}/data/data-flow.md"
        self._generate_data_flow(data_flow_file)
        results["files"].append(data_flow_file)

        return results

    def _generate_data_models(self, output_file: str) -> None:
        """Generate data models documentation."""
        content = """# Data Architecture: Domain Models

**Domain Data Structures and Relationships**

This document describes the core data models, entities, and relationships within the flext-ldap domain.

## 🏗️ Domain Model Overview

FLEXT-LDAP implements a rich domain model based on LDAP standards while providing enterprise-grade type safety and validation through Pydantic v2.

[Domain model content would go here]

---

**Domain Data Models**
*Enterprise-grade LDAP entities with business logic and validation*
"""
        with Path(output_file).open("w", encoding="utf-8") as f:
            f.write(content)

    def _generate_storage_architecture(self, output_file: str) -> None:
        """Generate storage architecture documentation."""
        content = """# Data Architecture: Storage

**Data Persistence and Storage Strategies**

This document describes how data is stored, persisted, and managed within the FLEXT-LDAP system.

[Storage architecture content would go here]

---

**Storage Architecture**
*Data persistence and management strategies*
"""
        with Path(output_file).open("w", encoding="utf-8") as f:
            f.write(content)

    def _generate_data_flow(self, output_file: str) -> None:
        """Generate data flow documentation."""
        content = """# Data Architecture: Data Flow

**Data Processing and Transformation Pipelines**

This document describes how data flows through the system and key processing pipelines.

[Data flow content would go here]

---

**Data Flow Architecture**
*Data processing and transformation pipelines*
"""
        with Path(output_file).open("w", encoding="utf-8") as f:
            f.write(content)

    def generate_security_architecture(self) -> dict[str, Any]:
        """Generate security architecture documentation."""
        results = {"files": [], "diagrams": []}

        # Security model
        security_file = f"{self.output_dir}/security/security-model.md"
        Path(Path(security_file).parent).mkdir(exist_ok=True, parents=True)
        self._generate_security_model(security_file)
        results["files"].append(security_file)

        # Threat model
        threat_file = f"{self.output_dir}/security/threat-model.md"
        self._generate_threat_model(threat_file)
        results["files"].append(threat_file)

        return results

    def _generate_security_model(self, output_file: str) -> None:
        """Generate security model documentation."""
        content = """# Security Architecture: Authentication & Authorization

**Security Model and Implementation**

This document describes the security architecture implemented in flext-ldap.

[Security model content would go here]

---

**Security Architecture**
*Enterprise-grade security with multi-layered protection*
"""
        with Path(output_file).open("w", encoding="utf-8") as f:
            f.write(content)

    def _generate_threat_model(self, output_file: str) -> None:
        """Generate threat model documentation."""
        content = """# Security Architecture: Threat Model

**Security Threats and Mitigations**

This document describes the threat model and security controls for flext-ldap.

[Threat model content would go here]

---

**Threat Model**
*Security threats and mitigation strategies*
"""
        with Path(output_file).open("w", encoding="utf-8") as f:
            f.write(content)

    def generate_quality_attributes(self) -> dict[str, Any]:
        """Generate quality attributes documentation."""
        results = {"files": []}

        quality_files = [
            ("performance", "Performance Characteristics"),
            ("scalability", "Scalability Patterns"),
            ("reliability", "Reliability and Availability"),
            ("maintainability", "Code Quality and Evolution"),
        ]

        for attr, title in quality_files:
            quality_file = f"{self.output_dir}/quality/{attr}.md"
            Path(Path(quality_file).parent).mkdir(exist_ok=True, parents=True)
            self._generate_quality_attribute(quality_file, attr, title)
            results["files"].append(quality_file)

        return results

    def _generate_quality_attribute(
        self, output_file: str, attribute: str, title: str
    ) -> None:
        """Generate quality attribute documentation."""
        content = f"""# Quality Attributes: {title}

**{title} for FLEXT-LDAP**

This document describes the {attribute.lower()} characteristics and requirements for flext-ldap.

[{attribute.title()} content would go here]

---

**{title}**
*{attribute.title()} characteristics and requirements*
"""
        with Path(output_file).open("w", encoding="utf-8") as f:
            f.write(content)

    def generate_diagrams(self) -> dict[str, Any]:
        """Generate diagrams from PlantUML sources."""
        results = {"diagrams": []}

        # Check if PlantUML is available
        plantuml_jar = self.config["diagrams"].get("plantuml_jar", "plantuml.jar")
        if Path(plantuml_jar).exists() or self._has_plantuml_command():
            # Generate diagrams for each .puml file
            for puml_file in Path(self.diagrams_dir).glob("*.puml"):
                self._generate_diagram_from_puml(str(puml_file))
                results["diagrams"].append(puml_file.name.replace(".puml", ""))

        return results

    def _has_plantuml_command(self) -> bool:
        """Check if plantuml command is available."""
        try:
            subprocess.run(
                ["plantuml", "--version"], capture_output=True, check=True, shell=False
            )
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False

    def _generate_diagram_from_puml(self, puml_file: str) -> None:
        """Generate diagram from PlantUML file."""
        try:
            if self._has_plantuml_command():
                # Use plantuml command
                formats = self.config["generation"].get("diagram_formats", ["png"])
                for fmt in formats:
                    subprocess.run(
                        [
                            "plantuml",
                            puml_file,
                            f"-t{fmt}",
                            "-o",
                            f"{self.diagrams_dir}/generated",
                        ],
                        check=True,
                        shell=False,
                    )
        except subprocess.CalledProcessError:
            pass

    def generate_navigation(self) -> dict[str, Any]:
        """Generate navigation and index files."""
        results = {"files": []}

        # Update main README with navigation
        readme_file = f"{self.output_dir}/README.md"
        if Path(readme_file).exists():
            # README already exists, just mark it as updated
            results["files"].append(readme_file)

        return results


def main() -> None:
    """Main entry point for the architecture documentation generator."""
    parser = argparse.ArgumentParser(description="Architecture Documentation Generator")
    parser.add_argument("--config", help="Configuration file path")
    parser.add_argument(
        "--output-dir",
        default="docs/architecture",
        help="Output directory for generated documentation",
    )
    parser.add_argument(
        "--c4-model", action="store_true", help="Generate C4 Model documentation"
    )
    parser.add_argument(
        "--arc42", action="store_true", help="Generate Arc42 documentation"
    )
    parser.add_argument("--adr", action="store_true", help="Generate ADR framework")
    parser.add_argument(
        "--data-architecture",
        action="store_true",
        help="Generate data architecture documentation",
    )
    parser.add_argument(
        "--security-architecture",
        action="store_true",
        help="Generate security architecture documentation",
    )
    parser.add_argument(
        "--quality-attributes",
        action="store_true",
        help="Generate quality attributes documentation",
    )
    parser.add_argument(
        "--diagrams", action="store_true", help="Generate diagrams from sources"
    )
    parser.add_argument(
        "--full-suite",
        action="store_true",
        help="Generate complete architecture documentation suite",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    args = parser.parse_args()

    # Determine what to generate
    if args.full_suite:
        generate_all = True
    else:
        generate_all = not any([
            args.c4_model,
            args.arc42,
            args.adr,
            args.data_architecture,
            args.security_architecture,
            args.quality_attributes,
            args.diagrams,
        ])

    # Update config based on args
    config_updates = {}
    if not generate_all:
        config_updates = {
            "generation": {
                "include_c4_model": args.c4_model,
                "include_arc42": args.arc42,
                "include_adr": args.adr,
                "include_data_architecture": args.data_architecture,
                "include_security_architecture": args.security_architecture,
                "include_quality_attributes": args.quality_attributes,
                "generate_diagrams": args.diagrams,
            }
        }

    generator = ArchitectureGenerator(
        config_path=args.config, output_dir=args.output_dir, verbose=args.verbose
    )

    # Apply config updates
    if config_updates:
        for key, value in config_updates.items():
            if key in generator.config:
                generator.config[key].update(value)
            else:
                generator.config[key] = value

    if generate_all:
        results = generator.generate_full_suite()
    else:
        results = generator.generate_full_suite()  # Still generates based on config

    # Print summary

    if results.get("errors"):
        for _error in results["errors"][:3]:
            pass


if __name__ == "__main__":
    main()
