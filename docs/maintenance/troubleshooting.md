# Documentation Maintenance System - Troubleshooting Guide


<!-- TOC START -->
- [Table of Contents](#table-of-contents)
- [Quick Diagnosis](#quick-diagnosis)
  - [System Health Check](#system-health-check)
  - [Configuration Validation](#configuration-validation)
  - [Dependency Check](#dependency-check)
- [Common Issues](#common-issues)
  - [Import Errors](#import-errors)
  - [Permission Errors](#permission-errors)
  - [Configuration File Errors](#configuration-file-errors)
  - [Path Resolution Issues](#path-resolution-issues)
- [Component-Specific Problems](#component-specific-problems)
  - [Content Audit Issues](#content-audit-issues)
  - [Link Validation Problems](#link-validation-problems)
  - [Style Validation Errors](#style-validation-errors)
  - [Content Optimization Issues](#content-optimization-issues)
  - [Reporting System Problems](#reporting-system-problems)
  - [Synchronization Issues](#synchronization-issues)
- [Performance Issues](#performance-issues)
  - [Memory Usage](#memory-usage)
  - [Slow Execution](#slow-execution)
  - [Disk Space Issues](#disk-space-issues)
- [Configuration Problems](#configuration-problems)
  - [Invalid Configuration Values](#invalid-configuration-values)
  - [Environment-Specific Settings](#environment-specific-settings)
- [Integration Issues](#integration-issues)
  - [CI/CD Pipeline Failures](#cicd-pipeline-failures)
  - [IDE Integration Problems](#ide-integration-problems)
  - [Version Control Conflicts](#version-control-conflicts)
- [Recovery Procedures](#recovery-procedures)
  - [Complete System Reset](#complete-system-reset)
  - [Component-Specific Recovery](#component-specific-recovery)
  - [Data Recovery](#data-recovery)
- [Debug Tools](#debug-tools)
  - [Enable Debug Logging](#enable-debug-logging)
  - [Performance Profiling](#performance-profiling)
  - [Memory Monitoring](#memory-monitoring)
  - [Network Debugging](#network-debugging)
  - [File System Debugging](#file-system-debugging)
- [Advanced Troubleshooting](#advanced-troubleshooting)
  - [Custom Diagnostic Scripts](#custom-diagnostic-scripts)
  - [Automated Health Checks](#automated-health-checks)
<!-- TOC END -->

**Common issues, diagnostics, and solutions for the Documentation Maintenance System**

## Table of Contents

- [Quick Diagnosis](#quick-diagnosis)
- [Common Issues](#common-issues)
- [Component-Specific Problems](#component-specific-problems)
- [Performance Issues](#performance-issues)
- [Configuration Problems](#configuration-problems)
- [Integration Issues](#integration-issues)
- [Recovery Procedures](#recovery-procedures)
- [Debug Tools](#debug-tools)

## Quick Diagnosis

### System Health Check

```bash
# Quick system check
python docs/maintenance/maintain.py --comprehensive --dry-run

# Check all components individually
python docs/maintenance/audit.py --quick
python docs/maintenance/validate_links.py --check-all
python docs/maintenance/validate_style.py
python docs/maintenance/optimize.py --dry-run
python docs/maintenance/report.py --generate-dashboard
```

### Configuration Validation

```bash
# Validate configuration file
python -c "
import yaml
with open('docs/maintenance/config.yaml') as f:
    config = yaml.safe_load(f)
    print('✅ Configuration file is valid')
    print(f'Found {len(config)} top-level sections')
"
```

### Dependency Check

```bash
# Check required dependencies
python -c "
try:
    import yaml, requests, bs4, lxml, markdown
    print('✅ Core dependencies available')
except ImportError as e:
    print(f'❌ Missing dependency: {e}')
"
```

## Common Issues

### Import Errors

**Symptom:**

```yaml
ModuleNotFoundError: No module named 'yaml'
```

**Diagnosis:**

```bash
# Check if dependencies are installed
pip list | grep -E "(PyYAML|requests|beautifulsoup4)"

# Install missing dependencies
pip install -r docs/maintenance/requirements.txt
```

**Prevention:**

- Always install dependencies before running maintenance
- Use virtual environments to avoid conflicts

### Permission Errors

**Symptom:**

```yaml
PermissionError: [Errno 13] Permission denied: 'docs/README.md'
```

**Diagnosis:**

```bash
# Check file permissions
ls -la docs/README.md

# Check directory permissions
ls -ld docs/
```

**Solutions:**

```bash
# Fix file permissions
chmod 644 docs/README.md
chmod 755 docs/

# Or run with appropriate user
sudo -u docsuser python maintenance/audit.py
```

### Configuration File Errors

**Symptom:**

```
yaml.YAMLError: mapping values are not allowed here
```

**Diagnosis:**

```bash
# Validate YAML syntax
python -c "
import yaml
try:
    with open('docs/maintenance/config.yaml') as f:
        yaml.safe_load(f)
    print('✅ YAML syntax is valid')
except yaml.YAMLError as e:
    print(f'❌ YAML error: {e}')
"
```

**Solutions:**

- Check indentation (YAML is indentation-sensitive)
- Use spaces, not tabs
- Validate quotes and special characters
- Use online YAML validators

### Path Resolution Issues

**Symptom:**

```yaml
FileNotFoundError: [Errno 2] No such file or directory: 'docs/README.md'
```

**Diagnosis:**

```bash
# Check current working directory
pwd

# Check if docs directory exists
ls -la docs/

# Check relative paths
python -c "import os; print(os.path.abspath('docs'))"
```

**Solutions:**

- Run commands from the project root directory
- Use absolute paths in scripts
- Verify directory structure matches expectations

## Component-Specific Problems

### Content Audit Issues

#### Slow Performance

**Symptom:** Audit takes too long on large documentation sets

**Solutions:**

```yaml
# config.yaml - Optimize audit settings
audit:
  include_patterns:
    - "*.md" # Limit to markdown only
  exclude_patterns:
    - "**/node_modules/**"
    - "**/.git/**"
    - "**/backups/**"
```

#### Memory Issues

**Symptom:** Out of memory errors with large files

**Solutions:**

```python
# Process files individually
for file_path in file_list:
    result = auditor.audit_file(file_path)
    # Process result immediately
    del result
```

### Link Validation Problems

#### False Positives

**Symptom:** Valid links reported as broken

**Diagnosis:**

```bash
# Debug specific link
python maintenance/validate_links.py --debug-link "https://example.com"

# Check network connectivity
curl -I https://example.com
```

**Solutions:**

- Add domains to skip list in config
- Increase timeout values
- Check firewall/proxy settings

#### Rate Limiting

**Symptom:** Getting 429 Too Many Requests errors

**Solutions:**

```yaml
# config.yaml - Reduce request frequency
validation:
  timeout: 15
  retries: 2
  max_workers: 2
```

#### SSL Certificate Issues

**Symptom:** SSL verification errors

**Solutions:**

```bash
# Disable SSL verification (not recommended for production)
export REQUESTS_CA_BUNDLE=/path/to/ca-bundle.crt

# Or add to skip domains
skip_domains:
  - "self-signed-domain.com"
```

### Style Validation Errors

#### False Heading Hierarchy Violations

**Symptom:** Legitimate heading structures flagged as invalid

**Diagnosis:**

```bash
# Check specific file
python maintenance/validate_style.py --file docs/example.md --verbose
```

**Solutions:**

- Adjust heading hierarchy rules in config
- Use proper markdown heading syntax
- Document intentional deviations

#### Code Block Language Detection

**Symptom:** Language not detected correctly

**Solutions:**

````python
# Manually specify language
```python
def example():
    pass
````

````

### Content Optimization Issues

#### Unwanted Changes

**Symptom:** Optimization makes incorrect changes

**Recovery:**
```bash
# Check what changed
git diff docs/

# Restore from backup
cp docs/maintenance/backups/example.md.backup docs/example.md

# Or rollback
python maintenance/sync.py --rollback docs/example.md
````

#### Over-Aggressive Fixes

**Solutions:**

```yaml
# config.yaml - Be more conservative
optimization:
  auto_fix: false # Manual review required
  fix_common_typos: true
  enhance_code_blocks: false # Skip complex changes
```

### Reporting System Problems

#### Missing Charts/Data

**Symptom:** Reports generated but missing visualizations

**Diagnosis:**

```bash
# Check matplotlib/seaborn installation
python -c "import matplotlib, seaborn; print('✅ Chart libraries available')"

# Check data availability
ls -la docs/maintenance/reports/
```

**Solutions:**

- Install visualization dependencies
- Ensure audit data is available before generating reports
- Check file permissions for report output directory

### Synchronization Issues

#### Git Operation Failures

**Symptom:** Sync operations fail with git errors

**Diagnosis:**

```bash
# Check git status
python maintenance/sync.py --status

# Manual git check
git status
git remote -v
```

**Solutions:**

- Ensure git repository is properly initialized
- Check remote repository access
- Verify branch permissions
- Use manual git commands if automated sync fails

## Performance Issues

### Memory Usage

**Symptom:** High memory consumption with large documentation sets

**Solutions:**

```python
# Process files in batches
batch_size = 10
for i in range(0, len(file_list), batch_size):
    batch = file_list[i:i+batch_size]
    # Process batch
```

```yaml
# config.yaml - Limit concurrent operations
validation:
  max_workers: 2
```

### Slow Execution

**Symptom:** Operations take too long to complete

**Solutions:**

- Enable caching for link validation
- Reduce external link checking frequency
- Use parallel processing where appropriate
- Schedule intensive tasks during off-hours

### Disk Space Issues

**Symptom:** Running out of disk space due to backups/logs

**Solutions:**

```bash
# Clean old backups
find docs/maintenance/backups/ -type f -mtime +30 -delete

# Compress old reports
gzip docs/maintenance/reports/*.json

# Limit log file size
logrotate -f /etc/logrotate.d/docs-maintenance
```

## Configuration Problems

### Invalid Configuration Values

**Symptom:** Components fail with configuration-related errors

**Validation:**

```python
# Validate configuration
python -c "
import yaml
from cerberus import Validator

schema = {
    'audit': {
        'thresholds': {
            'min_word_count': {'type': 'integer', 'min': 0},
            'max_age_days': {'type': 'integer', 'min': 1}
        }
    }
}

with open('docs/maintenance/config.yaml') as f:
    config = yaml.safe_load(f)

v = Validator(schema)
if v.validate(config):
    print('✅ Configuration is valid')
else:
    print('❌ Configuration errors:', v.errors)
"
```

### Environment-Specific Settings

**Symptom:** Configuration works in development but fails in production

**Solutions:**

- Use environment variables for sensitive data
- Create environment-specific config files
- Use config inheritance (base + environment overrides)

```yaml
# config.prod.yaml
extends: config.yaml
sync:
  auto_commit: true
  push_after_commit: true
```

## Integration Issues

### CI/CD Pipeline Failures

**Symptom:** Maintenance jobs fail in automated pipelines

**Diagnosis:**

```bash
# Test in isolated environment
docker run --rm -v $(pwd):/workspace \
  python:3.9-slim \
  bash -c "cd /workspace && pip install -r docs/maintenance/requirements.txt && python docs/maintenance/audit.py --quick"
```

**Solutions:**

- Use specific Python versions in pipelines
- Install dependencies in correct order
- Handle network timeouts gracefully
- Use caching for dependencies

### IDE Integration Problems

**Symptom:** Maintenance scripts don't work in IDE environments

**Solutions:**

- Set working directory in IDE run configurations
- Use absolute paths in scripts
- Configure PYTHONPATH correctly
- Handle import path issues

### Version Control Conflicts

**Symptom:** Merge conflicts in maintenance-generated files

**Solutions:**

- Don't commit generated files to version control
- Use .gitignore for reports and cache files
- Regenerate reports after merges
- Use branch-specific maintenance runs

## Recovery Procedures

### Complete System Reset

```bash
# Stop all maintenance processes
pkill -f "python.*maintenance"

# Clear all caches and temporary files
rm -rf docs/maintenance/.cache/
rm -rf docs/maintenance/backups/
rm -rf docs/maintenance/reports/

# Reset configuration to defaults
cp docs/maintenance/config.yaml.backup docs/maintenance/config.yaml

# Reinitialize
python docs/maintenance/audit.py --rebuild-db
```

### Component-Specific Recovery

#### Audit System Recovery

```bash
# Clear audit cache
rm -rf docs/maintenance/.audit_cache/

# Rebuild audit database
python docs/maintenance/audit.py --rebuild-db
```

#### Link Validation Recovery

```bash
# Clear link cache
rm docs/maintenance/.link_cache.json

# Reset validation state
python docs/maintenance/validate_links.py --clear-cache
```

#### Git Repository Recovery

```bash
# Check repository state
git status
git log --oneline -5

# Reset to clean state
git reset --hard HEAD
git clean -fd
```

### Data Recovery

#### Restore from Backups

```bash
# List available backups
ls docs/maintenance/backups/

# Restore specific file
cp docs/maintenance/backups/README.md.20241201_120000.backup docs/README.md
```

#### Regenerate Reports

```bash
# Regenerate all reports
python docs/maintenance/report.py --generate-dashboard --weekly-summary
```

## Debug Tools

### Enable Debug Logging

```python
# Add to scripts
import logging
logging.basicConfig(level=logging.DEBUG)

# Or set environment variable
export DOCS_MAINTENANCE_DEBUG=1
```

### Performance Profiling

```python
# Profile script execution
python -m cProfile docs/maintenance/audit.py --comprehensive > audit_profile.txt

# Analyze results
python -c "
import pstats
p = pstats.Stats('audit_profile.txt')
p.sort_stats('cumulative').print_stats(20)
"
```

### Memory Monitoring

```python
# Monitor memory usage
import psutil
import os

process = psutil.Process(os.getpid())
print(f"Memory usage: {process.memory_info().rss / 1024 / 1024:.1f} MB")
```

### Network Debugging

```bash
# Test network connectivity
curl -v https://example.com

# Check DNS resolution
nslookup example.com

# Test with different user agents
curl -H "User-Agent: Mozilla/5.0" https://example.com
```

### File System Debugging

```python
# Debug file operations
import os
print(f"Current directory: {os.getcwd()}")
print(f"Docs directory exists: {os.path.exists('docs')}")
print(f"Docs directory contents: {os.listdir('docs')}")
```

## Advanced Troubleshooting

### Custom Diagnostic Scripts

Create diagnostic scripts for complex issues:

```python
# docs/maintenance/diagnostics.py
def diagnose_link_issues():
    """Comprehensive link validation diagnostics."""
    # Check network connectivity
    # Test DNS resolution
    # Validate SSL certificates
    # Check firewall rules
    pass

def diagnose_performance_issues():
    """Performance bottleneck analysis."""
    # Profile execution time
    # Monitor resource usage
    # Identify slow components
    # Suggest optimizations
    pass
```

### Automated Health Checks

```bash
# Create health check script
cat > docs/maintenance/health_check.sh << 'EOF'
#!/bin/bash
echo "=== Documentation Maintenance System Health Check ==="

# Check dependencies
echo "Checking dependencies..."
python -c "import yaml, requests, bs4; print('✅ Dependencies OK')" 2>/dev/null || echo "❌ Dependencies missing"

# Check configuration
echo "Checking configuration..."
python -c "import yaml; yaml.safe_load(open('docs/maintenance/config.yaml')); print('✅ Config OK')" 2>/dev/null || echo "❌ Config invalid"

# Check file permissions
echo "Checking permissions..."
[ -r docs/maintenance/config.yaml ] && echo "✅ Config readable" || echo "❌ Config not readable"
[ -w docs/ ] && echo "✅ Docs writable" || echo "❌ Docs not writable"

# Check disk space
echo "Checking disk space..."
df -h docs/ | tail -1

echo "Health check complete."
EOF

chmod +x docs/maintenance/health_check.sh
```

---

**Documentation Maintenance System Troubleshooting Guide**

**Key Recovery Steps:**

1. **Diagnose**: Run health checks and gather diagnostic information
2. **Isolate**: Identify which component is failing
3. **Fix**: Apply appropriate solution from this guide
4. **Verify**: Test the fix and ensure no regressions
5. **Prevent**: Update configurations or procedures to prevent recurrence

**Support Resources:**

- **GitHub Issues**: Bug reports and feature requests
- **Documentation**: Comprehensive user guide and API reference
- **Community**: Forums and discussion channels
- **Professional Services**: Enterprise support and consulting

**Prevention Best Practices:**

- Regular health checks and maintenance
- Automated monitoring and alerting
- Comprehensive testing before deployments
- Backup strategies and recovery procedures
- Documentation of troubleshooting procedures
