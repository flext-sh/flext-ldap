#!/bin/bash

# Documentation Maintenance System - Quick Runner
# This script provides easy access to common maintenance operations

set -e # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
MAINTENANCE_DIR="$SCRIPT_DIR"

# Function to print colored output
print_status() {
	echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
	echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
	echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
	echo -e "${BLUE}================================${NC}"
	echo -e "${BLUE}$1${NC}"
	echo -e "${BLUE}================================${NC}"
}

# Function to check if we're in the right directory
check_environment() {
	if [[ ! -f "pyproject.toml" ]]; then
		print_error "Not in project root directory. Please run from the project root."
		exit 1
	fi

	if [[ ! -d "docs/maintenance" ]]; then
		print_error "Maintenance system not found. Please ensure docs/maintenance/ exists."
		exit 1
	fi
}

# Function to check dependencies
check_dependencies() {
	print_status "Checking dependencies..."

	# Check Python
	if ! command -v python &>/dev/null; then
		print_error "Python not found. Please install Python 3.9+"
		exit 1
	fi

	# Check pip
	if ! command -v pip &>/dev/null; then
		print_error "pip not found. Please install pip"
		exit 1
	fi

	# Check if required packages are installed
	python -c "
try:
    import yaml, sys
    print('Core dependencies available')
except ImportError as e:
    print(f'Missing dependency: {e}', file=sys.stderr)
    sys.exit(1)
" 2>/dev/null || {
		print_warning "Installing required dependencies..."
		pip install PyYAML requests beautifulsoup4 lxml markdown || {
			print_error "Failed to install dependencies"
			exit 1
		}
	}

	print_status "Dependencies OK"
}

# Function to run a maintenance command
run_command() {
	local cmd="$1"
	local description="$2"

	print_status "Running: $description"
	if eval "$cmd"; then
		print_status "$description completed successfully"
		return 0
	else
		print_error "$description failed"
		return 1
	fi
}

# Function for comprehensive maintenance
run_comprehensive() {
	print_header "COMPREHENSIVE DOCUMENTATION MAINTENANCE"

	# Run all maintenance tasks
	run_command "python $MAINTENANCE_DIR/audit.py --comprehensive" "Content Quality Audit" || return 1
	run_command "python $MAINTENANCE_DIR/validate_links.py --check-all" "Link Validation" || return 1
	run_command "python $MAINTENANCE_DIR/validate_style.py" "Style Validation" || return 1
	run_command "python $MAINTENANCE_DIR/optimize.py --enhance-all" "Content Optimization" || return 1
	run_command "python $MAINTENANCE_DIR/report.py --generate-dashboard --weekly-summary" "Quality Reporting" || return 1

	# Check sync status
	run_command "python $MAINTENANCE_DIR/sync.py --status" "Synchronization Status Check"

	print_header "MAINTENANCE COMPLETE"
	print_status "All maintenance tasks completed successfully!"
	print_status "Check docs/maintenance/reports/ for detailed reports"
}

# Function for quick audit
run_quick_audit() {
	print_header "QUICK DOCUMENTATION AUDIT"

	run_command "python $MAINTENANCE_DIR/audit.py --quick" "Quick Content Audit" || return 1
	run_command "python $MAINTENANCE_DIR/validate_style.py" "Style Check" || return 1

	print_status "Quick audit completed. Run with --comprehensive for full analysis."
}

# Function for link checking only
run_link_check() {
	print_header "LINK VALIDATION"

	run_command "python $MAINTENANCE_DIR/validate_links.py --check-all" "Comprehensive Link Check" || return 1

	print_status "Link validation completed."
}

# Function to generate reports only
run_reports() {
	print_header "QUALITY REPORTING"

	run_command "python $MAINTENANCE_DIR/report.py --generate-dashboard" "Dashboard Generation" || return 1
	run_command "python $MAINTENANCE_DIR/report.py --weekly-summary" "Weekly Summary" || return 1

	print_status "Reports generated. Check docs/maintenance/reports/"
}

# Function to optimize content only
run_optimize() {
	print_header "CONTENT OPTIMIZATION"

	run_command "python $MAINTENANCE_DIR/optimize.py --enhance-all" "Content Enhancement" || return 1

	print_status "Content optimization completed."
}

# Function to show help
show_help() {
	cat <<EOF
Documentation Maintenance System - Quick Runner

USAGE:
    $0 [COMMAND] [OPTIONS]

COMMANDS:
    comprehensive    Run complete maintenance suite (audit, validate, optimize, report)
    audit           Quick content audit and style check
    links           Validate all links (internal and external)
    optimize        Optimize and enhance content
    reports         Generate quality reports and dashboards
    status          Show system status and recent activity
    help           Show this help message

OPTIONS:
    --dry-run       Show what would be done without making changes
    --verbose       Enable verbose output
    --config FILE   Use specific configuration file

EXAMPLES:
    $0 comprehensive              # Run full maintenance suite
    $0 audit                      # Quick quality check
    $0 links                      # Check all links
    $0 optimize --dry-run         # Preview optimization changes
    $0 reports                    # Generate quality reports
    $0 status                     # Show current status

DEPENDENCIES:
    The script will automatically install required dependencies if missing.

FILES:
    Configuration: docs/maintenance/config.yaml
    Reports: docs/maintenance/reports/
    Backups: docs/maintenance/backups/
    Logs: docs/maintenance/logs/

For detailed documentation, see:
    docs/maintenance/README.md
    docs/maintenance/user-guide.md
    docs/maintenance/troubleshooting.md

EOF
}

# Function to show status
show_status() {
	print_header "SYSTEM STATUS"

	# Check git status
	if command -v git &>/dev/null && git rev-parse --git-dir &>/dev/null; then
		print_status "Git repository: OK"
		git status --porcelain | head -10 | while read -r line; do
			print_status "Git: $line"
		done
	else
		print_warning "Git repository: Not available"
	fi

	# Check recent reports
	if [[ -d "$MAINTENANCE_DIR/reports" ]]; then
		recent_reports=$(find "$MAINTENANCE_DIR/reports" -name "*.html" -o -name "*.md" | wc -l)
		print_status "Recent reports: $recent_reports found"
	else
		print_warning "Reports directory: Not found"
	fi

	# Check backups
	if [[ -d "$MAINTENANCE_DIR/backups" ]]; then
		backup_count=$(find "$MAINTENANCE_DIR/backups" -type f | wc -l)
		print_status "Backups: $backup_count files"
	else
		print_warning "Backups directory: Not found"
	fi

	# Check configuration
	if [[ -f "$MAINTENANCE_DIR/config.yaml" ]]; then
		print_status "Configuration: OK"
	else
		print_error "Configuration: Missing config.yaml"
	fi
}

# Main script logic
main() {
	local command=""
	local dry_run=false
	local verbose=false
	local config_file=""

	# Parse arguments
	while [[ $# -gt 0 ]]; do
		case $1 in
		comprehensive | audit | links | optimize | reports | status | help)
			command="$1"
			shift
			;;
		--dry-run)
			dry_run=true
			shift
			;;
		--verbose)
			verbose=true
			shift
			;;
		--config)
			config_file="$2"
			shift 2
			;;
		*)
			print_error "Unknown option: $1"
			show_help
			exit 1
			;;
		esac
	done

	# Set default command
	if [[ -z $command ]]; then
		command="comprehensive"
	fi

	# Handle help
	if [[ $command == "help" ]]; then
		show_help
		exit 0
	fi

	# Set up environment
	check_environment
	check_dependencies

	# Set environment variables
	export PYTHONPATH="$PROJECT_ROOT:$PYTHONPATH"
	if [[ $verbose == "true" ]]; then
		export DOCS_MAINTENANCE_DEBUG=1
	fi
	if [[ -n $config_file ]]; then
		export DOCS_MAINTENANCE_CONFIG="$config_file"
	fi

	# Handle dry run
	if [[ $dry_run == "true" ]]; then
		print_warning "DRY RUN MODE - No changes will be made"
		export DOCS_MAINTENANCE_DRY_RUN=1
	fi

	# Execute command
	case $command in
	comprehensive)
		run_comprehensive
		;;
	audit)
		run_quick_audit
		;;
	links)
		run_link_check
		;;
	optimize)
		run_optimize
		;;
	reports)
		run_reports
		;;
	status)
		show_status
		;;
	*)
		print_error "Unknown command: $command"
		show_help
		exit 1
		;;
	esac
}

# Run main function with all arguments
main "$@"
