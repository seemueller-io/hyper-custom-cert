#!/bin/bash

# test-all.sh - Comprehensive test automation for hyper-custom-cert
# 
# This script automates testing across all feature combinations as specified
# in the development guidelines. It runs:
# - Default feature tests (native-tls)
# - No default features (no TLS backend)
# - rustls feature tests
# - insecure-dangerous feature tests
# - All feature combinations
# - Documentation tests
# - Build verification with strict warnings
#
# Usage: ./scripts/test-all.sh [OPTIONS]
# Options:
#   --help, -h          Show this help message
#   --verbose, -v       Enable verbose output
#   --no-doc           Skip documentation tests
#   --no-build         Skip build verification
#   --quick            Run only basic test combinations (skip exhaustive tests)

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
VERBOSE=false
SKIP_DOC=false
SKIP_BUILD=false
QUICK_MODE=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --help, -h          Show this help message"
            echo "  --verbose, -v       Enable verbose output"
            echo "  --no-doc           Skip documentation tests"
            echo "  --no-build         Skip build verification"
            echo "  --quick            Run only basic test combinations"
            echo ""
            echo "This script runs comprehensive tests for all feature combinations:"
            echo "- Default features (native-tls)"
            echo "- No default features"
            echo "- rustls features"
            echo "- insecure-dangerous features"
            echo "- Documentation tests"
            echo "- Build verification"
            exit 0
            ;;
        --verbose|-v)
            VERBOSE=true
            shift
            ;;
        --no-doc)
            SKIP_DOC=true
            shift
            ;;
        --no-build)
            SKIP_BUILD=true
            shift
            ;;
        --quick)
            QUICK_MODE=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

run_command() {
    local description="$1"
    shift
    
    log_info "Running: $description"
    
    if [[ "$VERBOSE" == true ]]; then
        echo "Command: $*"
    fi
    
    if "$@"; then
        log_success "$description - PASSED"
        return 0
    else
        log_error "$description - FAILED"
        return 1
    fi
}

# Ensure we're in the project root
if [[ ! -f "Cargo.toml" ]] || [[ ! -d "crates/hyper-custom-cert" ]]; then
    log_error "This script must be run from the project root directory"
    exit 1
fi

log_info "Starting comprehensive test suite for hyper-custom-cert"
echo "Working directory: $(pwd)"
echo "Timestamp: $(date)"
echo ""

# Test counter
TESTS_RUN=0
TESTS_PASSED=0

run_test() {
    ((TESTS_RUN++))
    if run_command "$@"; then
        ((TESTS_PASSED++))
        return 0
    else
        return 1
    fi
}

# 1. Test with default features (native-tls)
log_info "=== Testing with default features (native-tls) ==="
run_test "Default features test" cargo test

# 2. Test without default features (no TLS backend)
log_info "=== Testing without default features (no TLS backend) ==="
run_test "No default features test" cargo test --no-default-features

# 3. Test with rustls feature
log_info "=== Testing with rustls feature ==="
run_test "rustls feature test" cargo test --no-default-features --features "rustls"

# 4. Test with insecure-dangerous feature (if not in quick mode)
if [[ "$QUICK_MODE" != true ]]; then
    log_info "=== Testing with insecure-dangerous feature ==="
    run_test "insecure-dangerous feature test" cargo test --features "insecure-dangerous"
fi

# 5. Test with rustls + insecure-dangerous combination (if not in quick mode)
if [[ "$QUICK_MODE" != true ]]; then
    log_info "=== Testing with rustls + insecure-dangerous features ==="
    run_test "rustls + insecure-dangerous test" cargo test --no-default-features --features "rustls,insecure-dangerous"
fi

# 6. Test all features together (if not in quick mode)
if [[ "$QUICK_MODE" != true ]]; then
    log_info "=== Testing with all features ==="
    run_test "All features test" cargo test --all-features
fi

# 7. Documentation tests
if [[ "$SKIP_DOC" != true ]]; then
    log_info "=== Testing documentation examples ==="
    run_test "Documentation tests (default)" cargo test --doc
    
    if [[ "$QUICK_MODE" != true ]]; then
        run_test "Documentation tests (rustls)" cargo test --doc --no-default-features --features "rustls"
        run_test "Documentation tests (all features)" cargo test --doc --all-features
    fi
fi

# 8. Build verification with strict warnings
if [[ "$SKIP_BUILD" != true ]]; then
    log_info "=== Build verification with strict warnings ==="
    
    # Set RUSTDOCFLAGS for strict documentation warnings
    export RUSTDOCFLAGS="-D warnings"
    
    run_test "Build with default features" cargo build
    run_test "Build without default features" cargo build --no-default-features
    run_test "Build with rustls" cargo build --no-default-features --features "rustls"
    
    if [[ "$QUICK_MODE" != true ]]; then
        run_test "Build with insecure-dangerous" cargo build --features "insecure-dangerous"
        run_test "Build with all features" cargo build --all-features
    fi
    
    # Documentation generation with strict warnings
    run_test "Documentation generation (rustls)" cargo doc --no-default-features --features "rustls"
    
    if [[ "$QUICK_MODE" != true ]]; then
        run_test "Documentation generation (all features)" cargo doc --all-features
    fi
fi

# Summary
echo ""
echo "=========================================="
log_info "Test Summary"
echo "=========================================="
echo "Tests run: $TESTS_RUN"
echo "Tests passed: $TESTS_PASSED"
echo "Tests failed: $((TESTS_RUN - TESTS_PASSED))"

if [[ $TESTS_PASSED -eq $TESTS_RUN ]]; then
    log_success "All tests passed! ✅"
    exit 0
else
    log_error "Some tests failed! ❌"
    exit 1
fi