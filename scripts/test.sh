#!/bin/bash

# User Service Test Script
# Comprehensive testing script for the user service

set -e

echo "🧪 Running User Service Tests..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to run a test section
run_test_section() {
    local test_name="$1"
    local test_command="$2"
    
    print_status "Running $test_name..."
    if eval "$test_command"; then
        print_status "✅ $test_name passed"
    else
        print_error "❌ $test_name failed"
        exit 1
    fi
    echo ""
}

# Set test environment
export RUST_TEST_THREADS=1
export RUST_BACKTRACE=1

# Unit tests
run_test_section "Unit Tests" "cargo test --lib"

# Integration tests (if any)
if [ -d "tests" ]; then
    run_test_section "Integration Tests" "cargo test --test '*'"
fi

# Documentation tests
run_test_section "Documentation Tests" "cargo test --doc"

# Code formatting check
run_test_section "Code Formatting" "cargo fmt --check"

# Linting with Clippy
run_test_section "Clippy Lints" "cargo clippy --all-targets --all-features -- -D warnings"

# Security audit (if cargo-audit is installed)
if command -v cargo-audit &> /dev/null; then
    run_test_section "Security Audit" "cargo audit"
else
    print_warning "cargo-audit not installed. Skipping security audit."
    print_warning "Install with: cargo install cargo-audit"
fi

# Check for unused dependencies (if cargo-udeps is installed)
if command -v cargo-udeps &> /dev/null; then
    run_test_section "Unused Dependencies" "cargo +nightly udeps"
else
    print_warning "cargo-udeps not installed. Skipping unused dependency check."
    print_warning "Install with: cargo install cargo-udeps"
fi

# Build in release mode
run_test_section "Release Build" "cargo build --release"

# Check that examples compile
if [ -d "examples" ]; then
    run_test_section "Example Compilation" "cargo build --examples"
fi

print_status "🎉 All tests passed successfully!"
echo ""
print_status "Test Summary:"
echo "  ✅ Unit tests"
echo "  ✅ Integration tests"
echo "  ✅ Documentation tests"
echo "  ✅ Code formatting"
echo "  ✅ Clippy lints"
echo "  ✅ Release build"
echo "  ✅ Example compilation"
echo ""
print_status "Ready for production! 🚀"