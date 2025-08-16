#!/bin/bash

# User Service Test Runner
# This script sets up the environment and runs tests with proper database configuration

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
DATABASE_URL="postgresql://user_service_test:test_password@localhost:5433/user_service_test"
TEST_FILTER=""
SETUP_DB=true
CLEANUP_DB=false
VERBOSE=false

# Help function
show_help() {
    cat << EOF
User Service Test Runner

USAGE:
    $0 [OPTIONS] [TEST_FILTER]

OPTIONS:
    -h, --help              Show this help message
    -s, --skip-db-setup     Skip database setup (assumes database is already running)
    -c, --cleanup           Stop and remove test database after tests
    -v, --verbose           Show verbose output
    --db-url URL           Override default database URL

EXAMPLES:
    $0                                    # Run all tests with database setup
    $0 test_create_user                   # Run tests matching 'test_create_user'
    $0 --skip-db-setup                    # Run tests without setting up database
    $0 --cleanup test_password            # Run password tests and cleanup database
    $0 -v service::user::tests            # Run all user service tests with verbose output

DATABASE:
    The script expects a PostgreSQL test database running on localhost:5433
    Default connection: $DATABASE_URL

EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -s|--skip-db-setup)
            SETUP_DB=false
            shift
            ;;
        -c|--cleanup)
            CLEANUP_DB=true
            shift
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        --db-url)
            DATABASE_URL="$2"
            shift 2
            ;;
        -*)
            echo -e "${RED}Error: Unknown option $1${NC}"
            show_help
            exit 1
            ;;
        *)
            TEST_FILTER="$1"
            shift
            ;;
    esac
done

# Print configuration
echo -e "${BLUE}User Service Test Runner${NC}"
echo -e "${BLUE}========================${NC}"
echo -e "Database URL: ${YELLOW}$DATABASE_URL${NC}"
echo -e "Setup Database: ${YELLOW}$SETUP_DB${NC}"
echo -e "Cleanup Database: ${YELLOW}$CLEANUP_DB${NC}"
echo -e "Test Filter: ${YELLOW}${TEST_FILTER:-"(all tests)"}${NC}"
echo ""

# Function to check if database is running
check_database() {
    echo -e "${BLUE}Checking database connection...${NC}"

    # Extract connection details from DATABASE_URL
    local host=$(echo $DATABASE_URL | sed -n 's/.*@\([^:]*\):.*/\1/p')
    local port=$(echo $DATABASE_URL | sed -n 's/.*:\([0-9]*\)\/.*/\1/p')

    if command -v nc >/dev/null 2>&1; then
        if ! nc -z $host $port 2>/dev/null; then
            echo -e "${RED}Error: Cannot connect to database at $host:$port${NC}"
            return 1
        fi
    else
        echo -e "${YELLOW}Warning: 'nc' command not found, skipping connection check${NC}"
    fi

    echo -e "${GREEN}Database connection OK${NC}"
    return 0
}

# Function to setup database
setup_database() {
    if [ "$SETUP_DB" = false ]; then
        echo -e "${YELLOW}Skipping database setup${NC}"
        check_database
        return $?
    fi

    echo -e "${BLUE}Setting up test database...${NC}"

    # Check if docker-compose is available
    if ! command -v docker-compose >/dev/null 2>&1; then
        echo -e "${RED}Error: docker-compose is required but not installed${NC}"
        exit 1
    fi

    # Start the test database
    echo -e "${BLUE}Starting test database container...${NC}"
    docker-compose up -d test-database

    # Wait for database to be ready
    echo -e "${BLUE}Waiting for database to be ready...${NC}"
    local attempts=0
    local max_attempts=30

    while [ $attempts -lt $max_attempts ]; do
        if check_database 2>/dev/null; then
            echo -e "${GREEN}Test database is ready!${NC}"
            return 0
        fi

        attempts=$((attempts + 1))
        echo -e "${YELLOW}Waiting for database... (attempt $attempts/$max_attempts)${NC}"
        sleep 2
    done

    echo -e "${RED}Error: Database failed to start within ${max_attempts} seconds${NC}"
    echo -e "${YELLOW}Try running: docker-compose logs test-database${NC}"
    exit 1
}

# Function to cleanup database
cleanup_database() {
    if [ "$CLEANUP_DB" = true ]; then
        echo -e "${BLUE}Cleaning up test database...${NC}"
        docker-compose down test-database
        echo -e "${GREEN}Test database stopped${NC}"
    fi
}

# Function to run tests
run_tests() {
    echo -e "${BLUE}Running tests...${NC}"

    # Build test command
    local test_cmd="cargo test --lib"

    if [ -n "$TEST_FILTER" ]; then
        test_cmd="$test_cmd $TEST_FILTER"
    fi

    if [ "$VERBOSE" = true ]; then
        test_cmd="$test_cmd -- --nocapture"
    fi

    echo -e "${YELLOW}Command: $test_cmd${NC}"
    echo ""

    # Set environment and run tests
    export DATABASE_URL="$DATABASE_URL"
    export RUST_LOG="${RUST_LOG:-debug}"
    export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"

    if eval $test_cmd; then
        echo ""
        echo -e "${GREEN}✅ All tests passed!${NC}"
        return 0
    else
        echo ""
        echo -e "${RED}❌ Some tests failed!${NC}"
        return 1
    fi
}

# Main execution
main() {
    local exit_code=0

    # Trap to ensure cleanup runs even if script is interrupted
    trap cleanup_database EXIT

    # Setup database
    setup_database || exit 1

    # Run tests
    run_tests || exit_code=1

    # Manual cleanup (also runs in trap)
    cleanup_database

    if [ $exit_code -eq 0 ]; then
        echo -e "${GREEN}🎉 Test run completed successfully!${NC}"
    else
        echo -e "${RED}💥 Test run failed!${NC}"
    fi

    exit $exit_code
}

# Run main function
main "$@"
