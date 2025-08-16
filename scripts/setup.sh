#!/bin/bash

# User Service Setup Script
# This script sets up the development environment for the user service

set -e

echo "🚀 Setting up User Service development environment..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

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

# Check if Rust is installed
if ! command -v rustc &> /dev/null; then
    print_error "Rust is not installed. Please install Rust from https://rustup.rs/"
    exit 1
fi

print_status "Rust version: $(rustc --version)"

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    print_warning "Docker is not installed. Some features may not work."
    print_warning "Install Docker from https://docs.docker.com/get-docker/"
else
    print_status "Docker version: $(docker --version)"
fi

# Check if sqlx-cli is installed
if ! command -v sqlx &> /dev/null; then
    print_status "Installing sqlx-cli..."
    cargo install sqlx-cli --no-default-features --features rustls,postgres
else
    print_status "sqlx-cli is already installed: $(sqlx --version)"
fi

# Copy environment file if it doesn't exist
if [ ! -f .env ]; then
    print_status "Creating .env file from template..."
    cp .env.example .env
    print_warning "Please update the .env file with your database configuration"
else
    print_status ".env file already exists"
fi

# Start PostgreSQL with Docker if available
if command -v docker &> /dev/null; then
    if [ "$1" = "--with-db" ]; then
        print_status "Starting PostgreSQL database with Docker..."
        docker-compose up -d database

        # Wait for database to be ready
        print_status "Waiting for database to be ready..."
        sleep 10

        # Run migrations
        print_status "Running database migrations..."
        export DATABASE_URL="postgresql://user_service:password@localhost:5432/user_service"
        sqlx migrate run

        print_status "Database is ready!"
    else
        print_warning "To start the database, run: $0 --with-db"
    fi
fi

# Install dependencies and build
print_status "Installing dependencies..."
cargo fetch

print_status "Building project..."
cargo build

# Run tests
print_status "Running tests..."
cargo test

# Check formatting and linting
print_status "Checking code formatting..."
cargo fmt --check || {
    print_warning "Code is not formatted. Run 'cargo fmt' to fix."
}

print_status "Running Clippy lints..."
cargo clippy -- -D warnings || {
    print_warning "Clippy found issues. Please fix them before committing."
}

print_status "Setup completed successfully! 🎉"
echo ""
print_status "Quick start commands:"
echo "  - Start the service: cargo run"
echo "  - Run tests: cargo test"
echo "  - Format code: cargo fmt"
echo "  - Check lints: cargo clippy"
echo "  - Start with database: docker-compose up"
echo ""
print_status "API will be available at: http://localhost:3000"
print_status "Health check: curl http://localhost:3000/health"
