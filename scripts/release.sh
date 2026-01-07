#!/bin/bash
# Release script for rust-bottle
# This script helps automate the cargo release process

set -e

echo "🚀 Preparing rust-bottle release"
echo ""

# Check if cargo-release is installed
if ! command -v cargo-release &> /dev/null; then
    echo "⚠️  cargo-release not found. Installing..."
    cargo install cargo-release --locked
fi

# Check current version
CURRENT_VERSION=$(grep '^version = ' Cargo.toml | cut -d'"' -f2)
echo "Current version: $CURRENT_VERSION"
echo ""

# Ask for release type
echo "What type of release?"
echo "1) patch (0.1.0 -> 0.1.1)"
echo "2) minor (0.1.0 -> 0.2.0)"
echo "3) major (0.1.0 -> 1.0.0)"
echo "4) custom version"
read -p "Enter choice [1-4]: " choice

case $choice in
    1)
        RELEASE_TYPE="patch"
        ;;
    2)
        RELEASE_TYPE="minor"
        ;;
    3)
        RELEASE_TYPE="major"
        ;;
    4)
        read -p "Enter version (e.g., 0.2.0): " CUSTOM_VERSION
        RELEASE_TYPE="version"
        RELEASE_ARG="--version $CUSTOM_VERSION"
        ;;
    *)
        echo "Invalid choice"
        exit 1
        ;;
esac

# Run pre-release checks
echo ""
echo "📋 Running pre-release checks..."
echo ""

# Check if tests pass
echo "Running tests..."
if ! cargo test --all-features; then
    echo "❌ Tests failed. Please fix before releasing."
    exit 1
fi

# Check if clippy passes
echo "Running clippy..."
if ! cargo clippy --all-features -- -D warnings; then
    echo "❌ Clippy found issues. Please fix before releasing."
    exit 1
fi

# Check if package is valid
echo "Checking package..."
if ! cargo package --allow-dirty; then
    echo "❌ Package check failed. Please fix before releasing."
    exit 1
fi

echo ""
echo "✅ Pre-release checks passed!"
echo ""

# Confirm release
read -p "Ready to release? This will bump version, create tag, and publish to crates.io [y/N]: " confirm
if [[ ! $confirm =~ ^[Yy]$ ]]; then
    echo "Release cancelled."
    exit 0
fi

# Run cargo-release
echo ""
echo "🚀 Running cargo-release..."
if [ "$choice" == "4" ]; then
    cargo release $RELEASE_TYPE $RELEASE_ARG --execute
else
    cargo release $RELEASE_TYPE --execute
fi

echo ""
echo "✅ Release complete!"
echo ""
echo "Next steps:"
echo "1. Verify the release on crates.io: https://crates.io/crates/rust-bottle"
echo "2. Create a GitHub release with release notes"
echo "3. Update any documentation that references the version"



