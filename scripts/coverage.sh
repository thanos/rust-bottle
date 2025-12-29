#!/bin/bash
# Coverage analysis script for rust-bottle
# This script generates coverage reports for different feature combinations

set -e

echo "🔍 Running code coverage analysis for rust-bottle"
echo ""

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if cargo-tarpaulin is installed
if ! command -v cargo-tarpaulin &> /dev/null; then
    echo "❌ cargo-tarpaulin is not installed"
    echo "   Install it with: cargo install cargo-tarpaulin"
    exit 1
fi

# Create coverage directory
mkdir -p coverage

# Feature sets to test
declare -a FEATURES=(
    ""
    "ml-kem"
    "post-quantum"
    "ml-kem,post-quantum"
)

# Function to run coverage for a feature set
run_coverage() {
    local features=$1
    local feature_name=${features:-"default"}
    
    echo -e "${YELLOW}📊 Running coverage with features: ${feature_name}${NC}"
    
    if [ -z "$features" ]; then
        cargo tarpaulin \
            --out Html \
            --out Xml \
            --out Stdout \
            --output-dir "coverage/${feature_name}" \
            --timeout 300 \
            --fail-under 80
    else
        cargo tarpaulin \
            --features "$features" \
            --out Html \
            --out Xml \
            --out Stdout \
            --output-dir "coverage/${feature_name}" \
            --timeout 300 \
            --fail-under 80
    fi
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ Coverage passed for ${feature_name}${NC}"
        echo ""
    else
        echo -e "❌ Coverage failed for ${feature_name}"
        echo ""
        return 1
    fi
}

# Run coverage for each feature set
FAILED=0
for features in "${FEATURES[@]}"; do
    if ! run_coverage "$features"; then
        FAILED=1
    fi
done

# Generate summary
echo "📈 Coverage Summary"
echo "=================="
echo ""
for features in "${FEATURES[@]}"; do
    feature_name=${features:-"default"}
    if [ -f "coverage/${feature_name}/cobertura.xml" ]; then
        echo "✅ ${feature_name}: Report generated"
        echo "   HTML: coverage/${feature_name}/tarpaulin-report.html"
        echo "   XML:  coverage/${feature_name}/cobertura.xml"
    else
        echo "❌ ${feature_name}: No report generated"
    fi
    echo ""
done

# Open the default coverage report if on macOS
if [[ "$OSTYPE" == "darwin"* ]] && [ -f "coverage/default/tarpaulin-report.html" ]; then
    echo "🌐 Opening coverage report in browser..."
    open "coverage/default/tarpaulin-report.html"
fi

if [ $FAILED -eq 1 ]; then
    echo "⚠️  Some coverage runs failed. Check the output above for details."
    exit 1
else
    echo -e "${GREEN}✅ All coverage reports generated successfully!${NC}"
    exit 0
fi


