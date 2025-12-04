#!/bin/bash
# Build script for BackupLens services
# This script builds all services without Docker

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/bin"
SERVICES=("backuplens-pipeline" "yara-scanner" "clamav-updater")

echo "Building BackupLens services..."
echo "Build directory: ${BUILD_DIR}"
echo ""

# Create build directory
mkdir -p "${BUILD_DIR}"

# Build each service
for service in "${SERVICES[@]}"; do
    echo "Building ${service}..."
    cd "${SCRIPT_DIR}/services/${service}"
    
    # Initialize go.mod if it doesn't exist
    if [ ! -f go.mod ]; then
        echo "  Initializing go.mod..."
        go mod init ${service}
    fi
    
    # Download dependencies
    echo "  Downloading dependencies..."
    go mod download
    
    # Build
    echo "  Compiling..."
    go build -o "${BUILD_DIR}/${service}" -ldflags="-s -w" .
    
    echo "  ✓ ${service} built successfully"
    echo ""
done

echo "Build complete!"
echo "Binaries are in: ${BUILD_DIR}"
echo ""
echo "To run services:"
echo "  ./bin/backuplens-pipeline"
echo "  ./bin/yara-scanner"
echo "  ./bin/clamav-updater"

