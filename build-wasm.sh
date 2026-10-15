#!/bin/bash
# Build script for DOM Mail MX Node WASM module

set -e

echo "=== Building DOM Mail MX Node WASM ==="

cd "$(dirname "$0")/rust-mx-node"

# Check for wasm-pack
if ! command -v wasm-pack &> /dev/null; then
    echo "Installing wasm-pack..."
    cargo install wasm-pack
fi

# Build for web target
echo "Building for web target..."
wasm-pack build \
    --target web \
    --out-dir ../../domail/assets/wasm \
    --out-name mx_node \
    --release \
    --features "console_log,wee_alloc" \
    -- -Z build-std=std,panic_abort -Z build-std-features=panic_immediate_abort

# Also build for Node.js target (for CLI)
echo "Building for Node.js target..."
wasm-pack build \
    --target nodejs \
    --out-dir ../../domail/assets/wasm-node \
    --out-name mx_node_node \
    --release \
    --features "console_log,wee_alloc" \
    -- -Z build-std=std,panic_abort -Z build-std-features=panic_immediate_abort

echo "=== Build complete ==="
echo "WASM files in: domail/assets/wasm/"
echo "  - mx_node.js"
echo "  - mx_node_bg.wasm"
echo "  - mx_node.d.ts"

# Copy to CLI directory
cp ../../domail/assets/wasm/mx_node_bg.wasm ../../domail/core/wasm/
cp ../../domail/assets/wasm/mx_node.js ../../domail/core/wasm/

echo "Done!"