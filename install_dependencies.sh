#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR"
VENV_DIR="$PROJECT_DIR/venv"
TEMP_DIR="$PROJECT_DIR/temp"
EMBER_REPO="https://github.com/AquaCoder0010/EMBER2024-updated"
echo "=== Starting dependency installation ==="

echo "[1/6] Creating virtual environment..."
python3 -m venv "$VENV_DIR"

echo "[2/6] Creating temp directory and cloning EMBER2024-updated..."
mkdir -p "$TEMP_DIR"
cd "$TEMP_DIR"
git clone "$EMBER_REPO"
cd "$PROJECT_DIR"

echo "[3/6] Installing EMBER2024 library..."
"$VENV_DIR/bin/pip" install "$TEMP_DIR/EMBER2024-updated/"

echo "[4/6] Fixing oscrypto for double-digit OpenSSL versions..."
OSCRYPTO_FILE="$VENV_DIR/lib/python3.12/site-packages/oscrypto/_openssl/_libcrypto_ctypes.py"

if [ -f "$OSCRYPTO_FILE" ]; then
    sed -i "s/\\\\b(\\\\d\\\\.\\\\d\\\\.\\\\d\[a-z\]*)\\\\b/\\\\b(\\\\d+\\\\.\\\\d+\\\\.\\\\d+\[a-z\]*)\\\\b/" "$OSCRYPTO_FILE"
    echo "Fixed $OSCRYPTO_FILE"
else
    echo "Warning: oscrypto file not found at $OSCRYPTO_FILE"
    echo "Attempting to find it..."
    FOUND_FILE=$(find "$VENV_DIR/lib/python3.12/site-packages" -name "_libcrypto_ctypes.py" 2>/dev/null | head -1)
    if [ -n "$FOUND_FILE" ]; then
        echo "Found at: $FOUND_FILE"
        sed -i "s/\\\\b(\\\\d\\\\.\\\\d\\\\.\\\\d\[a-z\]*)\\\\b/\\\\b(\\\\d+\\\\.\\\\d+\\\\.\\\\d+\[a-z\]*)\\\\b/" "$FOUND_FILE"
        echo "Fixed $FOUND_FILE"
    else
        echo "Could not find _libcrypto_ctypes.py, skipping fix"
    fi
fi

echo "[5/6] Installing requirements.txt..."
"$VENV_DIR/bin/pip" install -r "$PROJECT_DIR/requirements.txt"

echo "[6/6] Installation complete!"
echo ""
echo "To activate the virtual environment, run:"
echo "  source $VENV_DIR/bin/activate"
echo ""
echo "=== Dependency installation finished successfully ==="
