#!/bin/bash

# Setup script for UAV C2 System
# Installs dependencies and prepares environment

# Get the project root directory (parent of scripts folder)
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

echo "╔════════════════════════════════════════════════════════════╗"
echo "║         UAV C2 System - Setup Script                      ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "[SETUP] Project root: $PROJECT_ROOT"
echo ""

# Check Python version
echo "[SETUP] Checking Python version..."
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
echo "[SETUP] Python version: $PYTHON_VERSION"

# Check if virtual environment exists
if [ ! -d ".venv" ]; then
    echo "[SETUP] Creating virtual environment..."
    python3 -m venv .venv
    echo "[SETUP] ✓ Virtual environment created"
else
    echo "[SETUP] Virtual environment already exists"
fi

# Activate virtual environment
echo "[SETUP] Activating virtual environment..."
source .venv/bin/activate

# Upgrade pip
echo "[SETUP] Upgrading pip..."
pip install --upgrade pip > /dev/null 2>&1

# Install dependencies
echo "[SETUP] Installing dependencies..."
pip install -r requirements.txt

if [ $? -eq 0 ]; then
    echo "[SETUP] ✓ Dependencies installed successfully"
else
    echo "[SETUP] ✗ Failed to install dependencies"
    exit 1
fi

# Make scripts executable
echo "[SETUP] Making scripts executable..."
chmod +x scripts/run_mcc.sh
chmod +x scripts/run_drone.sh
chmod +x scripts/run_all_tests.sh
chmod +x src/mcc_server.py
chmod +x src/drone_client.py
chmod +x tests/test_suite.py
chmod +x tests/test_integration.py

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║         Setup Complete!                                    ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "To run the system:"
echo "  1. Terminal 1: ./scripts/run_mcc.sh"
echo "  2. Terminal 2: ./scripts/run_drone.sh DRONE_001"
echo "  3. Terminal 3: ./scripts/run_drone.sh DRONE_002"
echo ""
echo "To run tests:"
echo "  ./scripts/run_all_tests.sh"
echo ""
echo "Or manually:"
echo "  1. source .venv/bin/activate"
echo "  2. python3 mcc_server.py"
echo "  3. python3 drone_client.py DRONE_001"
echo ""
