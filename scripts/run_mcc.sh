#!/bin/bash

# Run MCC Server with proper environment

# Get the project root directory (parent of scripts folder)
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

# Check if virtual environment exists
if [ ! -d ".venv" ]; then
    echo "Error: Virtual environment not found!"
    echo "Please run: ./scripts/setup.sh"
    exit 1
fi

# Activate virtual environment and run MCC server
echo "Starting MCC Server..."
source .venv/bin/activate
export PYTHONPATH="${PROJECT_ROOT}/src:${PYTHONPATH}"
python3 src/mcc_server.py
