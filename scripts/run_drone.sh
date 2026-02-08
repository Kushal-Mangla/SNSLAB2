#!/bin/bash

# Run Drone Client with proper environment

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

# Check if drone ID is provided
if [ -z "$1" ]; then
    echo "Usage: ./scripts/run_drone.sh <DRONE_ID> [HOST] [PORT]"
    echo "Example: ./scripts/run_drone.sh DRONE_001"
    echo "Example: ./scripts/run_drone.sh DRONE_002 127.0.0.1 9999"
    exit 1
fi

# Activate virtual environment and run drone client
echo "Starting Drone Client: $1"
source .venv/bin/activate
export PYTHONPATH="${PROJECT_ROOT}/src:${PYTHONPATH}"
python3 src/drone_client.py "$@"
