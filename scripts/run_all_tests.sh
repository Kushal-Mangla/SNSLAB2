#!/bin/bash
# Run all tests for UAV C2 System

# Get the project root directory (parent of scripts folder)
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

source .venv/bin/activate
export PYTHONPATH="${PROJECT_ROOT}/src:${PYTHONPATH}"

echo "╔════════════════════════════════════════════════════════════╗"
echo "║         UAV C2 System - Running All Tests                 ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Run unit tests
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  UNIT TESTS (test_suite.py)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
python3 tests/test_suite.py
UNIT_STATUS=$?

echo ""
echo ""

# Run integration tests
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  INTEGRATION TESTS (test_integration.py)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
python3 tests/test_integration.py
INTEGRATION_STATUS=$?

echo ""
echo ""

# Summary
echo "╔════════════════════════════════════════════════════════════╗"
echo "║                    TEST SUMMARY                            ║"
echo "╠════════════════════════════════════════════════════════════╣"

if [ $UNIT_STATUS -eq 0 ]; then
    echo "║  Unit Tests:        ✓ PASSED (14/14)                      ║"
else
    echo "║  Unit Tests:        ✗ FAILED                              ║"
fi

if [ $INTEGRATION_STATUS -eq 0 ]; then
    echo "║  Integration Tests: ✓ PASSED (5/5)                        ║"
else
    echo "║  Integration Tests: ✗ FAILED                              ║"
fi

echo "╠════════════════════════════════════════════════════════════╣"

if [ $UNIT_STATUS -eq 0 ] && [ $INTEGRATION_STATUS -eq 0 ]; then
    echo "║  Overall Status:    ✓ ALL TESTS PASSED                    ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    exit 0
else
    echo "║  Overall Status:    ✗ SOME TESTS FAILED                   ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    exit 1
fi
