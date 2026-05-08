#!/usr/bin/env bash
set -euo pipefail

FILTER=""

usage() {
    echo "Usage: $0 [--unit | --smoke | -h]"
    echo ""
    echo "  (no args)    Run all tests with coverage"
    echo "  --unit       Run unit tests only"
    echo "  --smoke      Run smoke tests only"
    echo "  -h, --help   Show this help"
    exit 0
}

for arg in "$@"; do
    case $arg in
        --unit)    FILTER="-m not smoke" ;;
        --smoke)   FILTER="-m smoke" ;;
        -h|--help) usage ;;
        *)         echo "Unknown option: $arg"; usage ;;
    esac
done

CMD="python3 -m pytest -v $FILTER --cov=identity_provider_server --cov-report=term-missing"

echo "Running: $CMD"
exec $CMD
