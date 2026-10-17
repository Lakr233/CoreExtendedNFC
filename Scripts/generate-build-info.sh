#!/bin/zsh
# Writes Example/CENFC/DerivedSources/BuildInfo.swift (git-ignored) with the build
# time and commit. Run by the CENFC scheme's build pre-action, and by CI before the
# first build: on a fresh checkout the pre-action output appears too late for Xcode
# to compile it in the same build.

set -euo pipefail

PROJECT_DIR="${1:-${PROJECT_DIR:-$(cd "$(dirname "$0")/../Example" && pwd)}}"
COMMIT=$(git -C "${PROJECT_DIR}" rev-parse HEAD 2>/dev/null || echo "unknown")
BUILD_TIME=$(date "+%Y-%m-%d %H:%M:%S %z")
OUTPUT_DIR="${PROJECT_DIR}/CENFC/DerivedSources"
OUTPUT_FILE="${OUTPUT_DIR}/BuildInfo.swift"

mkdir -p "${OUTPUT_DIR}"

NEW_CONTENT="// Auto-generated — do not edit
import Foundation

enum BuildInfo {
    static let buildTime = \"${BUILD_TIME}\"
    static let commitID = \"${COMMIT}\"
}"

if [ -f "${OUTPUT_FILE}" ] && [ "$(cat "${OUTPUT_FILE}")" = "${NEW_CONTENT}" ]; then
    exit 0
fi

printf '%s\n' "${NEW_CONTENT}" > "${OUTPUT_FILE}"
