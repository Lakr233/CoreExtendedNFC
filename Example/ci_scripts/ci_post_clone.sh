#!/bin/zsh
# Xcode Cloud: generate BuildInfo.swift before the build starts. On a fresh
# checkout the scheme pre-action writes it too late to be compiled.

set -euo pipefail

"${CI_PRIMARY_REPOSITORY_PATH}/Scripts/generate-build-info.sh" "${CI_PRIMARY_REPOSITORY_PATH}/Example"
