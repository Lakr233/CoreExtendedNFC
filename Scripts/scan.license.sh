#!/bin/zsh

cd "$(dirname "$0")"

while [[ ! -d .git ]] && [[ "$(pwd)" != "/" ]]; do
    cd ..
done

if [[ -d .git ]]; then
    echo "[*] found project root: $(pwd)"
else
    echo "[!] could not find project root"
    exit 1
fi

PROJECT_ROOT=$(pwd)
PACKAGE_CLONE_ROOT="${PROJECT_ROOT}/.build/license.scanner/dependencies"

function with_retry {
    local retries=3
    local count=0
    while [[ $count -lt $retries ]]; do
        if "$@"; then return 0; fi
        count=$((count + 1))
    done
    return 1
}

echo "[*] resolving packages..."

with_retry xcodebuild -resolvePackageDependencies \
    -clonedSourcePackagesDirPath "$PACKAGE_CLONE_ROOT" \
    -project "${PROJECT_ROOT}/Example/CENFC.xcodeproj" \
    -scheme CENFC |
    xcbeautify 2>/dev/null

echo "[*] scanning licenses..."

SCANNER_DIR="$PACKAGE_CLONE_ROOT/checkouts"

declare -A PACKAGE_NAME_MAP
PACKAGE_RESOLVED="${PROJECT_ROOT}/Example/CENFC.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved"

if [[ -f "$PACKAGE_RESOLVED" ]]; then
    echo "[*] reading package names from Package.resolved..."
    while IFS= read -r line; do
        if [[ $line =~ \"identity\"[[:space:]]*:[[:space:]]*\"([^\"]+)\" ]]; then
            identity="${match[1]}"
            read -r location_line
            if [[ $location_line =~ \"location\"[[:space:]]*:[[:space:]]*\"[^/]+/([^/\"]+)\" ]]; then
                repo_name="${match[1]}"
                repo_name="${repo_name%.git}"
                PACKAGE_NAME_MAP[$identity]="$repo_name"
            fi
        fi
    done < <(grep -A 1 '"identity"' "$PACKAGE_RESOLVED")
fi

function get_correct_package_name {
    local dir_name=$1
    local lowercase_name=$(echo "$dir_name" | tr '[:upper:]' '[:lower:]')
    if [[ -n "${PACKAGE_NAME_MAP[$lowercase_name]}" ]]; then
        echo "${PACKAGE_NAME_MAP[$lowercase_name]}"
    else
        echo "$dir_name"
    fi
}

SCANNED_LICENSE_CONTENT="# Open Source Licenses\n\n"

if [[ -d "$SCANNER_DIR" ]]; then
    for file in $({ find "$SCANNER_DIR" -maxdepth 2 -name "LICENSE*" -type f | sort; find "$SCANNER_DIR" -maxdepth 2 -name "COPYING*" -type f | sort; }); do
        PACKAGE_NAME=$(get_correct_package_name $(basename $(dirname $file)))
        SCANNED_LICENSE_CONTENT="${SCANNED_LICENSE_CONTENT}\n\n## ${PACKAGE_NAME}\n\n$(cat $file)"
    done
fi

OUTPUT_FILE="${PROJECT_ROOT}/Example/CENFC/Resources/OpenSourceLicenses.md"
echo -e "$SCANNED_LICENSE_CONTENT" >"$OUTPUT_FILE"

echo "[*] checking for incompatible licenses..."

INCOMPATIBLE_LICENSES_KEYWORDS=(
    "GNU General Public License"
    "GNU Lesser General Public License"
    "GNU Affero General Public License"
)

for keyword in "${INCOMPATIBLE_LICENSES_KEYWORDS[@]}"; do
    if grep -q "$keyword" "$OUTPUT_FILE"; then
        echo "[!] found incompatible license: $keyword"
        exit 1
    fi
done

echo "[*] license scan output: $OUTPUT_FILE"
echo "[*] done"
