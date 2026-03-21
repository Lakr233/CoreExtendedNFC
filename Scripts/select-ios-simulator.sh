#!/bin/zsh

set -euo pipefail

json=$(xcrun simctl list devices available -j)

selection=$(python3 -c '
import json
import re
import sys

def version_key(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", version))

data = json.loads(sys.argv[1])
ios_runtimes = []

for runtime_name, devices in data.get("devices", {}).items():
    if "iOS" not in runtime_name:
        continue

    runtime_version = runtime_name.rsplit(".", 1)[-1]
    ios_runtimes.append((version_key(runtime_version), devices))

if not ios_runtimes:
    raise SystemExit("No iOS Simulator runtimes found")

ios_runtimes.sort(key=lambda item: item[0], reverse=True)

for _, devices in ios_runtimes:
    for prefix in ("iPhone", "iPad"):
        for device in devices:
            if not device.get("isAvailable", False):
                continue

            name = device.get("name", "")
            if name.startswith(prefix):
                print("platform=iOS Simulator,id={}\t{}".format(device["udid"], name))
                raise SystemExit(0)

raise SystemExit("No available iOS Simulator devices found")
' "$json")

destination=${selection%%$'\t'*}
name=${selection#*$'\t'}

echo "Selected simulator: $name" >&2
echo "$destination"
