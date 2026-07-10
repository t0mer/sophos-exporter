#!/usr/bin/env bash
# Compute the next date-based version YYYY.M.PATCH (no leading zero on the month).
# Finds the latest tag for the current YYYY.M and increments PATCH; starts at .0.
# Tags are pushed as v<version> (e.g. v2026.7.0).
set -euo pipefail
TODAY="$(date +%Y.%-m)"
LATEST="$(git tag --list "v${TODAY}.*" 2>/dev/null | sed 's/^v//' | sort -V | tail -1)"
if [ -z "$LATEST" ]; then
  echo "${TODAY}.0"
else
  PATCH="${LATEST##*.}"
  echo "${TODAY}.$((PATCH + 1))"
fi
