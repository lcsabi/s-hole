#!/bin/sh
# Prints the Go release (for example 1.26.9) of the golang builder image that
# the Dockerfile pins. CI, the weekly scan, and the release build with this
# release, so the archives and the image use the same Go. Dependabot moves
# the pin with the image digest. actions/setup-go downloads an exact release
# from go.dev when its own version list does not have it yet.
#
# Usage: sh .github/go-version.sh [Dockerfile]
set -eu

v=$(sed -n 's/^FROM .*golang:\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)-.*/\1/p' "${1:-Dockerfile}")
if [ -z "$v" ] || [ "$(printf '%s\n' "$v" | wc -l)" -ne 1 ]; then
  echo "go-version.sh: want one golang:X.Y.Z builder image in the Dockerfile" >&2
  exit 1
fi
printf '%s\n' "$v"
