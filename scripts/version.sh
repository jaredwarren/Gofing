#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION_FILE="$DIR/VERSION"
BUILD_DIR="$DIR/build"
HASH_FILE="$BUILD_DIR/.last_build_hash"

mkdir -p "$BUILD_DIR"

# Read existing version or initialize
if [ -f "$VERSION_FILE" ]; then
  CURRENT_VERSION=$(tr -d ' \t\r\n' < "$VERSION_FILE")
else
  CURRENT_VERSION="1.0.0"
fi

if [[ ! "$CURRENT_VERSION" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
  CURRENT_VERSION="1.0.0"
fi

MAJOR="${BASH_REMATCH[1]}"
MINOR="${BASH_REMATCH[2]}"
PATCH="${BASH_REMATCH[3]}"

# Compute fingerprint of git commit + tracked diff + untracked files (excluding VERSION & build directory)
GIT_HEAD=$(git -C "$DIR" rev-parse HEAD 2>/dev/null || echo "no-git")
TRACKED_DIFF=$(git -C "$DIR" diff HEAD -- ':(exclude)VERSION' 2>/dev/null | shasum -a 256 | awk '{print $1}')
UNTRACKED_HASH=$(git -C "$DIR" ls-files --others --exclude-standard 2>/dev/null | grep -v '^VERSION$' | while read -r f; do [ -f "$DIR/$f" ] && shasum -a 256 "$DIR/$f"; done | shasum -a 256 | awk '{print $1}')
FINGERPRINT=$(printf "%s-%s-%s" "$GIT_HEAD" "$TRACKED_DIFF" "$UNTRACKED_HASH" | shasum -a 256 | awk '{print $1}')

LAST_HASH=""
if [ -f "$HASH_FILE" ]; then
  LAST_HASH=$(tr -d ' \t\r\n' < "$HASH_FILE")
fi

# If there are changes since last build (or this is the initial build with this system)
if [ -n "$LAST_HASH" ] && [ "$FINGERPRINT" != "$LAST_HASH" ]; then
  PATCH=$((PATCH + 1))
  CURRENT_VERSION="${MAJOR}.${MINOR}.${PATCH}"
  echo "$CURRENT_VERSION" > "$VERSION_FILE"
  echo "$FINGERPRINT" > "$HASH_FILE"
elif [ -z "$LAST_HASH" ]; then
  # First time initializing the hash file with the current version
  echo "$CURRENT_VERSION" > "$VERSION_FILE"
  echo "$FINGERPRINT" > "$HASH_FILE"
fi

BUILD_TIME=$(date "+%Y-%m-%d %H:%M:%S")

case "${1:-}" in
  --version)
    echo "$CURRENT_VERSION"
    ;;
  --time)
    echo "$BUILD_TIME"
    ;;
  --env)
    printf 'VERSION="%s"\nBUILD_TIME="%s"\n' "$CURRENT_VERSION" "$BUILD_TIME"
    ;;
  --ldflags)
    echo "-X 'github.com/jaredwarren/Gofing/pkg/version.Version=$CURRENT_VERSION' -X 'github.com/jaredwarren/Gofing/pkg/version.BuildTime=$BUILD_TIME'"
    ;;
  *)
    echo "$CURRENT_VERSION ($BUILD_TIME)"
    ;;
esac
