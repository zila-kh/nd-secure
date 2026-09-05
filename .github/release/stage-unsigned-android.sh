#!/usr/bin/env bash
set -euo pipefail

mapfile -t apk_files < <(find src-tauri/gen/android -type f -name '*release*.apk' ! -name '*debug*' -print)
if (( ${#apk_files[@]} != 1 )); then
  echo "Expected exactly one unsigned release APK, found ${#apk_files[@]}." >&2
  exit 1
fi

build_tools="$(find "$ANDROID_HOME/build-tools" -mindepth 1 -maxdepth 1 -type d -print | sort -V | tail -n 1)"
[[ -n "$build_tools" ]] || { echo "Android build tools were not found." >&2; exit 1; }

if "$build_tools/apksigner" verify "${apk_files[0]}" >/dev/null 2>&1; then
  echo "Expected the fallback Android APK to be unsigned, but a valid APK signature was found." >&2
  exit 1
fi

mkdir -p release
cp "${apk_files[0]}" "release/ND-Secure_${VERSION}_android-arm64-unsigned.apk"
