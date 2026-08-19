#!/usr/bin/env bash
set -euo pipefail

keystore="$RUNNER_TEMP/upload-keystore.jks"
printf '%s' "$ANDROID_KEY_BASE64" | base64 --decode > "$keystore"

mapfile -t apk_files < <(find src-tauri/gen/android -type f -name '*release*.apk' ! -name '*debug*' -print)
mapfile -t aab_files < <(find src-tauri/gen/android -type f -name '*release*.aab' ! -name '*debug*' -print)
if (( ${#apk_files[@]} != 1 )); then
  echo "Expected exactly one release APK, found ${#apk_files[@]}." >&2
  exit 1
fi
if (( ${#aab_files[@]} != 1 )); then
  echo "Expected exactly one release AAB, found ${#aab_files[@]}." >&2
  exit 1
fi

build_tools="$(find "$ANDROID_HOME/build-tools" -mindepth 1 -maxdepth 1 -type d -print | sort -V | tail -n 1)"
[[ -n "$build_tools" ]] || { echo "Android build tools were not found." >&2; exit 1; }

mkdir -p release
aligned_apk="$RUNNER_TEMP/nd-secure-aligned.apk"
signed_apk="release/ND-Secure_${VERSION}_android-arm64.apk"
signed_aab="release/ND-Secure_${VERSION}_android-arm64.aab"

"$build_tools/zipalign" -f -p 4 "${apk_files[0]}" "$aligned_apk"
"$build_tools/apksigner" sign \
  --ks "$keystore" \
  --ks-key-alias "$ANDROID_KEY_ALIAS" \
  --ks-pass env:ANDROID_KEYSTORE_PASSWORD \
  --key-pass env:ANDROID_KEY_PASSWORD \
  --out "$signed_apk" \
  "$aligned_apk"
"$build_tools/apksigner" verify --verbose --print-certs "$signed_apk"

cp "${aab_files[0]}" "$signed_aab"
jarsigner \
  -keystore "$keystore" \
  -storepass:env ANDROID_KEYSTORE_PASSWORD \
  -keypass:env ANDROID_KEY_PASSWORD \
  -sigalg SHA256withRSA \
  -digestalg SHA-256 \
  "$signed_aab" \
  "$ANDROID_KEY_ALIAS"
jarsigner -verify -verbose -certs "$signed_aab"
