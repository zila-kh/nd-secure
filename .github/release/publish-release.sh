#!/usr/bin/env bash
set -euo pipefail

windows="release/ND-Secure_${VERSION}_windows-x64-setup.exe"
macos="release/ND-Secure_${VERSION}_macos-arm64.dmg"
test -s "$windows"
test -s "$macos"

if [[ "$ANDROID_ENABLED" == "true" ]]; then
  test -s "release/ND-Secure_${VERSION}_android-arm64.apk"
  test -s "release/ND-Secure_${VERSION}_android-arm64.aab"
  android_status="Production-signed Android APK and AAB are included."
else
  test -s "release/ND-Secure_${VERSION}_android-arm64-unsigned.apk"
  android_status="Unsigned release-mode Android APK is included for downstream/local signing; it is not installable until signed."
fi

(
  cd release
  find . -maxdepth 1 -type f ! -name SHA256SUMS -print0 \
    | sort -z \
    | xargs -0 sha256sum \
    | sed 's#  \./#  #'
) > release/SHA256SUMS
test -s release/SHA256SUMS

notes_file="$RUNNER_TEMP/release-notes.md"
cat > "$notes_file" <<NOTES
Automated ND Secure release from \`main\`.

- Source commit: \`$GITHUB_SHA\`
- Windows: x64 NSIS installer
- macOS: Apple Silicon DMG
- Android: $android_status
- Integrity: verify downloads with \`SHA256SUMS\`

The repository's documented security-review limitations still apply to this build.
NOTES

existing_tag_sha="$(git rev-list -n 1 "$TAG" 2>/dev/null || true)"
if [[ -n "$existing_tag_sha" && "$existing_tag_sha" != "$GITHUB_SHA" ]]; then
  echo "Refusing to update $TAG because it points to $existing_tag_sha instead of $GITHUB_SHA." >&2
  exit 1
fi

if gh release view "$TAG" >/dev/null 2>&1; then
  gh release upload "$TAG" release/* --clobber
  gh release edit "$TAG" \
    --title "ND Secure $VERSION" \
    --notes-file "$notes_file" \
    --draft=false \
    --latest
else
  gh release create "$TAG" release/* \
    --target "$GITHUB_SHA" \
    --title "ND Secure $VERSION" \
    --notes-file "$notes_file" \
    --latest
fi
