#!/usr/bin/env bash
set -euo pipefail

values=(
  "$APPLE_CERTIFICATE"
  "$APPLE_CERTIFICATE_PASSWORD"
  "$KEYCHAIN_PASSWORD"
  "$APPLE_ID"
  "$APPLE_PASSWORD"
  "$APPLE_TEAM_ID"
)
present=0
for value in "${values[@]}"; do
  [[ -n "$value" ]] && present=$((present + 1))
done

if (( present == 0 )); then
  echo "Apple signing is not configured; building the macOS bundle without Developer ID notarization."
  exit 0
fi
if (( present != ${#values[@]} )); then
  echo "Configure all Apple signing and notarization secrets or none of them." >&2
  exit 1
fi

certificate_path="$RUNNER_TEMP/apple-certificate.p12"
keychain_path="$RUNNER_TEMP/nd-secure-signing.keychain-db"
printf '%s' "$APPLE_CERTIFICATE" | /usr/bin/base64 -D > "$certificate_path"
security create-keychain -p "$KEYCHAIN_PASSWORD" "$keychain_path"
security set-keychain-settings -lut 21600 "$keychain_path"
security unlock-keychain -p "$KEYCHAIN_PASSWORD" "$keychain_path"
security import "$certificate_path" \
  -k "$keychain_path" \
  -P "$APPLE_CERTIFICATE_PASSWORD" \
  -T /usr/bin/codesign \
  -T /usr/bin/security
security set-key-partition-list \
  -S apple-tool:,apple:,codesign: \
  -s \
  -k "$KEYCHAIN_PASSWORD" \
  "$keychain_path"
security list-keychains -d user -s "$keychain_path"
security default-keychain -d user -s "$keychain_path"

identities_file="$RUNNER_TEMP/apple-identities.txt"
security find-identity -v -p codesigning "$keychain_path" \
  | grep -E '^[[:space:]]*[0-9]+\)' > "$identities_file" || true
identity_count="$(wc -l < "$identities_file" | tr -d ' ')"
if [[ "$identity_count" != "1" ]]; then
  echo "Expected exactly one valid code-signing identity, found $identity_count." >&2
  exit 1
fi
identity="$(sed -E 's/.*"(.*)".*/\1/' "$identities_file")"
[[ -n "$identity" ]] || { echo "Could not determine the Apple signing identity." >&2; exit 1; }
[[ "$identity" == Developer\ ID\ Application:* ]] || {
  echo "Production macOS releases require a Developer ID Application identity; found: $identity" >&2
  exit 1
}

{
  echo "APPLE_SIGNING_IDENTITY=$identity"
  echo "APPLE_ID=$APPLE_ID"
  echo "APPLE_PASSWORD=$APPLE_PASSWORD"
  echo "APPLE_TEAM_ID=$APPLE_TEAM_ID"
} >> "$GITHUB_ENV"
