#!/bin/bash
# =============================================================================
#  NetScope -- build a sideloadable .ipa (run on macOS with Xcode installed,
#  or let .github/workflows/build-ipa.yml do it in the cloud)
#
#  Usage:
#    ./Scripts/build-ipa.sh                     # unsigned .ipa (LiveContainer / TrollStore / Sideloadly)
#    TEAM_ID=MPZ586FDM5 ./Scripts/build-ipa.sh  # signed with your Apple ID certificate
#
#  Output: build/NetScope.ipa
# =============================================================================
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

OUT_DIR="build"
SCHEME="NetScope"
PROJECT="NetScope.xcodeproj"
ARCHIVE="$OUT_DIR/NetScope.xcarchive"
APP="$OUT_DIR/NetScope.app"
IPA="$OUT_DIR/NetScope.ipa"

mkdir -p "$OUT_DIR"
rm -rf "$APP" "$IPA" "$OUT_DIR/Payload"

if ! command -v xcodebuild >/dev/null 2>&1; then
  echo "  [!] xcodebuild not found -- this must run on a macOS system with Xcode installed." >&2
  echo "      On macOS Monterey without Xcode, use GitHub Actions: see .github/workflows/build-ipa.yml" >&2
  exit 1
fi

echo "== 1/3 Building NetScope (Release, device arm64) =="
SIGN_ARGS=(CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO CODE_SIGN_IDENTITY="")
if [ -n "${TEAM_ID:-}" ]; then
  SIGN_ARGS=(DEVELOPMENT_TEAM="$TEAM_ID" CODE_SIGN_STYLE=Automatic)
fi

xcodebuild \
  -project "$PROJECT" \
  -scheme "$SCHEME" \
  -configuration Release \
  -sdk iphoneos \
  -derivedDataPath "$OUT_DIR/dd" \
  -archivePath "$ARCHIVE" \
  "${SIGN_ARGS[@]}" \
  archive

echo "== 2/3 Extracting NetScope.app =="
cp -R "$ARCHIVE/Products/Applications/NetScope.app" "$APP"

echo "== 3/3 Packaging NetScope.ipa =="
mkdir -p "$OUT_DIR/Payload"
cp -R "$APP" "$OUT_DIR/Payload/"
(cd "$OUT_DIR" && zip -qry "NetScope.ipa" Payload)
rm -rf "$OUT_DIR/Payload"

echo
echo "  ✓ $IPA"
echo "    size : $(du -h "$IPA" | cut -f1)"
echo
echo "  Install on iPhone:"
echo "    • LiveContainer  -> import NetScope.ipa -> launch"
echo "    • Sideloadly / AltStore -> install with your Apple ID"
echo "    • TrollStore (iOS 14.0-16.6.1 / 17.0) -> install directly"
