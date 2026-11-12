#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
if ! command -v xcodebuild >/dev/null; then
  echo 'Install Xcode and select it with xcode-select first.' >&2; exit 1
fi
mkdir -p Verification
xcodebuild -version | tee Verification/xcode-version.txt
plutil -lint Info.plist Resources/PrivacyInfo.xcprivacy NetScope.xcodeproj/project.pbxproj
xcodebuild -list -project NetScope.xcodeproj | tee Verification/project-list.txt
# Compiles without device-signing credentials. Does not run tests or certify release readiness.
xcodebuild -project NetScope.xcodeproj -scheme NetScope -configuration Debug \
  -sdk iphonesimulator -destination 'generic/platform=iOS Simulator' \
  -derivedDataPath .derivedData CODE_SIGNING_ALLOWED=NO build \
  2>&1 | tee Verification/build.log
cat <<'MESSAGE'
Next: xcodebuild -showdestinations -project NetScope.xcodeproj -scheme NetScope
Choose an installed simulator and run:
  xcodebuild -project NetScope.xcodeproj -scheme NetScope -destination 'platform=iOS Simulator,id=YOUR_SIMULATOR_UDID' test
Then select your signing team and test networking on a physical iPhone.
MESSAGE
