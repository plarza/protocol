#!/bin/zsh
# Releases AzaKit for apps to fetch with SwiftPM, from github.com/plarza/protocol:
#
#   scripts/release-swift.sh 0.1.0
#
# Builds it (scripts/build-swift.sh), points Package.swift at this version's XCFramework by URL
# and checksum, commits that with the generated bindings, tags the commit, pushes it to every
# remote and attaches the XCFramework to a GitHub release of the tag.
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION=${1:?usage: scripts/release-swift.sh <version>}
ZIP=AzaKitFFI.xcframework.zip

./scripts/build-swift.sh
WORK=$(mktemp -d)
trap 'rm -rf $WORK' EXIT
ditto -c -k --sequesterRsrc --keepParent swift/Generated/AzaKitFFI.xcframework $WORK/$ZIP
CHECKSUM=$(swift package compute-checksum $WORK/$ZIP)

sed -i '' -E \
  -e "s#releases/download/[^/]+/$ZIP#releases/download/$VERSION/$ZIP#" \
  -e "s#checksum: \"[0-9a-f]{64}\"#checksum: \"$CHECKSUM\"#" \
  Package.swift
git add Package.swift swift/Sources/AzaKit/AzaKit.swift
git commit -q -m "AzaKit $VERSION"
git tag $VERSION
for remote in $(git remote); do git push -q $remote HEAD $VERSION; done
gh release create $VERSION $WORK/$ZIP --repo plarza/protocol --title "AzaKit $VERSION" --notes "AzaKit $VERSION for iOS and macOS."
echo "Released AzaKit $VERSION"
