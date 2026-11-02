#!/bin/zsh
# Builds the aza client library for iPhone, the simulator and Mac, generates the Swift bindings,
# and packs them into swift/Generated/AzaKitFFI.xcframework and swift/Sources/AzaKit/AzaKit.swift.
#
# ONLY="<targets>" builds just those targets (the package then works only on those platforms).
set -euo pipefail
cd "$(dirname "$0")/.."

PROFILE=${PROFILE:-release}
FLAG=$([[ $PROFILE == release ]] && echo --release || echo)
TARGETS=(${=${ONLY:-aarch64-apple-ios aarch64-apple-ios-sim aarch64-apple-darwin}})
OUT=swift/Generated
TARGET=${CARGO_TARGET_DIR:-target}

export IPHONEOS_DEPLOYMENT_TARGET=26.0
export MACOSX_DEPLOYMENT_TARGET=26.0
for t in $TARGETS; do
  cargo build $FLAG -p aza-swift --lib --target $t
done

# The bindings are generated from the Mac library.
cargo build $FLAG -p aza-swift --lib --target aarch64-apple-darwin
rm -rf $OUT && mkdir -p $OUT/headers
cargo run -q -p aza-swift --bin uniffi-bindgen -- generate \
  --library $TARGET/aarch64-apple-darwin/$PROFILE/libaza_kit.dylib --language swift --out-dir $OUT/bindings
mv $OUT/bindings/aza_kitFFI.h $OUT/headers/
cat > $OUT/headers/module.modulemap <<'M'
module aza_kitFFI {
    header "aza_kitFFI.h"
    export *
}
M
mv $OUT/bindings/aza_kit.swift swift/Sources/AzaKit/AzaKit.swift
rm -rf $OUT/bindings

ARGS=()
for t in $TARGETS; do
  ARGS+=(-library $TARGET/$t/$PROFILE/libaza_kit.a -headers $OUT/headers)
done
xcodebuild -create-xcframework $ARGS -output $OUT/AzaKitFFI.xcframework >/dev/null
rm -rf $OUT/headers
echo "Built $OUT/AzaKitFFI.xcframework ($PROFILE: $TARGETS)"
