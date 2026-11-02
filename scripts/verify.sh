#!/usr/bin/env bash
# Checks a commit exactly as it ships: from a clean checkout of it, so nothing uncommitted in
# this one counts. The pre-push hook runs it on every push to main; CI only builds the image.
# The checkout shares this one's build directory, so it is quick.
set -euo pipefail

revision=$(git rev-parse "${1:-HEAD}")
root=$(git rev-parse --show-toplevel)
# The physical path: macOS's temporary directory is a symlink.
checkout=$(cd "$(mktemp -d)" && pwd -P)/protocol
git worktree add --detach --quiet "$checkout" "$revision"
trap 'git -C "$root" worktree remove --force "$checkout"' EXIT
export CARGO_TARGET_DIR="$root/target"

cd "$checkout"
echo "Verifying ${revision::12}…"
cargo verus verify --manifest-path crates/aza-core/Cargo.toml
cargo fmt --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
