#!/bin/bash
#
# Apply (or revert) the PKCS#11 patch against an AOSP / GrapheneOS source tree.
#
# Run from the repo root (the directory containing build/, external/, script/,
# etc.). Run after every `repo sync` to keep the patch fresh.
#
# Usage:
#   script/pkcs11/install-patches.sh apply     # default
#   script/pkcs11/install-patches.sh revert

set -o errexit -o nounset -o pipefail

action=${1:-apply}

repo_root=$(pwd)
patch_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/aosp-patches" && pwd)

target_project="build/make"

if [[ ! -d "$repo_root/$target_project" ]]; then
    echo "install-patches.sh: $target_project not found under $repo_root" >&2
    echo "Run this script from the root of your AOSP source tree." >&2
    exit 1
fi

apply_one() {
    local patch=$1
    echo ">>> $action $(basename "$patch") in $target_project"

    # `git apply --check` would tell us if the patch is fresh, but a stricter
    # idempotency test is: try to apply in --reverse --check first; if it
    # succeeds, the patch is already applied.
    cd "$repo_root/$target_project"
    if [[ $action == apply ]]; then
        if git apply --check --reverse "$patch" 2>/dev/null; then
            echo "    already applied -- skipping"
        else
            git apply --3way "$patch"
        fi
    elif [[ $action == revert ]]; then
        if git apply --check "$patch" 2>/dev/null; then
            echo "    not applied -- skipping"
        else
            git apply --reverse "$patch"
        fi
    else
        echo "install-patches.sh: unrecognized action '$action' (use apply or revert)" >&2
        exit 1
    fi
}

for patch in "$patch_dir"/*.patch; do
    apply_one "$patch"
done

echo
echo "done."
