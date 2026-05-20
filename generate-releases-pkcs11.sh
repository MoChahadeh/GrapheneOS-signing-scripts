#!/bin/bash
#
# PKCS#11-aware variant of generate-releases.sh.
#
# Unlike the upstream version this runs serially -- the YubiKey can only do
# one signing operation at a time, so parallelism here would just queue up
# blocked workers and waste memory. If you have multiple YubiKeys with
# identical keysets, run multiple shells in parallel each with its own
# yubikey.env pointing to a different token.

set -o errexit -o nounset -o pipefail

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

[[ $# -eq 1 ]] || user_error "expected 1 argument: BUILD_NUMBER"

BUILD_NUMBER=$1

# Source PKCS#11 env once so the PIN is collected interactively just one time
# at the top of the run. All children inherit it.
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=pkcs11/pkcs11-env.sh
source "$script_dir/pkcs11/pkcs11-env.sh"

chrt -b -p 0 $$

export TMPDIR="${OUT:-$PWD/delta-generation}"

devices=(
    stallion rango mustang blazer frankel tegu comet komodo caiman
    tokay akita husky shiba felix tangorpro lynx cheetah panther
    bluejay raven oriole
)

for device in "${devices[@]}"; do
    echo -e "\n>>> $(tput setaf 3)Signing release for $device$(tput sgr0)"
    "$script_dir/generate-release-pkcs11.sh" "$device" "$BUILD_NUMBER"
done
