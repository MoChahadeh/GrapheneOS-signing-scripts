#!/bin/bash
#
# PKCS#11-aware variant of generate-delta.sh. See generate-release-pkcs11.sh
# for prerequisites.

set -o errexit -o nounset -o pipefail

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

[[ $# -eq 3 ]] || user_error "expected 3 arguments (device, source and target version)"

chrt -b -p 0 $$

DEVICE=$1
OLD=$2
NEW=$3

PERSISTENT_KEY_DIR=keys/$DEVICE

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=pkcs11/pkcs11-env.sh
source "$script_dir/pkcs11/pkcs11-env.sh"

export PATH="$PWD/prebuilts/build-tools/linux-x86/bin:$PATH"
export PATH="$PWD/prebuilts/build-tools/path/linux-x86:$PATH"
export PATH="$PWD/releases/$NEW/release-$DEVICE-$NEW/bin:$PATH"

PAYLOAD_HELPER="$script_dir/pkcs11/yubikey-payload-signer"

SIGNAPK_PKCS11_ARGS=$(printf '%s ' \
    -providerClass sun.security.pkcs11.SunPKCS11 \
    -providerArg "$YUBIKEY_PKCS11_CFG" \
    -loadPrivateKeysFromKeyStore PKCS11 \
    -keyStorePin "$YUBIKEY_PIN")

cd "releases/$NEW"

ota_from_target_files \
    --use_pkcs11_aliases \
    --java_args "$JAVA_PKCS11_ARGS" \
    --extra_signapk_args "$SIGNAPK_PKCS11_ARGS" \
    --payload_signer "$PAYLOAD_HELPER" \
    --payload_signer_args "-label releasekey" \
    --payload_signer_maximum_signature_size 512 \
    -k "$PWD/../../$PERSISTENT_KEY_DIR/releasekey" \
    -i "../$OLD/release-$DEVICE-$OLD/$DEVICE-target_files.zip" \
    "release-$DEVICE-$NEW/$DEVICE-target_files.zip" \
    "$DEVICE-incremental-$OLD-$NEW.zip"
