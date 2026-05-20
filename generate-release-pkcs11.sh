#!/bin/bash
#
# PKCS#11-aware variant of generate-release.sh.
#
# Drops the on-disk private key dance (decrypt-keys, /dev/shm/key_dir) in
# favor of sourcing pkcs11/pkcs11-env.sh, which renders a SunPKCS11 JVM
# config and exports the alias map + PIN that the AOSP signing pipeline
# needs.
#
# Pre-requisites:
#   - YubiKey provisioned with 10 RSA-4096 keys (see pkcs11/README.md).
#   - pkcs11/yubikey.env present and filled in (see pkcs11/yubikey.env.example).
#   - script/pkcs11/install-patches.sh has been run against build/make.
#   - pkcs11/extract-certs has been run for this device, so
#     keys/$DEVICE/{releasekey,platform,...}.x509.pem and avb_pubkey.pem +
#     avb_pkmd.bin are present.

set -o errexit -o pipefail

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

[[ $# -eq 2 ]] || user_error "expected two arguments: DEVICE BUILD_NUMBER"

chrt -b -p 0 $$

DEVICE=$1
BUILD_NUMBER=$2

PERSISTENT_KEY_DIR=keys/$DEVICE
RELEASE_OUT=releases/$BUILD_NUMBER/release-$DEVICE-$BUILD_NUMBER

# Source PKCS#11 environment. This sets:
#   YUBIKEY_PKCS11_MODULE, YUBIKEY_PKCS11_SLOT (optional), YUBIKEY_PIN
#   YUBIKEY_PKCS11_CFG          (rendered SunPKCS11 config path)
#   YUBIKEY_LABEL_<aosp_name>   (one per signing key)
#   OTATOOLS_PKCS11_ALIAS_MAP   (consumed by the patched common.py)
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=pkcs11/pkcs11-env.sh
source "$script_dir/pkcs11/pkcs11-env.sh"

OLD_PATH="$PATH"
export PATH="$PWD/prebuilts/build-tools/linux-x86/bin:$PATH"
export PATH="$PWD/prebuilts/build-tools/path/linux-x86:$PATH"

TARGET_FILES=$DEVICE-target_files.zip
TARGET_FILES_INPUT=$PWD/releases/$BUILD_NUMBER/$TARGET_FILES

rm -rf $RELEASE_OUT
mkdir -p $RELEASE_OUT
unzip releases/$BUILD_NUMBER/$DEVICE-otatools.zip -d $RELEASE_OUT
cd $RELEASE_OUT
# make soong ignore Android.bp from unpacked otatools to avoid breaking subsequent builds
touch .find-ignore

# Capture the source-tree absolute path to the per-device public-cert
# directory BEFORE we cd into the release output. Then symlink it into the
# release-out so otatools' relative paths resolve. The patched common.py
# never reads .pk8 files when --use_pkcs11_aliases is in effect.
src_key_dir="$script_dir/../$PERSISTENT_KEY_DIR"
KEY_DIR=keys
ln -s "$src_key_dir" $KEY_DIR
trap "rm -f \"$PWD/$KEY_DIR\"" EXIT

export PATH="$PWD/bin:$PATH"

source device/common/clear-factory-images-variables.sh

BUILD=$BUILD_NUMBER
VERSION=$BUILD_NUMBER
DEVICE=$1
PRODUCT=$DEVICE

get_radio_image() {
    grep "require version-$1" OTA/android-info.txt | cut -d '=' -f 2 | tr '[:upper:]' '[:lower:]'
}

unzip $TARGET_FILES_INPUT OTA/android-info.txt

if [[ $DEVICE == @(rango|mustang|blazer|frankel) ]]; then
    BOOTLOADER=$(get_radio_image bootloader)
    RADIO=$(get_radio_image baseband)
    DISABLE_UART=true
    DISABLE_DPM=true
elif [[ $DEVICE == @(stallion|tegu|comet|komodo|caiman|tokay|akita|husky|shiba|felix|tangorpro|lynx|cheetah|panther|bluejay|raven|oriole) ]]; then
    BOOTLOADER=$(get_radio_image bootloader)
    [[ $DEVICE != tangorpro ]] && RADIO=$(get_radio_image baseband)
    DISABLE_UART=true
    DISABLE_FIPS=true
    DISABLE_DPM=true
else
    user_error "$DEVICE is not supported by the release script"
fi

# --- PKCS#11 signing argument bundles ---------------------------------------

AVB_PKMD="$KEY_DIR/avb_pkmd.bin"
AVB_PUBKEY="$KEY_DIR/avb_pubkey.pem"
AVB_ALGORITHM=SHA256_RSA4096

# Pin the AVB signer to the "avb" AOSP key name regardless of which pubkey
# path avbtool passes in (boot, vbmeta, APEX payloads, ...). The helper then
# looks up YUBIKEY_ID_avb / YUBIKEY_LABEL_avb from the env.
export YUBIKEY_AVB_NAME="avb"

AVB_HELPER="$script_dir/pkcs11/yubikey-avb-signer"
PAYLOAD_HELPER="$script_dir/pkcs11/yubikey-payload-signer"

AVB_SIGNING_HELPER_ARG="--signing_helper_with_files=$AVB_HELPER"

# signapk.jar PKCS#11 args. Quote PIN in case it contains shell-special chars.
# `--extra_signapk_args` is shlex-split by the AOSP code.
SIGNAPK_PKCS11_ARGS=$(printf '%s ' \
    -providerClass sun.security.pkcs11.SunPKCS11 \
    -providerArg "$YUBIKEY_PKCS11_CFG" \
    -loadPrivateKeysFromKeyStore PKCS11 \
    -keyStorePin "$YUBIKEY_PIN")

sign_target_files_apks \
    --use_pkcs11_aliases \
    --java_args "$JAVA_PKCS11_ARGS" \
    --extra_signapk_args "$SIGNAPK_PKCS11_ARGS" \
    -o -d "$KEY_DIR" \
    --avb_vbmeta_key "$AVB_PUBKEY" --avb_vbmeta_algorithm $AVB_ALGORITHM \
    --avb_vbmeta_extra_args "$AVB_SIGNING_HELPER_ARG" \
    --avb_apex_extra_args   "$AVB_SIGNING_HELPER_ARG" \
    --avb_boot_extra_args   "$AVB_SIGNING_HELPER_ARG" \
    --avb_init_boot_extra_args "$AVB_SIGNING_HELPER_ARG" \
    --avb_recovery_extra_args  "$AVB_SIGNING_HELPER_ARG" \
    --avb_system_extra_args        "$AVB_SIGNING_HELPER_ARG" \
    --avb_system_other_extra_args  "$AVB_SIGNING_HELPER_ARG" \
    --avb_vendor_extra_args        "$AVB_SIGNING_HELPER_ARG" \
    --avb_dtbo_extra_args          "$AVB_SIGNING_HELPER_ARG" \
    --avb_vbmeta_system_extra_args "$AVB_SIGNING_HELPER_ARG" \
    --avb_vbmeta_vendor_extra_args "$AVB_SIGNING_HELPER_ARG" \
    --extra_apks com.android.adbd.apex="$KEY_DIR/releasekey" \
    --extra_apex_payload_key com.android.adbd.apex="$AVB_PUBKEY" \
    --extra_apks AdServicesApk.apk="$KEY_DIR/releasekey" \
    --extra_apks com.android.adservices.apex="$KEY_DIR/releasekey" \
    --extra_apex_payload_key com.android.adservices.apex="$AVB_PUBKEY" \
    --extra_apks com.android.apex.cts.shim.apex="$KEY_DIR/releasekey" \
    --extra_apex_payload_key com.android.apex.cts.shim.apex="$AVB_PUBKEY" \
    --extra_apks com.android.appsearch.apk.apk="$KEY_DIR/releasekey" \
    --extra_apks com.android.appsearch.apex="$KEY_DIR/releasekey" \
    --extra_apex_payload_key com.android.appsearch.apex="$AVB_PUBKEY" \
    --extra_apks com.android.art.apex="$KEY_DIR/releasekey" \
    --extra_apex_payload_key com.android.art.apex="$AVB_PUBKEY" \
    --extra_apks com.android.art.debug.apex="$KEY_DIR/releasekey" \
    --extra_apex_payload_key com.android.art.debug.apex="$AVB_PUBKEY" \
    --extra_apks Bluetooth.apk="$KEY_DIR/bluetooth" \
    --extra_apks com.android.bt.apex="$KEY_DIR/releasekey" \
    --extra_apex_payload_key com.android.bt.apex="$AVB_PUBKEY" \
    --extra_apks com.android.cellbroadcast.apex="$KEY_DIR/releasekey" \
    --extra_apex_payload_key com.android.cellbroadcast.apex="$AVB_PUBKEY" \
    --extra_apks com.android.compos.apex="$KEY_DIR/releasekey" \
    --extra_apex_payload_key com.android.compos.apex="$AVB_PUBKEY" \
    --extra_apks com.android.configinfrastructure.apex="$KEY_DIR/releasekey" \
    --extra_apex_payload_key com.android.configinfrastructure.apex="$AVB_PUBKEY" \
    --extra_apks com.android.conscrypt.apex="$KEY_DIR/releasekey" \
    --extra_apex_payload_key com.android.conscrypt.apex="$AVB_PUBKEY" \
    --extra_apks com.android.crashrecovery.apex="$KEY_DIR/releasekey" \
    --extra_apex_payload_key com.android.crashrecovery.apex="$AVB_PUBKEY" \
    --extra_apks com.android.devicelock.apex="$KEY_DIR/releasekey" \
    --extra_apex_payload_key com.android.devicelock.apex="$AVB_PUBKEY" \
    --extra_apks com.android.extservices.apex="$KEY_DIR/releasekey" \
    --extra_apex_payload_key com.android.extservices.apex="$AVB_PUBKEY" \
    --extra_apks com.android.hardware.biometrics.face.virtual.apex="$KEY_DIR/releasekey" \
    --extra_apex_payload_key com.android.hardware.biometrics.face.virtual.apex="$AVB_PUBKEY" \
    --extra_apks com.android.hardware.biometrics.fingerprint.virtual.apex="$KEY_DIR/releasekey" \
    --extra_apex_payload_key com.android.hardware.biometrics.fingerprint.virtual.apex="$AVB_PUBKEY" \
    --extra_apks com.android.hardware.cas.apex="$KEY_DIR/releasekey" \
    --extra_apex_payload_key com.android.hardware.cas.apex="$AVB_PUBKEY" \
    --extra_apks HealthConnectBackupRestore.apk="$KEY_DIR/releasekey" \
    --extra_apks HealthConnectController.apk="$KEY_DIR/releasekey" \
    --extra_apks com.android.healthfitness.apex="$KEY_DIR/releasekey" \
    --extra_apex_payload_key com.android.healthfitness.apex="$AVB_PUBKEY" \
    --extra_apks com.android.i18n.apex="$KEY_DIR/releasekey" \
    --extra_apex_payload_key com.android.i18n.apex="$AVB_PUBKEY" \
    --extra_apks com.android.ipsec.apex="$KEY_DIR/releasekey" \
    --extra_apex_payload_key com.android.ipsec.apex="$AVB_PUBKEY" \
    --extra_apks com.android.media.apex="$KEY_DIR/releasekey" \
    --extra_apex_payload_key com.android.media.apex="$AVB_PUBKEY" \
    --extra_apks com.android.media.swcodec.apex="$KEY_DIR/releasekey" \
    --extra_apex_payload_key com.android.media.swcodec.apex="$AVB_PUBKEY" \
    --extra_apks com.android.mediaprovider.apex="$KEY_DIR/releasekey" \
    --extra_apex_payload_key com.android.mediaprovider.apex="$AVB_PUBKEY" \
    --extra_apks com.android.neuralnetworks.apex="$KEY_DIR/releasekey" \
    --extra_apex_payload_key com.android.neuralnetworks.apex="$AVB_PUBKEY" \
    --extra_apks com.android.nfcservices.apex="$KEY_DIR/releasekey" \
    --extra_apex_payload_key com.android.nfcservices.apex="$AVB_PUBKEY" \
    --extra_apks FederatedCompute.apk="$KEY_DIR/releasekey" \
    --extra_apks com.android.ondevicepersonalization.apex="$KEY_DIR/releasekey" \
    --extra_apex_payload_key com.android.ondevicepersonalization.apex="$AVB_PUBKEY" \
    --extra_apks com.android.os.statsd.apex="$KEY_DIR/releasekey" \
    --extra_apex_payload_key com.android.os.statsd.apex="$AVB_PUBKEY" \
    --extra_apks SafetyCenterResources.apk="$KEY_DIR/releasekey" \
    --extra_apks com.android.permission.apex="$KEY_DIR/releasekey" \
    --extra_apex_payload_key com.android.permission.apex="$AVB_PUBKEY" \
    --extra_apks com.android.profiling.apex="$KEY_DIR/releasekey" \
    --extra_apex_payload_key com.android.profiling.apex="$AVB_PUBKEY" \
    --extra_apks com.android.resolv.apex="$KEY_DIR/releasekey" \
    --extra_apex_payload_key com.android.resolv.apex="$AVB_PUBKEY" \
    --extra_apks com.android.rkpd.apex="$KEY_DIR/releasekey" \
    --extra_apex_payload_key com.android.rkpd.apex="$AVB_PUBKEY" \
    --extra_apks com.android.runtime.apex="$KEY_DIR/releasekey" \
    --extra_apex_payload_key com.android.runtime.apex="$AVB_PUBKEY" \
    --extra_apks com.android.scheduling.apex="$KEY_DIR/releasekey" \
    --extra_apex_payload_key com.android.scheduling.apex="$AVB_PUBKEY" \
    --extra_apks com.android.sdkext.apex="$KEY_DIR/releasekey" \
    --extra_apex_payload_key com.android.sdkext.apex="$AVB_PUBKEY" \
    --extra_apks com.android.telephonycore.apex="$KEY_DIR/releasekey" \
    --extra_apex_payload_key com.android.telephonycore.apex="$AVB_PUBKEY" \
    --extra_apks ServiceConnectivityResources.apk="$KEY_DIR/releasekey" \
    --extra_apks com.android.tethering.apex="$KEY_DIR/releasekey" \
    --extra_apex_payload_key com.android.tethering.apex="$AVB_PUBKEY" \
    --extra_apks com.android.tzdata.apex="$KEY_DIR/releasekey" \
    --extra_apex_payload_key com.android.tzdata.apex="$AVB_PUBKEY" \
    --extra_apks com.android.uprobestats.apex="$KEY_DIR/releasekey" \
    --extra_apex_payload_key com.android.uprobestats.apex="$AVB_PUBKEY" \
    --extra_apks ServiceUwbResources.apk="$KEY_DIR/releasekey" \
    --extra_apks com.android.uwb.apex="$KEY_DIR/releasekey" \
    --extra_apex_payload_key com.android.uwb.apex="$AVB_PUBKEY" \
    --extra_apks com.android.virt.apex="$KEY_DIR/releasekey" \
    --extra_apex_payload_key com.android.virt.apex="$AVB_PUBKEY" \
    --extra_apks OsuLogin.apk="$KEY_DIR/releasekey" \
    --extra_apks ServiceWifiResources.apk="$KEY_DIR/releasekey" \
    --extra_apks WifiDialog.apk="$KEY_DIR/releasekey" \
    --extra_apks com.android.wifi.apex="$KEY_DIR/releasekey" \
    --extra_apex_payload_key com.android.wifi.apex="$AVB_PUBKEY" \
    --extra_apks com.google.pixel.camera.hal.apex="$KEY_DIR/releasekey" \
    --extra_apex_payload_key com.google.pixel.camera.hal.apex="$AVB_PUBKEY" \
    $TARGET_FILES_INPUT $TARGET_FILES

# OTA package. Outer signing (whole-file mode) uses signapk.jar, so it inherits
# the PKCS#11 keystore args via --extra_signapk_args. The payload itself is
# signed by openssl-equivalent code that we override with --payload_signer.
ota_from_target_files \
    --use_pkcs11_aliases \
    --java_args "$JAVA_PKCS11_ARGS" \
    --extra_signapk_args "$SIGNAPK_PKCS11_ARGS" \
    --payload_signer "$PAYLOAD_HELPER" \
    --payload_signer_args "-label releasekey" \
    --payload_signer_maximum_signature_size 512 \
    -k "$KEY_DIR/releasekey" $TARGET_FILES \
    $DEVICE-ota_update-$BUILD_NUMBER.zip
script/generate-metadata $DEVICE-ota_update-$BUILD_NUMBER.zip

img_from_target_files $TARGET_FILES $DEVICE-img-$BUILD_NUMBER.zip

source device/common/generate-factory-images-common.sh

if [[ $DEVICE == @(rango|mustang|blazer|frankel) ]]; then
    MAX_DOWNLOAD_SIZE=0x10000000
else
    MAX_DOWNLOAD_SIZE=0xf900000
fi

fastboot -S $MAX_DOWNLOAD_SIZE optimize-factory-image $DEVICE-factory-$BUILD_NUMBER.zip $DEVICE-install-$BUILD_NUMBER

if [[ -f "$KEY_DIR/id_ed25519" ]]; then
    export PATH="$OLD_PATH"
    ssh-keygen -Y sign -n "factory images" -f "$KEY_DIR/id_ed25519" $DEVICE-install-$BUILD_NUMBER.zip
fi
