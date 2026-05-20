# shellcheck shell=bash
#
# Sources yubikey.env, validates the configuration, renders pkcs11.cfg from
# the template, and exports helper variables consumed by the rest of the
# PKCS#11 signing flow. Source this file -- do not execute it.

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    echo "pkcs11-env.sh must be sourced, not executed" >&2
    exit 1
fi

_pkcs11_env_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Locate yubikey.env. Caller may override via $YUBIKEY_ENV.
if [[ -n "${YUBIKEY_ENV:-}" ]]; then
    _pkcs11_env_file="$YUBIKEY_ENV"
elif [[ -f "$_pkcs11_env_dir/yubikey.env" ]]; then
    _pkcs11_env_file="$_pkcs11_env_dir/yubikey.env"
else
    echo "pkcs11-env.sh: no yubikey.env found at $_pkcs11_env_dir/yubikey.env" >&2
    echo "Copy pkcs11/yubikey.env.example, edit it, then re-run." >&2
    return 1
fi

# shellcheck disable=SC1090
source "$_pkcs11_env_file"

# --- validate ---------------------------------------------------------------

if [[ -z "${YUBIKEY_PKCS11_MODULE:-}" ]]; then
    echo "pkcs11-env.sh: YUBIKEY_PKCS11_MODULE is unset" >&2
    return 1
fi

if [[ ! -e "$YUBIKEY_PKCS11_MODULE" ]]; then
    echo "pkcs11-env.sh: PKCS#11 module not found: $YUBIKEY_PKCS11_MODULE" >&2
    return 1
fi

# --- prompt for PIN if not provided -----------------------------------------

if [[ -z "${YUBIKEY_PIN:-}" ]]; then
    read -rsp "Enter YubiKey PIN: " YUBIKEY_PIN
    echo
    export YUBIKEY_PIN
fi

# --- render pkcs11.cfg from template ----------------------------------------

# Prefer /dev/shm on Linux (tmpfs); fall back to $TMPDIR/tmp elsewhere (macOS).
_pkcs11_tmpdir="${TMPDIR:-/tmp}"
[[ -d /dev/shm ]] && _pkcs11_tmpdir=/dev/shm

YUBIKEY_PKCS11_CFG="${YUBIKEY_PKCS11_CFG:-$(mktemp "$_pkcs11_tmpdir/pkcs11-XXXXXXXX.cfg")}"
export YUBIKEY_PKCS11_CFG

# Slot line: only emit if YUBIKEY_PKCS11_SLOT is set.
if [[ -n "${YUBIKEY_PKCS11_SLOT:-}" ]]; then
    _slot_line="slot = $YUBIKEY_PKCS11_SLOT"
else
    _slot_line=""
fi

# Render template. Use a temp file then move atomically so concurrent readers
# never see a half-rendered config.
_cfg_tmp="$(mktemp "$_pkcs11_tmpdir/pkcs11-XXXXXXXX.tmp")"
sed -e "s|@LIBRARY@|$YUBIKEY_PKCS11_MODULE|g" \
    -e "s|@SLOT_LINE@|$_slot_line|g" \
    "$_pkcs11_env_dir/pkcs11.cfg.template" > "$_cfg_tmp"
mv "$_cfg_tmp" "$YUBIKEY_PKCS11_CFG"

# --- validate per-key configuration + build the alias map -------------------
#
# Each AOSP signing key needs at least one identifier:
#   - YUBIKEY_LABEL_<name> (CKA_LABEL of the *certificate* on the token --
#     required for SunPKCS11 / signapk.jar, which uses the cert label as the
#     keystore alias);
#   - YUBIKEY_ID_<name> (CKA_ID hex -- used by the AVB and payload helpers
#     via pkcs11-tool, and the only deterministic identifier when a slot's
#     cert and private key have different CKA_LABELs, as on OpenSC PIV).
#
# OTATOOLS_PKCS11_ALIAS_MAP is consumed by the common.py patch when signing
# APKs / OTA packages via signapk.jar. It contains only the keys that have a
# label set; keys configured by ID alone are skipped here (the helpers read
# YUBIKEY_ID_* directly).

_alias_map=""
_first=1
for _name in releasekey platform shared media networkstack bluetooth \
             sdk_sandbox gmscompat_lib nfc avb; do
    _label_var="YUBIKEY_LABEL_$_name"
    _id_var="YUBIKEY_ID_$_name"
    _label="${!_label_var:-}"
    _id="${!_id_var:-}"
    if [[ -z $_label && -z $_id ]]; then
        echo "pkcs11-env.sh: neither $_label_var nor $_id_var is set for '$_name'" >&2
        echo "  set one of them in yubikey.env (label is required for APK/OTA-package signing keys)" >&2
        return 1
    fi
    if [[ -n $_label ]]; then
        if (( _first )); then _first=0; else _alias_map+=","; fi
        _alias_map+="$_name=$_label"
    fi
done
export OTATOOLS_PKCS11_ALIAS_MAP="$_alias_map"

# --- JVM args required for SunPKCS11 reflection -----------------------------
#
# signapk.jar runs as an unnamed module and instantiates SunPKCS11 via
# reflection. Starting with JDK 9 the jdk.crypto.cryptoki module no longer
# exports sun.security.pkcs11 to unnamed modules by default, so any plain
# `java -jar signapk.jar -providerClass sun.security.pkcs11.SunPKCS11 ...`
# invocation fails with:
#
#   java.lang.IllegalAccessException: class com.android.signapk.SignApk
#       cannot access class sun.security.pkcs11.SunPKCS11
#       (in module jdk.crypto.cryptoki) because module jdk.crypto.cryptoki
#       does not export sun.security.pkcs11 to unnamed module @...
#
# --add-exports re-opens the package for public reflection; --add-opens
# additionally allows setAccessible(true) in case the JVM/signapk version
# falls back to deeper reflection. Both are safe to set together.
JAVA_PKCS11_ARGS="-Xmx4096m"
JAVA_PKCS11_ARGS+=" --add-exports=jdk.crypto.cryptoki/sun.security.pkcs11=ALL-UNNAMED"
JAVA_PKCS11_ARGS+=" --add-opens=jdk.crypto.cryptoki/sun.security.pkcs11=ALL-UNNAMED"
export JAVA_PKCS11_ARGS

unset _pkcs11_env_dir _pkcs11_env_file _cfg_tmp _slot_line _alias_map \
      _first _name _label_var _id_var _label _id _pkcs11_tmpdir
