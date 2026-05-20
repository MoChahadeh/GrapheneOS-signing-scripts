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

YUBIKEY_PKCS11_CFG="${YUBIKEY_PKCS11_CFG:-$(mktemp /dev/shm/pkcs11-XXXXXXXX.cfg)}"
export YUBIKEY_PKCS11_CFG

# Slot line: only emit if YUBIKEY_PKCS11_SLOT is set.
if [[ -n "${YUBIKEY_PKCS11_SLOT:-}" ]]; then
    _slot_line="slot = $YUBIKEY_PKCS11_SLOT"
else
    _slot_line=""
fi

# Render template. Use a temp file then move atomically so concurrent readers
# never see a half-rendered config.
_cfg_tmp="$(mktemp /dev/shm/pkcs11-XXXXXXXX.tmp)"
sed -e "s|@LIBRARY@|$YUBIKEY_PKCS11_MODULE|g" \
    -e "s|@SLOT_LINE@|$_slot_line|g" \
    "$_pkcs11_env_dir/pkcs11.cfg.template" > "$_cfg_tmp"
mv "$_cfg_tmp" "$YUBIKEY_PKCS11_CFG"

# --- build the alias map ----------------------------------------------------
#
# OTATOOLS_PKCS11_ALIAS_MAP is read by the common.py patch to translate the
# AOSP basename (releasekey, platform, ...) to the CKA_LABEL on the token.
#
# Format: "aosp_name1=label1,aosp_name2=label2,..."
#
# Commas are not allowed in CKA_LABELs. The patch does a single-pass split on
# ',' then '='.

_alias_map=""
_first=1
for _name in releasekey platform shared media networkstack bluetooth \
             sdk_sandbox gmscompat_lib nfc avb; do
    _var="YUBIKEY_LABEL_$_name"
    _label="${!_var:-}"
    if [[ -z $_label ]]; then
        echo "pkcs11-env.sh: $_var is unset (set it in yubikey.env)" >&2
        return 1
    fi
    if (( _first )); then _first=0; else _alias_map+=","; fi
    _alias_map+="$_name=$_label"
done
export OTATOOLS_PKCS11_ALIAS_MAP="$_alias_map"

# Convenience accessors for the helper signing scripts (avb, payload, ...).
# These don't go through the alias map -- helpers receive the basename in
# their args and look up the label themselves.
yubikey_label_for() {
    local _name=$1
    local _var="YUBIKEY_LABEL_$_name"
    printf '%s\n' "${!_var}"
}
export -f yubikey_label_for

unset _pkcs11_env_dir _pkcs11_env_file _cfg_tmp _slot_line _alias_map \
      _first _name _var _label
