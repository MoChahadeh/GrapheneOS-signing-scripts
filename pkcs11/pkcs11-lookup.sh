# shellcheck shell=bash
#
# Shared helpers for resolving an AOSP key name to PKCS#11 lookup arguments.
#
# Sourcing this file defines `pkcs11_resolve_lookup <aosp_name>`, which sets
# the `pkcs11_lookup_args` array to a `--id <hex>` pair (preferred) or
# `--label <label>` pair (fallback). The array is fit to splat directly into
# a pkcs11-tool invocation.

# Prefer YUBIKEY_ID_<name> over YUBIKEY_LABEL_<name>: CKA_ID is the same on
# the cert, public key, and private key for a given slot, while CKA_LABEL
# can differ between those object types (e.g. OpenSC's PIV driver labels
# them "PIV AUTH key", "PIV AUTH pubkey", and "Certificate for PIV
# Authentication" respectively).
pkcs11_resolve_lookup() {
    local name=$1
    local id_var="YUBIKEY_ID_$name"
    local label_var="YUBIKEY_LABEL_$name"
    if [[ -n "${!id_var:-}" ]]; then
        pkcs11_lookup_args=(--id "${!id_var}")
    elif [[ -n "${!label_var:-}" ]]; then
        pkcs11_lookup_args=(--label "${!label_var}")
    else
        echo "pkcs11_resolve_lookup: neither $id_var nor $label_var is set for '$name'" >&2
        return 1
    fi
}
