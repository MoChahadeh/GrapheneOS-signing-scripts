# YubiKey / PKCS#11 signing for GrapheneOS

This subdirectory turns the upstream GrapheneOS signing flow into a
hardware-backed pipeline where the 10 RSA-4096 signing keys live on a
YubiKey (or any PKCS#11 token) and never touch disk in unencrypted form.

It is layered on top of the standard scripts in this repo, not a
replacement -- the upstream `generate-release.sh`, `decrypt-keys`,
`encrypt-keys`, etc. are left untouched so you can switch back at any
time.

## What gets signed and how

| Component                   | Tool                          | Mechanism we use                                   |
|-----------------------------|-------------------------------|----------------------------------------------------|
| APKs (system, vendor, etc.) | `signapk.jar` via `SignFile`  | `-loadPrivateKeysFromKeyStore PKCS11` (built-in)   |
| OTA package (whole file)    | `signapk.jar` (`-w`)          | Same as APKs                                       |
| OTA payload                 | `delta_generator` + signer    | Custom `--payload_signer` script (CKM_RSA_PKCS)    |
| APEX containers             | `signapk.jar`                 | Same as APKs                                       |
| APEX payloads               | `avbtool add_hashtree_footer` | `--signing_helper_with_files` (CKM_RSA_X_509)      |
| vbmeta + AVB-signed images  | `avbtool make_vbmeta_image`   | `--signing_helper_with_files` (CKM_RSA_X_509)      |
| Factory image bundle (zip)  | `ssh-keygen -Y sign`          | Untouched -- still uses an on-disk ed25519 key     |

The factory-image bundle signature is what gets verified by
`update_engine`'s sideload path; it is intentionally separate from the
release signing chain and we leave it alone. If you don't need it, drop
the trailing `ssh-keygen -Y sign` block from `generate-release-pkcs11.sh`.

## Prerequisites

### On the build host

- `pkcs11-tool` (OpenSC; Debian/Ubuntu: `apt install opensc-pkcs11
  opensc`). This is the only PKCS#11 client we shell out to.
- `openssl` (any modern version) for extracting public certs into PEM.
- A JVM that ships SunPKCS11 -- any OpenJDK 11+ works. The AOSP build
  already pulls one in.
- The AOSP prerequisites that GrapheneOS itself requires (see
  https://grapheneos.org/build).

### On the YubiKey

Provision **10 RSA-4096 keys** ahead of time. YubiKey 5.7+ is required
for RSA-4096 PIV; older firmware caps at RSA-2048. Each key must have a
PKCS#11 `CKA_LABEL` that you'll plug into `yubikey.env`. The 10 keys are:

```
bluetooth   gmscompat_lib   media   networkstack   nfc
platform    releasekey      shared  sdk_sandbox    avb
```

The default `yubikey.env.example` ships with the OpenSC PKCS#11 module
(`opensc-pkcs11.so`) because it works for both direct-attached YubiKeys
and YubiKeys forwarded over PC/SC (e.g. via `pcsc-relay` for signing
from a remote build host). Yubico's `libykcs11.so` is faster and uses
more reader-friendly labels, but it does NOT work through PC/SC
relaying -- it talks to the smartcard layer through a different path
and won't see relayed tokens. If your token is always physically
attached to the signing host, you can swap to `libykcs11.so` for
cosmetic-label benefits; otherwise stick with OpenSC.

You can verify the token's view with:

```
pkcs11-tool --module "$YUBIKEY_PKCS11_MODULE" --list-objects --type privkey
```

### Identifying slots: CKA_ID vs CKA_LABEL

Each slot can be addressed by either CKA_ID (a single byte, same on the
cert / public key / private key for one slot) or CKA_LABEL (a string,
per-object, driver-defined). In `yubikey.env` set EITHER:

  - `YUBIKEY_ID_<name>="<hex>"` -- preferred, used by the AVB and payload
    helpers via `pkcs11-tool --id`. Deterministic across object types.
  - `YUBIKEY_LABEL_<name>="<string>"` -- the **certificate's** CKA_LABEL.
    Required for any key that goes through APK / OTA-package signing
    because signapk.jar's SunPKCS11 path uses the cert label as its
    keystore alias.

Both can be set. The helpers prefer ID; signapk.jar always uses LABEL.

The most common foot-gun is the OpenSC PIV driver (the default here),
which gives the cert, public key, and private key of one slot three
different labels (e.g. slot 9a private key is `"PIV AUTH key"` and its
cert is `"Certificate for PIV Authentication"`). For that reason set
`YUBIKEY_ID_*` for every key and add `YUBIKEY_LABEL_*` with the **cert
label** for the keys signapk.jar will use (i.e. all of them except
`avb`). The `yubikey.env.example` file has a worked example for both
OpenSC (default) and libykcs11 layouts.

## One-time setup

```sh
# 1. Drop this repo into your tree as `script/` via your local_manifest
#    (see ../local_manifests/yubikey-signing.xml.example).
repo sync -j8

# 2. Apply the PKCS#11 patch to build/make/tools/releasetools/common.py.
script/pkcs11/install-patches.sh

# 3. Create your local config.
cp script/pkcs11/yubikey.env.example script/pkcs11/yubikey.env
$EDITOR script/pkcs11/yubikey.env       # set library path + labels

# 4. Extract the public certificates from the YubiKey for each device.
#    The .pk8 files are intentionally not created.
script/pkcs11/extract-certs cheetah rango caiman ...
```

The patch is idempotent and the helper recognizes a fresh `repo sync`
that lost the patch -- just re-run `install-patches.sh` after each sync.

If you'd rather skip the post-sync step entirely, maintain a long-lived
fork of `GrapheneOS/platform_build` with the patch committed on top and
point your local_manifest at it. See Option B in
`local_manifests/yubikey-signing.xml.example` for the exact XML and
bootstrap commands.

## Building and signing

```sh
# Same as the upstream build flow.
. build/envsetup.sh
lunch cheetah-cur-user
m vendorbootimage vendorkernelbootimage target-files-package otatools-package
script/finalize.sh

# Sign with the YubiKey. Touch when the token blinks.
script/generate-release-pkcs11.sh cheetah 2026051901

# Batch mode -- serial, since a single token can only sign one thing at
# a time.
script/generate-releases-pkcs11.sh 2026051901

# Incremental OTAs:
script/generate-delta-pkcs11.sh cheetah 2026051800 2026051901
```

The first invocation prompts once for the PIV PIN and caches it for the
duration of the shell. If you need to rotate the PIN mid-session, `unset
YUBIKEY_PIN` and the next invocation will re-prompt.

## How the moving parts fit together

```
                   yubikey.env
                       |
                       v
              pkcs11/pkcs11-env.sh                  one-time, per shell
                       |
        +--------------+------------------+
        |              |                  |
        v              v                  v
  $OTATOOLS_PKCS11    $YUBIKEY_PKCS11_CFG   $YUBIKEY_LABEL_*
   _ALIAS_MAP          (SunPKCS11 cfg)
        |              |                          |
        | (read by)    | (read by signapk.jar     | (read by AVB +
        | the patched  |  via -providerArg)       |  payload helpers)
        | common.py    |                          |
        v              v                          v
   sign_target_files_apks    signapk.jar     yubikey-{avb,payload}-signer
   ota_from_target_files
                                                  |
                                                  v
                                              pkcs11-tool
                                              (CKM_RSA_X_509 /
                                               CKM_RSA_PKCS)
                                                  |
                                                  v
                                              YubiKey  (the only place
                                                        private keys
                                                        ever exist)
```

## What's in the AOSP patch

`aosp-patches/0001-releasetools-add-pkcs11-keystore-support.patch`
adds two things to `build/make/tools/releasetools/common.py`:

1. A `--use_pkcs11_aliases` CLI flag that flips `SignFile()` from passing
   `<keypath>.pk8` to passing the basename (e.g. `releasekey`). This
   basename is what signapk.jar's
   `-loadPrivateKeysFromKeyStore PKCS11` mode uses as the keystore alias.

2. An `OTATOOLS_PKCS11_ALIAS_MAP` env var that lets you override the
   basename with an arbitrary CKA_LABEL string (so the AOSP key name
   doesn't have to match what's burned into your token).

That's the entire AOSP-side change. Everything else is in scripts that
ship in this repo.

## Why we don't use openssl's `pkcs11-provider` engine

The shell helpers use `pkcs11-tool` directly with explicit mechanisms
(`RSA-X-509`, `RSA-PKCS`) instead of `openssl pkeyutl -engine pkcs11`.
Two reasons:

- One fewer dependency to install and configure (engine_pkcs11 or
  pkcs11-provider depending on the OpenSSL version).
- AVB feeds its signing helper an already-padded hash (PKCS#1 v1.5
  + ASN.1 DigestInfo). OpenSSL doesn't expose a clean way to "sign
  these bytes with no padding"; it always wants to compose the
  padding itself. `pkcs11-tool --mechanism RSA-X-509` does raw RSA,
  which is exactly what AVB needs.

If you'd rather use OpenSSL, both helpers are short shell scripts --
swap the `pkcs11-tool` line for an `openssl` line and you're done.

## Security notes

- `yubikey.env` is gitignored. Never check in a copy that contains the
  PIN.
- The rendered SunPKCS11 config lives in `/dev/shm` and is removed by the
  shell trap on exit; the PIN, however, is exported into the
  environment for the lifetime of the script. If you're paranoid about
  process listings on a multi-user host, run the build under its own
  uid.
- The `extract-certs` helper writes `*.pk8` placeholder files with the
  literal contents `PKCS11-MANAGED`. The patched `common.py` never opens
  them; they exist only so directory listings make sense.
- Touch-to-sign on the YubiKey is strongly recommended for at least the
  `releasekey` and `avb` slots. Configure via
  `yubico-piv-tool -aset-touch-policy -s9c -PTouch=always` (slot 9c is
  the Digital Signature slot; adapt for retired slots as needed).

## Limitations

- Single-key-at-a-time. With one token, parallel device signing isn't
  possible. `generate-releases-pkcs11.sh` runs serially.
- The patch targets the current GrapheneOS `platform_build` (Android 16
  QPR2). If the upstream `SignFile()` shape changes, the patch hunks
  may need re-rolling -- it's small enough to do by hand.
- We don't sign the factory-image bundle with the YubiKey. That
  signature uses an ed25519 key for `ssh-keygen -Y sign`; ed25519 isn't
  available on PIV. Leave it on disk (encrypted) or skip it.
