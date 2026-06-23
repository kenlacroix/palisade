# Release signing

The release workflow publishes a `SHA256SUMS` manifest over the agent binaries
and a detached **minisign** signature, `SHA256SUMS.minisig`. The installer
(`site/public/install`) verifies that signature against a public key pinned in
the script before trusting any checksum — so a tampered or swapped manifest is
rejected, not just a corrupted download.

minisign is Ed25519 under the hood, matching the detection-catalog signing in
`control-plane/app/signing.py`.

## One-time setup

1. **Generate a keypair on a trusted machine** (passwordless, so CI can sign
   non-interactively — GitHub's secret store is the protection):

   ```sh
   minisign -G -W -p palisade-release.pub -s palisade-release.key
   ```

2. **Pin the public key in the installer.** Copy the base64 key — the second,
   non-comment line of `palisade-release.pub` (starts with `RW`) — into
   `MINISIGN_PUBKEY` in `site/public/install`:

   ```sh
   MINISIGN_PUBKEY="RW...."
   ```

3. **Add the secret key to GitHub Actions** as the `MINISIGN_SECRET_KEY` repo
   secret (full contents of `palisade-release.key`):

   ```sh
   gh secret set MINISIGN_SECRET_KEY < palisade-release.key
   ```

4. Store `palisade-release.key` offline and delete the working copy. The public
   key is safe to publish.

Until `MINISIGN_SECRET_KEY` is set, the workflow publishes `SHA256SUMS` unsigned;
until `MINISIGN_PUBKEY` is pinned, the installer falls back to checksum-only
verification. Both are no-ops rather than failures, so rollout is safe in either
order — but pin the key before cutting the first signed release.

## Installer behavior

- **Pinned key + minisign present:** verify the signature, fail closed on a bad
  signature.
- **No minisign, or no signature published:** print a warning with the manual
  verification command and continue on checksum-only.
- **`PALISADE_REQUIRE_SIGNATURE=1`:** make any unverifiable case fatal (no key
  pinned, minisign missing, or signature absent).

## Manual verification

```sh
curl -fsSLO https://github.com/kenlacroix/palisade/releases/latest/download/SHA256SUMS
curl -fsSLO https://github.com/kenlacroix/palisade/releases/latest/download/SHA256SUMS.minisig
minisign -Vm SHA256SUMS -P "RWTFbgXBpSvo0JBsv9Lc+Tldsv2Em3K2xPLqxwjqi3i+4MZR09BYpC7S"
sha256sum -c SHA256SUMS --ignore-missing
```

## Key rotation

Generate a new keypair, update `MINISIGN_PUBKEY` in the installer, and replace
the `MINISIGN_SECRET_KEY` secret. Old releases stay verifiable with the old key;
clients always use the key pinned in the installer they fetched.
