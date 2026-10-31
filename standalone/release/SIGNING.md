# Signing the standalone releases

Each release has a `SHA256SUMS` over every asset and `SHA256SUMS.minisig`, its minisign signature.
`install.sh --version` and the CLI (when it downloads the vm-agent) check the signature before they
trust any hash, and stop on a missing or wrong one. The signature's trusted comment is
`controlclaw <version>`, and both check it, so an older signed release cannot be served as a newer
one.

## Why minisign

- **One key, offline, with no CI.** This repo has no CI. Keyless cosign would need an OIDC sign-in
  (the host's own account) and would write it to the public Rekor log for good.
- **No new tool to check it.** `install.sh` checks the signature with `openssl` (it needs openssl
  anyway), the CLI with Node's own crypto, and anyone can run `minisign -V`.
- The image will also get a cosign signature when it is pushed to a registry (not done yet). Here it
  is covered by `SHA256SUMS`.

## Make the key (host, once)

```bash
minisign -G -p controlclaw.pub -s ~/.minisign/controlclaw.key   # asks for a passphrase
```

- Keep `controlclaw.key` off this repo and off the boxes. Keep two offline copies (a password
  manager's file attachment and an encrypted USB key), and the passphrase apart from them.
- Commit `controlclaw.pub` over `standalone/release/controlclaw.pub` (it holds a placeholder now).
  From then on:
  - `release.sh` stamps the key into the CLI and into the `install.sh` it packs;
  - `install.sh` run from a checkout reads it from this folder.

## Sign a release

Releases are built only in the private repo: they are pinned by its lockfile and made with the
role's release script. The public export has neither, and `release.sh` stops there.

`standalone/release/release.sh <version>` builds everything, then either:

- signs it: `CC_MINISIGN_KEY=~/.minisign/controlclaw.key standalone/release/release.sh <version>`
  (minisign asks for the passphrase), checks it and prints the publish lines; or
- prints the line to run where the key is:
  `minisign -S -H -s <key> -m SHA256SUMS -t "controlclaw <version>"`. After that,
  `standalone/release/release.sh --check <version>` checks the signature (this commit's key, the
  prehashed form, the version in the trusted comment, every asset against `SHA256SUMS`) and only then
  prints the publish lines.

`-H` makes the prehashed signature that `install.sh` and the CLI accept (minisign 0.11 makes it by
default; older versions do not).

A try (`CC_RELEASE_DRY_RUN=1`) goes to `rust/dist/standalone-dry/<version>/` and prints nothing to
publish.

## Install without trusting the download

The first `install.sh` comes from the release itself. Check the archive before running it:

```bash
minisign -Vm SHA256SUMS -p controlclaw.pub      # the key from the repo, not from the release
sha256sum -c --ignore-missing SHA256SUMS
```

## Rotate the key

1. Make a new key, commit the new `controlclaw.pub`, and make a release signed with the new key.
2. The CLI and install scripts already out there only trust the old key. Sign that release's
   `SHA256SUMS` with the old key too, and publish it as `SHA256SUMS.old.minisig`, so people can
   check the new scripts with the key they already have.
3. If the old key leaked, say so in the release notes and in SECURITY.md, and do not sign with it
   again.

## Tests

- The dry runs use a throwaway key without a passphrase (`minisign -G -W`) and
  `CC_RELEASE_DRY_RUN=1 CC_RELEASE_PUBKEY_FILE=<its .pub>`. A real release refuses another key file,
  and refuses the placeholder.
- `testdata/` has a fixed vector signed by the minisign tool (its secret key was deleted). Both
  checks run against it: `verify.test.sh` for the openssl one in `install.sh`, and
  `packages/cli/src/release.test.ts` for the CLI's.
