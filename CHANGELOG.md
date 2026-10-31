# Changelog

<!-- markdownlint-configure-file
  {
    // MD024/no-duplicate-heading - every release repeats the same few
    // headings, which is what keeps the page readable scrolling down it;
    // only a duplicate under the same release heading would be the
    // accident this rule looks for
    "MD024": { "siblings_only": true }
  }
-->

The release's own pull request writes its section here, from the squash
subjects since the previous tag; a pull request adds no entry
(`CONTRIBUTING.md`'s *Pull requests*, section 9 of [the organization
standard][std]). [RELEASE_NOTES.md](./RELEASE_NOTES.md) has the release
notes, which say what a user has to act on; this file is the record
behind them.

[std]: https://github.com/btclib-org/.github

## v2026.10.31

### The repository opens with btclib-wallet's bip32 and descriptors

btclib-wallet's `bip32` and `descriptors` at b8b5c9b, with their tests,
renamed to `bip32_descriptors`, around base58-bech32's repository files;
the integration workflow pins bitcoind 32.1 (issue btclib-org/.github#1811).

### The prose describes this package

The review bot's prompt, AUTHORS.md and a pypi-install comment describe
this package, not base58-bech32; comments naming btclib-wallet's modules
say they are btclib-wallet's (issue btclib-org/.github#1811).

### The README shows the OpenSSF badges

The Best Practices and Baseline badges of bestpractices.dev project
16116, which RELEASING.md also reads at release.
