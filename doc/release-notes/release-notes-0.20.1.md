# ScooterCoin Core 0.20.1

This maintenance release keeps the existing ScooterCoin mainnet and wallet data
format. It does not introduce a coin swap or a new blockchain.

## Changes

- Prevent a wallet unlocked for staking only from signing spending transactions
  through `walletprocesspsbt`. Requests with `sign=false` can still update PSBT
  metadata. Fully unlocking the wallet permits signing as before.
- Initialize the version-warning confirmation window before it is used.
- Fix a transaction-validation robustness issue that could cause node failure.
  Upgrading is recommended, including for staking nodes. The on-disk coin
  serialization and mainnet consensus rules are unchanged.
- Report money supply from the validated active-chain tip rather than an
  unvalidated header. This RPC value is not a calculation of spendable supply
  after provably unspendable outputs or address-based burns.
- Add explicit buttons for the project website and block explorer. Clicking a
  button opens that fixed HTTPS URL in the system browser; no wallet address or
  transaction identifier is added to it.
- Add an optional ScooterCoin color theme. The native appearance remains
  available through Settings.
- Restore compatibility with the Windows 32-bit cross-compiler.
- Produce separate Windows 32-bit and 64-bit installers and portable packages.
  The 32-bit executables are linked large-address-aware.
- Update the Windows dependency recipes to Qt 5.15.19, OpenSSL 3.5.9,
  zlib 1.3.2, libevent 2.1.12 and miniupnpc 2.3.3.
- Repair inherited Bitcoin-specific test fixtures and add coverage for scrypt,
  staking-only PSBT signing and canonical staking signatures.

## Upgrading

Back up your wallet using the wallet's backup function and keep the backup
private. Shut down the old wallet normally and wait for it to exit completely
before installing or replacing executables. Never run two wallet processes
against the same data directory.

Use the 64-bit package on 64-bit Windows. A 32-bit process normally has only
2 GiB of virtual address space on 32-bit Windows. Large-address-aware executables
can use up to 4 GiB on 64-bit Windows, but that does not guarantee that every
wallet and cache configuration fits. For constrained systems, reduce caches,
for example with `-dbcache=100 -maxmempool=50`.

Installers and portable archives are separate downloads. Verify their hashes
against the release's `SHA256SUMS` file before use. Unsigned installers are
identified as such in their filenames; hashes do not replace code signing.

## Test networks

The local regression-test network has a corrected genesis proof of work.
Existing **regtest** data directories and functional-test caches must be
recreated. Do not delete a mainnet data directory or wallet as part of this
test-only reset. Mainnet and testnet genesis definitions are unchanged.

The inherited public testnet is not repaired or certified by this release.

## Links

- Website: <https://scootercoin.org/>
- Explorer: <https://explorer.scootercoin.org/>
- Source and issues: <https://github.com/ScooterCoinWallet/wallet-pos>
- Downloads: <https://github.com/ScooterCoinWallet/wallet-pos/releases>
