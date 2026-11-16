# Recovery phrase v2

XE wallets generate **24 English BIP39 words** from 256 bits of OS randomness.
Import accepts 12, 15, 18, 21 or 24 words. Write the words down in order before
using the wallet. The phrase is your only backup unless you separately keep the
hex signing seed. Anyone with that backup controls the account.

## Derivation

1. Trim, lowercase, split on Unicode whitespace, join with ASCII spaces, then
   normalize with NFKD. Validate the BIP39 English wordlist and entropy checksum.
2. Derive the 64-byte BIP39 seed with PBKDF2-HMAC-SHA512, 2048 iterations, password
   NFKD(words), salt `mnemonic` followed by NFKD(BIP39 passphrase).
3. Use SLIP-0010 ed25519 at `m/44'/22597'/account'`. Every level is hardened. Account
   defaults to 0 and must be an integer from 0 through 2147483647.
4. Use the 32-byte leaf key as the ed25519 signing seed. The existing address
   derivation stays `sha256("xe/account/v1" || public_key)`.

The coin type is **22597** (`0x5845`, the bytes "XE") on every XE network. It is
defined by one constant in each implementation, and the vectors record
`coin_type: 22597` and `coin_type_provisional: false`. Changing the coin type
changes the resulting accounts. A phrase made while the coin type was 1 (before
testnet-0006) derives a different, empty account on this path; such a wallet
restores from its hex seed.

A phrase cannot be computed from a signing seed. A hex-only wallet therefore has
no phrase. BIP39 compatibility does not make an XE account an Ethereum account;
other software must use XE's ed25519 derivation path and address rule.

## BIP39 passphrase

The default is empty. Opt in explicitly with CLI `--passphrase` or the browser
and Edge advanced controls. This is separate from the web vault password.
At creation, enter it twice: both entries must match exactly before continuing.
The CLI hides both prompts; the browser and Edge use password fields. Both
fields are cleared after creation or applying the passphrase. Restore asks once;
check the restored address against your backup.
It is case-sensitive, is not trimmed, and is NFKD-normalized. Keep it separately
from the words and avoid a weak passphrase. **It is never stored. On restore, a
wrong passphrase opens a different, empty account**, with no validation error.
To restore a protected phrase you need the words, passphrase and account index.
A separately saved hex seed restores that specific account without them.

## CLI

```sh
xe wallet create
xe wallet create --passphrase        # two hidden prompts, never a value on argv
xe wallet restore                    # phrase from stdin, never an argument
xe wallet restore --account 1 --passphrase
xe wallet phrase                     # stored words on stdout; warning on stderr
```

Generation always uses account 0. Restore prints the address for checking and
refuses to overwrite existing files. On a terminal, words are hidden; finish a
shorter phrase with a blank line. Piped input can end with EOF. `--passphrase`
requires a controlling terminal and reads a hidden prompt there, including when
words arrive through a pipe. Never put either secret in shell arguments or logs.
Creation requires a second hidden confirmation. A mismatch exits without writing
files and restores terminal echo:

```text
BIP39 passphrases do not match; wallet was not created
```

`wallet.seed` remains 64 hex characters plus a newline, mode 0600. Signing still
reads it. The additional `wallet.phrase`, also mode 0600, contains normalized
words on one line, `account: N` on the next, and `address: <64 hex>` on the third.
The address is derived from the signing seed, including when a BIP39 passphrase
was used. Parent directories are created
with mode 0700. `XE_WALLET` selects the seed path; the phrase path replaces the
`.seed` suffix with `.phrase`, or appends `.phrase` if there is no `.seed` suffix.
Both names must be available before a new wallet is saved.
If a stray phrase file exists without the seed, create and restore refuse before
prompting and name the file: `recovery phrase file already exists at <path>; refusing to overwrite it`.

`xe wallet phrase` compares the recorded address with the address derived from
`wallet.seed`. A missing or mismatched address prints no words and fails with:

```text
the phrase file does not belong to this wallet; its backup is wallet.seed
```

This also protects against a leftover phrase file after copying an older seed
into place. No migration of phrase files without an address is provided.

On a hex-only wallet, `xe wallet phrase` fails with:

```text
this wallet was created from a hex seed and has no recovery phrase; its backup is wallet.seed
```

## Browser and Edge

The embedded web wallet shows 24 numbered words and requires three randomly
selected words before saving or enabling the account. Import accepts words or a
64-hex seed. The advanced section enables a BIP39 passphrase or an imported
account index. From an unlocked phrase wallet, Add offers the next account from
that phrase; re-enter its BIP39 passphrase if one was used. Before deriving the
next account, the wallet checks the entered passphrase against the current
account's decrypted signing seed and refuses a mismatch without changing the
vault. Leaving the passphrase option unticked checks an empty passphrase. The
input is cleared after success or a mismatch. Each additional account stores
its phrase and index for later reveal.

The web vault keeps `encrypted_seed` unchanged and adds optional
`encrypted_phrase`, `phrase_iv` and `account`. Phrase encryption uses the same
PBKDF2-SHA256 vault key (600,000 iterations, per-wallet salt) and a separate
random AES-GCM IV. Existing vaults open without migration. DAO and chat still
use only the signing seed. Show backup reveals stored words, with hex behind an
advanced control; hex-only wallets show hex and explain why they have no phrase.

The vault password can be cached in sessionStorage by the existing unlock flow.
The BIP39 passphrase is never cached. They are different secrets.

Edge's New address creates a new phrase each time at account 0. Its existing
three-word check remains mandatory. Advanced Apply passphrase stays disabled
until both entries match exactly. Applying changes the address under the displayed
phrase, clears both inputs, and resets the check.
New address resets the passphrase option. Edge does not retain the backup after
the modal closes.

## Legacy wallets

**Wallets made before v2 restore from their hex seed.** The former words
encoded the signing seed directly. They also have valid BIP39 checksums, so
software cannot detect them from the words. V2 interprets those words using
standard BIP39 and produces a different, empty account. There is no legacy mode.
Keep or import the old `wallet.seed`; never replace it by restoring old words.
Operational node, faucet and provider keys remain raw seeds and are unaffected.
