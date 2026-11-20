"""Signer: company-held keys behind a scope policy.

The keyfile is JSON encrypted with XSalsa20-Poly1305 (PyNaCl SecretBox) under an Argon2id-derived
key from DAO_SIGNER_PASSPHRASE. It holds the seeds of the company's own accounts:

  harness   signs every event in the log (so the log's authorship is verifiable)
  dao       the DAO's public account: directory registration, chat read proofs, chat replies
  fee       receives proposal fees, refunds or burns them
  agent:<id> agent seats, when designated (P2)

What is NOT here, ever: keyset keys, treasury keys, member keys. Those are human-held and signed
client-side. The signer refuses to sign anything outside a key's scopes.

What the log holds of a key's use. A use that writes something leaves the event of what it wrote, appended
by the caller in the transaction that wrote it: `fee.received`, `fee.refunded`, `fee.burned`, `outbox.sent`,
`directory.registered`, and every event itself for the harness key. A refusal has no caller that got as
far as writing anything, so the signer counts it here (`keypair`) and the worker puts the count on the
log as `signer.denied` with its next health check, key and scope and nothing else (XE-3974). Two routine
uses are not logged one by one, because each is a read or a repeat that changes nothing: the chat read
proof made for every poll of the node's store, and a directory registration that renews an entry already
on record.

The keyfile is read through `_read_keyfile` and written through `_write_keyfile` and no other way: every
failure to open it is a SignerError (XE-1779, XE-4282), and it is never on disk in a state other than
whole and 0600 (XE-4285).
"""

from __future__ import annotations

import json
import logging
import os
import secrets
from dataclasses import dataclass
from pathlib import Path

from nacl import pwhash, secret, utils

from xe.keys import KeyPair, exact_hex

SCOPES = {
    "harness": {"event.sign"},
    "dao": {"directory.register", "chat.read_proof", "chat.send", "inbox.ack"},
    "fee": {"block.receive", "block.send.refund", "block.burn"},
}
AGENT_SCOPES = {"chat.send", "portal.vote", "directory.register", "chat.read_proof"}


log = logging.getLogger("dao.signer")


class SignerError(RuntimeError):
    pass


@dataclass
class KeyInfo:
    name: str
    public_key: str
    address: str
    scopes: list[str]


def _kdf(passphrase: str, salt: bytes) -> bytes:
    return pwhash.argon2id.kdf(
        secret.SecretBox.KEY_SIZE, passphrase.encode("utf-8"), salt,
        opslimit=pwhash.argon2id.OPSLIMIT_MODERATE, memlimit=pwhash.argon2id.MEMLIMIT_MODERATE,
    )


def encrypt_keyfile(contents: dict, passphrase: str) -> dict:
    salt = utils.random(pwhash.argon2id.SALTBYTES)
    box = secret.SecretBox(_kdf(passphrase, salt))
    ct = box.encrypt(json.dumps(contents).encode("utf-8"))
    return {"version": 1, "kdf": "argon2id", "salt": salt.hex(), "ciphertext": ct.hex()}


def decrypt_keyfile(blob: dict, passphrase: str) -> dict:
    """Every way the file can fail to open is a SignerError, which the startup path turns into a clean
    abort: a missing field, bad hex, a wrong passphrase, or plaintext that is not JSON (XE-1779)."""
    try:
        box = secret.SecretBox(_kdf(passphrase, exact_hex(blob["salt"], None, "keyfile salt")))
        pt = box.decrypt(exact_hex(blob["ciphertext"], None, "keyfile ciphertext"))
        return json.loads(pt.decode("utf-8"))
    except SignerError:
        raise
    except Exception as e:  # nacl CryptoError, KeyError, ValueError (hex, JSON, UTF-8), TypeError
        raise SignerError(f"keyfile passphrase is wrong or the file is corrupt ({type(e).__name__})") from e


def _read_keyfile(path: Path, passphrase: str) -> dict:
    """The keyfile's decrypted contents: `{"keys": {name: seed hex}, "scopes": {name: [scope]}}`. Every way
    this can fail is a SignerError, for every caller: the file missing or unreadable, not JSON, not the
    shape a keyfile has, the passphrase wrong (XE-1779 closed this for `load` alone, XE-4282)."""
    if not _exists(path):
        raise SignerError(f"signer keyfile not found at {path}; run `dao keys init`")
    if not passphrase:
        raise SignerError("DAO_SIGNER_PASSPHRASE is empty")
    try:
        blob = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(blob, dict):
            raise SignerError("keyfile is not a JSON object")
        contents = decrypt_keyfile(blob, passphrase)
        if not isinstance(contents, dict) or not isinstance(contents.get("keys"), dict) \
                or not isinstance(contents.get("scopes", {}), dict):
            raise SignerError(f"keyfile at {path} does not hold a set of keys")
        return contents
    except SignerError:
        raise
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError) as e:
        raise SignerError(f"keyfile at {path} is corrupt ({type(e).__name__})") from e


def _exists(path: Path) -> bool:
    """Whether the keyfile is there. A path that cannot be looked at (a parent that may not be searched) is
    a SignerError like every other way the keyfile can fail, not a traceback from the CLI (XE-4282)."""
    try:
        return path.exists()
    except OSError as e:
        raise SignerError(f"keyfile at {path} cannot be reached ({type(e).__name__}: {e.strerror or e})") from e


def _write_keyfile(path: Path, contents: dict, passphrase: str) -> None:
    """Put the keyfile in place whole and private. It is written to a new file beside it, created 0600 (so
    it is never readable to anyone else, not for the moment between a write and a chmod), synced, and then
    renamed over the path: a reader sees the old file or the new one, and a crash or a full disk part-way
    leaves the old one as it was instead of a truncated file with every key in it gone (XE-4285)."""
    data = json.dumps(encrypt_keyfile(contents, passphrase), indent=1).encode("utf-8")
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(6)}.tmp")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    except OSError as e:
        raise SignerError(f"keyfile at {path} could not be written ({type(e).__name__}: {e.strerror or e})") from e


def _default_scopes(name: str) -> set[str]:
    return set(SCOPES.get(name, AGENT_SCOPES if name.startswith("agent:") else set()))


class Signer:
    def __init__(self, keys: dict[str, KeyPair], scopes: dict[str, set[str]]):
        self._keys = keys
        self._scopes = scopes
        self._denied: dict[tuple[str, str], int] = {}

    # ---- construction ---------------------------------------------------------------------

    @classmethod
    def load(cls, path: Path, passphrase: str) -> "Signer":
        contents = _read_keyfile(path, passphrase)
        try:
            keys = {name: KeyPair.from_seed_hex(seed) for name, seed in contents["keys"].items()}
            scopes = {name: set(s) for name, s in contents.get("scopes", {}).items()}
        except (ValueError, KeyError, TypeError, AttributeError) as e:
            raise SignerError(f"keyfile at {path} is corrupt ({type(e).__name__})") from e
        for name in keys:
            scopes.setdefault(name, _default_scopes(name))
        return cls(keys, scopes)

    @classmethod
    def empty(cls) -> "Signer":
        return cls({}, {})

    @staticmethod
    def init_keyfile(path: Path, passphrase: str, names: tuple[str, ...] = ("harness", "dao", "fee")) -> dict[str, KeyInfo]:
        if _exists(path):
            raise SignerError(f"{path} already exists; refusing to overwrite")
        if len(passphrase) < 12:
            raise SignerError("passphrase must be at least 12 characters")
        keys = {n: KeyPair.generate() for n in names}
        contents = {
            "keys": {n: kp.seed.hex() for n, kp in keys.items()},
            "scopes": {n: sorted(_default_scopes(n)) for n in names},
        }
        _write_keyfile(path, contents, passphrase)
        return {n: KeyInfo(n, kp.pub_key_hex, kp.address, contents["scopes"][n]) for n, kp in keys.items()}

    @staticmethod
    def add_key(path: Path, passphrase: str, name: str, scopes: set[str] | None = None) -> KeyInfo:
        contents = _read_keyfile(path, passphrase)
        if name in contents["keys"]:
            raise SignerError(f"key {name!r} already exists")
        kp = KeyPair.generate()
        contents["keys"][name] = kp.seed.hex()
        sc = sorted(scopes if scopes is not None else _default_scopes(name))
        contents.setdefault("scopes", {})[name] = sc
        _write_keyfile(path, contents, passphrase)
        return KeyInfo(name, kp.pub_key_hex, kp.address, sc)

    # ---- use ------------------------------------------------------------------------------

    def has(self, name: str) -> bool:
        return name in self._keys

    def info(self, name: str) -> KeyInfo:
        kp = self._require(name)
        return KeyInfo(name, kp.pub_key_hex, kp.address, sorted(self._scopes.get(name, set())))

    def infos(self) -> list[KeyInfo]:
        return [self.info(n) for n in sorted(self._keys)]

    def address(self, name: str) -> str:
        return self._require(name).address

    def public_key(self, name: str) -> str:
        return self._require(name).pub_key_hex

    def keypair(self, name: str, scope: str) -> KeyPair:
        """Return the key pair for a scoped operation that needs it (building blocks, envelopes).
        The policy check happens here, and so does the record of a refusal: every caller gets its key
        through this, so a use that was refused is counted whoever asked and however they handled being
        told (`denials`). A use that is allowed is logged by the caller, as the event of what the
        key was used to write."""
        kp = self._keys.get(name)
        if kp is None or scope not in self._scopes.get(name, set()):
            self._denied[(name, scope)] = self._denied.get((name, scope), 0) + 1
            log.warning("signer refused key %r for scope %r", name, scope)
            raise SignerError(f"no key named {name!r} in signer" if kp is None
                              else f"key {name!r} is not permitted scope {scope!r}")
        return kp

    def denials(self) -> list[dict]:
        """The refusals not yet recorded, one entry per key and scope with how many times. Key and scope
        only: what was to be signed is not kept. Reading them does not start the count again: a refusal
        is counted here until whoever records it says it is recorded (`forget`), so a record that did
        not commit loses none (XE-14106)."""
        return [{"key": k, "scope": s, "count": n} for (k, s), n in sorted(self._denied.items())]

    def forget(self, recorded: list[dict]) -> None:
        """Stop counting the refusals in `recorded`, a reading of `denials` that is now on the log. Only
        what was read is taken off: a refusal since the reading is still counted."""
        for x in recorded:
            key = (x["key"], x["scope"])
            left = self._denied.get(key, 0) - x["count"]
            if left > 0:
                self._denied[key] = left
            else:
                self._denied.pop(key, None)

    def sign(self, name: str, scope: str, message: bytes) -> str:
        return self.keypair(name, scope).sign_hex(message)

    def _require(self, name: str) -> KeyPair:
        kp = self._keys.get(name)
        if kp is None:
            raise SignerError(f"no key named {name!r} in signer")
        return kp
