"""Encryption-at-rest for the stored credentials (`accounts.secretEnc`).

Threat model, stated plainly because this app deliberately stores router/NAS/WLAN passwords: the
key lives next to the database in the same Docker volume, so this protects against a leaked *DB
copy* (backup file, `docker cp`, a stray SQLite dump) -- NOT against someone who already has root
on the Docker host, since they can read the key file too. That is an intentional trade-off: the
alternative (a passphrase the user types on every container start) would make an unattended
restart impossible, and this is documentation infrastructure that has to come back up on its own.
See README "Sicherheit".
"""
from __future__ import annotations

import os
import stat
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

_KEY_PATH = Path(os.environ.get("HOMEATLAS_KEY_PATH", "/data/secret.key"))
_cached: Fernet | None = None


def _fernet() -> Fernet:
    global _cached
    if _cached is not None:
        return _cached
    if _KEY_PATH.exists():
        key = _KEY_PATH.read_bytes().strip()
    else:
        key = Fernet.generate_key()
        _KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
        _KEY_PATH.write_bytes(key)
        # Best effort -- on a bind-mounted host directory the owner/permissions may not be ours to
        # set, and failing startup over a chmod would be worse than the weaker file mode.
        try:
            _KEY_PATH.chmod(stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
    _cached = Fernet(key)
    return _cached


def encrypt(plaintext: str) -> str:
    if not plaintext:
        return ""
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt(token: str) -> str:
    """Returns "" for an unreadable value rather than raising: a secret that can't be decrypted
    (key file replaced, volume restored without it) must not take down the whole inventory view --
    the UI shows the entry with an empty secret, which is a recoverable state the user can fix by
    re-entering the password."""
    if not token:
        return ""
    try:
        return _fernet().decrypt(token.encode()).decode()
    except (InvalidToken, ValueError):
        return ""
