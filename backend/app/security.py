"""Passwortrichtlinie und zweiter Faktor (TOTP).

TOTP is implemented against RFC 6238 with the standard library rather than a dependency: it is
about thirty lines of HMAC, and every authenticator app speaks it. The QR code uses the `qrcode`
package for the matrix only -- the SVG is emitted here, so no image backend (Pillow, lxml) is
needed in the container.

The password rules aim at *usable* strength: a long passphrase passes without needing a symbol,
because "Keller Sicherung Blau 12" is both stronger and more memorable than "Pw1!". Every rejection
says what to change, in German, instead of restating the policy.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import struct
import time
import unicodedata

MIN_LENGTH = 10
# Above this a passphrase is accepted on length alone -- character-class rules on long inputs push
# people towards short-and-obfuscated, which is the weaker outcome.
PASSPHRASE_LENGTH = 20

# Not a serious dictionary -- just the handful that shows up when someone types something to get
# past the form. A real leaked-password check would need a data file and an update path.
_OBVIOUS = {
    "passwort", "password", "geheim", "12345678", "123456789", "1234567890", "qwertz",
    "qwertzuiop", "asdfghjkl", "administrator", "homeatlas", "willkommen", "changeme",
    "letmein", "monkey", "iloveyou", "sonnenschein", "fussball", "hallo123", "test1234",
}


class PasswordError(ValueError):
    pass


def _classes(password: str) -> int:
    return sum([
        bool(re.search(r"[a-zäöüß]", password)),
        bool(re.search(r"[A-ZÄÖÜ]", password)),
        bool(re.search(r"\d", password)),
        bool(re.search(r"[^\w\s]", password)),
    ])


def check_password(password: str, username: str = "") -> None:
    """Raises PasswordError with a sentence the user can act on. Silent on success."""
    password = unicodedata.normalize("NFKC", password or "")
    if len(password) < MIN_LENGTH:
        raise PasswordError(
            f"Das Passwort ist zu kurz. Es braucht mindestens {MIN_LENGTH} Zeichen -- am einfachsten "
            "geht das mit mehreren Wörtern hintereinander, etwa „Keller Sicherung Blau 12“."
        )
    if password.strip() != password.strip(" "):
        pass  # Tabs/newlines are fine inside a passphrase; only fully blank input is rejected below.
    if not password.strip():
        raise PasswordError("Das Passwort darf nicht nur aus Leerzeichen bestehen.")

    lowered = password.lower()
    if lowered in _OBVIOUS or (len(lowered) < 16 and any(word == lowered for word in _OBVIOUS)):
        raise PasswordError("Dieses Passwort ist zu bekannt und wird als Erstes ausprobiert. Bitte ein anderes wählen.")
    if username and len(username) >= 3 and username.lower() in lowered:
        raise PasswordError("Das Passwort darf den Benutzernamen nicht enthalten.")

    if len(password) >= PASSPHRASE_LENGTH:
        # Long enough that composition rules add nothing.
        return

    if _classes(password) < 3:
        raise PasswordError(
            "Das Passwort ist zu einfach. Es braucht mindestens drei der vier Arten: Kleinbuchstaben, "
            "Großbuchstaben, Ziffern, Sonderzeichen -- oder alternativ mindestens "
            f"{PASSPHRASE_LENGTH} Zeichen, dann genügt eine Folge aus mehreren Wörtern."
        )
    if re.fullmatch(r"(.)\1*", password):
        raise PasswordError("Das Passwort besteht nur aus einem einzigen wiederholten Zeichen.")
    if re.search(r"(abcdef|qwertz|qwerty|123456|987654)", lowered):
        raise PasswordError("Das Passwort enthält eine offensichtliche Tastatur- oder Zahlenfolge.")


def describe_policy() -> dict:
    return {
        "minLength": MIN_LENGTH,
        "passphraseLength": PASSPHRASE_LENGTH,
        "rules": [
            f"Mindestens {MIN_LENGTH} Zeichen.",
            "Entweder drei der vier Arten (Klein-, Großbuchstaben, Ziffern, Sonderzeichen) …",
            f"… oder ab {PASSPHRASE_LENGTH} Zeichen genügt eine Folge aus mehreren Wörtern.",
            "Kein Benutzername, keine bekannten Passwörter, keine Tastaturfolgen.",
        ],
    }


# ---------------------------------------------------------------------------------------------
# TOTP (RFC 6238)
# ---------------------------------------------------------------------------------------------

_STEP = 30
_DIGITS = 6


def generate_totp_secret() -> str:
    """Base32 without padding -- what authenticator apps expect for manual entry."""
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _code_at(secret_b32: str, counter: int) -> str:
    padding = "=" * (-len(secret_b32) % 8)
    key = base64.b32decode(secret_b32.upper() + padding, casefold=True)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % (10 ** _DIGITS)).zfill(_DIGITS)


def verify_totp(secret_b32: str, code: str, window: int = 1) -> bool:
    """`window` steps of tolerance in each direction, so a phone clock that is a few seconds off
    still works. Comparison is constant-time."""
    code = re.sub(r"\s", "", code or "")
    if not secret_b32 or not re.fullmatch(r"\d{6}", code):
        return False
    counter = int(time.time()) // _STEP
    for drift in range(-window, window + 1):
        try:
            expected = _code_at(secret_b32, counter + drift)
        except (ValueError, TypeError):
            return False
        if secrets.compare_digest(expected, code):
            return True
    return False


def provisioning_uri(secret_b32: str, account: str, issuer: str = "HomeAtlas") -> str:
    from urllib.parse import quote
    label = quote(f"{issuer}:{account}")
    return (f"otpauth://totp/{label}?secret={secret_b32}&issuer={quote(issuer)}"
            f"&algorithm=SHA1&digits={_DIGITS}&period={_STEP}")


def qr_svg(data: str, module_px: int = 4) -> str:
    """QR code as a self-contained SVG string.

    Only the matrix comes from `qrcode`; the SVG is written here so the container needs no image
    backend. Returns "" if the library is missing -- the setup screen then falls back to showing
    the secret for manual entry, which every authenticator app supports.
    """
    try:
        import qrcode
    except ImportError:
        return ""
    code = qrcode.QRCode(border=2, box_size=1)
    code.add_data(data)
    code.make(fit=True)
    matrix = code.get_matrix()
    size = len(matrix)
    dimension = size * module_px
    rects = []
    for y, row in enumerate(matrix):
        run_start = None
        for x in range(size + 1):
            filled = x < size and row[x]
            if filled and run_start is None:
                run_start = x
            elif not filled and run_start is not None:
                # Horizontal run-length merging keeps the SVG a few kB instead of a few hundred.
                rects.append(
                    f'<rect x="{run_start * module_px}" y="{y * module_px}" '
                    f'width="{(x - run_start) * module_px}" height="{module_px}"/>'
                )
                run_start = None
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{dimension}" height="{dimension}" '
        f'viewBox="0 0 {dimension} {dimension}" shape-rendering="crispEdges" role="img" '
        f'aria-label="QR-Code zur Einrichtung der Zwei-Faktor-Anmeldung">'
        f'<rect width="{dimension}" height="{dimension}" fill="#ffffff"/>'
        f'<g fill="#000000">{"".join(rects)}</g></svg>'
    )
