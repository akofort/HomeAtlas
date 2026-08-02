"""Passwort-Wiederherstellung von der Kommandozeile.

    docker compose exec backend python -m app.reset_password
    docker compose exec backend python -m app.reset_password <benutzer> <neues-passwort>

Reason this exists: the generated first-run password is printed exactly once, to the startup log
of the container that created it. If that container is gone (crash loop, `docker compose down`,
log rotation) while the data volume survives, the account exists and nobody can get in --
`ADMIN_PASSWORD` deliberately only applies when no user exists yet, so it is no way back.

Running this requires shell access to the container, which already implies control of the host,
so it grants nothing an attacker in that position wouldn't have anyway.
"""
from __future__ import annotations

import secrets
import sys

from . import auth, db


def main(argv: list[str]) -> int:
    db.init_db()

    if len(argv) == 0:
        users = db.list_users()
        if not users:
            print("Es existiert noch kein Benutzer. Beim nächsten Start wird automatisch einer angelegt.")
            return 0
        print(f"{len(users)} Benutzer:")
        for user in users:
            print(f"  {user['username']:<20} {user['role']}")
        print("\nPasswort ändern:")
        print("  python -m app.reset_password <benutzer> <neues-passwort>")
        return 0

    if len(argv) != 2:
        print("Aufruf: python -m app.reset_password [<benutzer> <neues-passwort>]", file=sys.stderr)
        return 2

    username, password = argv
    if len(password) < 8:
        print("Das Passwort muss mindestens 8 Zeichen haben.", file=sys.stderr)
        return 2

    salt = secrets.token_hex(16)
    password_hash = auth.hash_password(password, salt)
    user = db.get_user_by_username_raw(username)

    if user is None:
        db.create_user(username, password_hash, salt, auth.ROLE_ADMIN)
        print(f"Benutzer '{username}' wurde neu als Administrator angelegt.")
    else:
        db.set_user_password(user["id"], password_hash, salt)
        print(f"Passwort für '{username}' ({user['role']}) wurde geändert.")

    print("Bestehende Sitzungen bleiben gültig -- zum Aussperren zusätzlich das Volume neu anlegen.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
