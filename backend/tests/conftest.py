"""Makes `backend/` importable as the root for `app.*` regardless of where pytest is invoked
from or how it auto-detects rootdir -- explicit beats relying on import-mode defaults."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from app import db


@pytest.fixture()
def temp_db(tmp_path, monkeypatch):
    """A throwaway SQLite database for tests that touch db.py -- isolated per test, never the
    real HOMEATLAS_DB_PATH."""
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "test.db"))
    db.init_db()
    return db
