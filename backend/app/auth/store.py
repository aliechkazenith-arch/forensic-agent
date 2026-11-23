"""SQLite Storage & Lifecycle Management for RBAC Investigator Accounts.

Standards:
- Local-first SQLite store (vault/users.db)
- Cryptographic password storage (bcrypt hashes only)
- Case-insensitive username and badge ID resolution
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
from uuid import uuid4

from backend.app.auth.models import UserCreate, UserRead, UserRole


class UserStore:
    """Thread-safe SQLite store for investigator credentials and role assignments."""

    def __init__(self, db_path: Optional[Union[str, Path]] = None):
        """Initialize UserStore. Uses ':memory:' if db_path is None or ':memory:'."""
        if db_path is None or str(db_path) == ":memory:":
            self._db_path = ":memory:"
        else:
            p = Path(db_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            self._db_path = str(p)

        self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
        self._init_tables()

    def _init_tables(self) -> None:
        """Create users table with unique constraints and role checks."""
        with self._conn:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    badge_id TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL CHECK(role IN ('lead_investigator', 'soc_analyst', 'auditor')),
                    full_name TEXT,
                    is_active INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    account_type TEXT NOT NULL DEFAULT 'human' CHECK(account_type IN ('human', 'service_account', 'agent'))
                );
                """
            )
            try:
                self._conn.execute("ALTER TABLE users ADD COLUMN account_type TEXT NOT NULL DEFAULT 'human';")
            except sqlite3.OperationalError:
                pass
            self._conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username COLLATE NOCASE);")
            self._conn.execute("CREATE INDEX IF NOT EXISTS idx_users_badge_id ON users(badge_id COLLATE NOCASE);")

    def count_users(self) -> int:
        """Count total registered investigator accounts."""
        cursor = self._conn.execute("SELECT COUNT(*) FROM users;")
        row = cursor.fetchone()
        return row[0] if row else 0

    def count_active_users(self) -> int:
        """Count active investigator accounts."""
        cursor = self._conn.execute("SELECT COUNT(*) FROM users WHERE is_active = 1;")
        row = cursor.fetchone()
        return row[0] if row else 0

    def create_user(
        self,
        user_in: UserCreate,
        password_hash: str,
        user_id: Optional[str] = None,
    ) -> UserRead:
        """Register a new investigator account."""
        uid = user_id or str(uuid4())
        created_at = datetime.now(timezone.utc).isoformat()

        acct_type = getattr(user_in, "account_type", "human") or "human"
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO users (
                    id, username, badge_id, password_hash, role,
                    full_name, is_active, created_at, account_type
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    uid,
                    user_in.username.strip(),
                    user_in.badge_id.strip(),
                    password_hash,
                    user_in.role,
                    user_in.full_name.strip() if user_in.full_name else None,
                    1 if user_in.is_active else 0,
                    created_at,
                    acct_type,
                ),
            )

        return UserRead(
            id=uid,
            username=user_in.username.strip(),
            badge_id=user_in.badge_id.strip(),
            role=user_in.role,
            account_type=acct_type,
            full_name=user_in.full_name.strip() if user_in.full_name else None,
            is_active=user_in.is_active,
            created_at=created_at,
        )

    def get_by_username(self, username: str) -> Optional[Tuple[UserRead, str]]:
        """Retrieve user profile and password hash by username (case-insensitive)."""
        cursor = self._conn.execute(
            """
            SELECT id, username, badge_id, password_hash, role, full_name, is_active, created_at, account_type
            FROM users
            WHERE LOWER(username) = LOWER(?);
            """,
            (username.strip(),),
        )
        row = cursor.fetchone()
        if not row:
            return None

        acct_type = row[8] if len(row) > 8 and row[8] else "human"
        user = UserRead(
            id=row[0],
            username=row[1],
            badge_id=row[2],
            role=row[4],
            account_type=acct_type,
            full_name=row[5],
            is_active=bool(row[6]),
            created_at=row[7],
        )
        return user, row[3]

    def get_by_badge_id(self, badge_id: str) -> Optional[Tuple[UserRead, str]]:
        """Retrieve user profile and password hash by badge ID (case-insensitive)."""
        cursor = self._conn.execute(
            """
            SELECT id, username, badge_id, password_hash, role, full_name, is_active, created_at, account_type
            FROM users
            WHERE LOWER(badge_id) = LOWER(?);
            """,
            (badge_id.strip(),),
        )
        row = cursor.fetchone()
        if not row:
            return None

        acct_type = row[8] if len(row) > 8 and row[8] else "human"
        user = UserRead(
            id=row[0],
            username=row[1],
            badge_id=row[2],
            role=row[4],
            account_type=acct_type,
            full_name=row[5],
            is_active=bool(row[6]),
            created_at=row[7],
        )
        return user, row[3]

    def get_by_id(self, user_id: str) -> Optional[UserRead]:
        """Retrieve user profile by primary UUID."""
        cursor = self._conn.execute(
            """
            SELECT id, username, badge_id, role, full_name, is_active, created_at, account_type
            FROM users
            WHERE id = ?;
            """,
            (user_id,),
        )
        row = cursor.fetchone()
        if not row:
            return None

        acct_type = row[7] if len(row) > 7 and row[7] else "human"
        return UserRead(
            id=row[0],
            username=row[1],
            badge_id=row[2],
            role=row[3],
            account_type=acct_type,
            full_name=row[4],
            is_active=bool(row[5]),
            created_at=row[6],
        )

    def list_users(self) -> List[UserRead]:
        """List all registered investigator accounts."""
        cursor = self._conn.execute(
            """
            SELECT id, username, badge_id, role, full_name, is_active, created_at, account_type
            FROM users
            ORDER BY created_at ASC;
            """
        )
        rows = cursor.fetchall()
        return [
            UserRead(
                id=r[0],
                username=r[1],
                badge_id=r[2],
                role=r[3],
                account_type=r[7] if len(r) > 7 and r[7] else "human",
                full_name=r[4],
                is_active=bool(r[5]),
                created_at=r[6],
            )
            for r in rows
        ]

    def update_user_status(self, user_id: str, is_active: bool) -> Optional[UserRead]:
        """Toggle an account between active and suspended."""
        with self._conn:
            cursor = self._conn.execute(
                "UPDATE users SET is_active = ? WHERE id = ?;",
                (1 if is_active else 0, user_id),
            )
            if cursor.rowcount == 0:
                return None

        return self.get_by_id(user_id)

    def close(self) -> None:
        """Close SQLite database connection."""
        if hasattr(self, "_conn") and self._conn:
            self._conn.close()
