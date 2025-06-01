from __future__ import annotations
import sqlite3
import json
from pathlib import Path
from typing import Any, Optional

from models.core import UserInDB


class SQLiteDB:
    def __init__(self, db_path: str = "data/users.db") -> None:
        self.db_path = db_path
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    data TEXT NOT NULL
                )
            """)
            conn.commit()

    def get_user_by_username(self, username: str) -> Optional[dict[str, Any]]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT data FROM users WHERE username = ?", (username.strip().lower(),)
            )
            row = cursor.fetchone()
            return json.loads(row[0]) if row else None

    def delete_user(self, username: str) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM users WHERE username = ?", (username.strip().lower(),))
            conn.commit()

    def save_user(self, user: UserInDB, allow_update: bool = False) -> None:
        data = json.dumps(user.dict(exclude_none=True))
        with sqlite3.connect(self.db_path) as conn:
            if allow_update:
                conn.execute("""
                    INSERT INTO users (username, data) VALUES (?, ?)
                    ON CONFLICT(username) DO UPDATE SET data=excluded.data
                """, (user.username.strip().lower(), data))
            else:
                conn.execute("INSERT INTO users (username, data) VALUES (?, ?)", (user.username.strip().lower(), data))
            conn.commit()

    def query_usernames_by_index(self, index_key: str, index_value: str) -> list[str]:
        matched_usernames = []
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT username, data FROM users")
            for username, raw_data in cursor.fetchall():
                user_data = json.loads(raw_data)
                keys = index_key.split(".")
                value = user_data
                try:
                    for key in keys:
                        value = value[key]
                    if value == index_value:
                        matched_usernames.append(username)
                except (KeyError, TypeError):
                    continue
        return matched_usernames

    def update_user_field(self, username: str, field: str, value: Any) -> None:
        user_data = self.get_user_by_username(username)
        if not user_data:
            raise ValueError(f"User {username} not found")

        keys = field.split(".")
        target = user_data
        for key in keys[:-1]:
            target = target.setdefault(key, {})
        target[keys[-1]] = value

        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE users SET data = ? WHERE username = ?",
                (json.dumps(user_data), username.strip().lower())
            )
            conn.commit()
