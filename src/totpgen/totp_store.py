"""
@file    totp_store.py
@author  Rob Pellegrin
@date    05/28/2026
@license MIT License

"""

import sqlite3
from pathlib import Path
from types import TracebackType
from typing import Any, Self


class TotpSecretStore:
    """Manages connections to sqlite database containing TOTP secrets."""

    def __init__(self, db_path: str = "secrets.db") -> None:
        self.db = Path(db_path)

        self.conn = sqlite3.connect(db_path)
        self.cursor = self.conn.cursor()

    def add(self, entry: tuple[Any, ...]) -> None:
        sql = """
            INSERT INTO
            secrets(name, secret, issuer, added_on)
            VALUES(?,?,?,?)
        """
        self._execute(sql, entry)

    def get(self, name: str) -> tuple[str] | None:
        sql = """
            SELECT *
            FROM secrets
            WHERE name = ?
        """
        self._execute(sql, (name,))

        return self.cursor.fetchone()

    def get_all(self) -> list[tuple[Any, ...]]:
        sql = """
            SELECT *
            FROM secrets
        """

        self._execute(sql, tuple())

        return self.cursor.fetchall()

    def remove(self, name: str) -> None:
        sql = """
            DELETE
            FROM secrets
            WHERE name = ?
        """

        self._execute(sql, (name,))

    def update(self, old: str, new: str) -> None:
        sql = """
            UPDATE secrets
            SET name = ?
            WHERE name = ?
        """
        self._execute(sql, (new, old))

    def _execute(self, sql: str, tup: tuple[Any, ...]) -> None:
        try:
            self.cursor.execute(sql, tup)
        except sqlite3.IntegrityError:
            print("Integrity Error!")

    def _create_table(self) -> None:
        sql = """
            CREATE TABLE IF NOT EXISTS secrets (
                name text PRIMARY KEY,
                secret text NOT NULL,
                issuer text,
                added_on DATE
            );"""

        self._execute(sql, tuple())

    def __enter__(self) -> Self:
        self._create_table()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.conn.commit()
        self.conn.close()


def main() -> None:
    secret1 = (
        "github",
        "12-xx-xx-xx-",
        "github.com",
        "05/29/2026",
    )

    secret2 = (
        "google",
        "xx-99-xx-xx",
        "google.com",
        "09/29/2026",
    )

    with TotpSecretStore() as db:
        db.add(secret1)
        db.add(secret2)

        print(db.get("google"))

        db.remove("google")


if __name__ == "__main__":
    main()
