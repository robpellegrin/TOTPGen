"""
@file    add.py
@author  Rob Pellegrin
@date    06/04/2026
@license MIT License

TODO:
    - Inputs need to be validated!

"""

import datetime
import sqlite3
from collections import namedtuple

from totpgen.totp_store import TotpSecretStore

Token = namedtuple("Token", ["name", "secret", "issuer", "date"])


def add() -> None:
    try:
        token = [
            input("name: "),
            input("secret: "),
            input("issuer: "),
            datetime.datetime.now(),
        ]
    except KeyboardInterrupt:
        print("")
        raise SystemExit

    for i in token:
        print(i)

    tup = tuple(token)

    with TotpSecretStore() as db:
        try:
            db.add(tup)
        except sqlite3.IntegrityError:
            print(f'Token "{token.name}" already exists in ')
