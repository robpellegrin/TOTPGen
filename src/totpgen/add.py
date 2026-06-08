"""
@file    add.py
@author  Rob Pellegrin
@date    06/04/2026
@license MIT License

TODO:
    - Inputs need to be validated!
    - Optional table formatting.

"""

import datetime
import sqlite3
from collections import namedtuple

from totpgen.totp_store import TotpSecretStore

Token = namedtuple("Token", ["name", "secret", "issuer", "date"])


def add(args) -> None:
    date = datetime.datetime.now().strftime("%Y/%m/%d")

    try:
        token = [
            input("name: "),
            input("secret: "),
            input("issuer: "),
            date,
        ]
    except KeyboardInterrupt:
        print("")
        raise SystemExit

    tup = tuple(token)

    with TotpSecretStore() as db:
        try:
            db.add(tup)
        except sqlite3.IntegrityError:
            print(f'Token "{token[0]}" already exists in ')
