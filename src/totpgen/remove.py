"""
@file    remove.py
@author  Rob Pellegrin
@date    06/05/2026
@license MIT License

"""

from totpgen.totp_store import TotpSecretStore


def remove(args) -> None:
    with TotpSecretStore() as db:
        db.remove(args.name)
