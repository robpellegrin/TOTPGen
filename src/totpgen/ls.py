"""
@file    ls.py
@author  Rob Pellegrin
@date    06/04/2026
@license MIT License

"""

from collections import namedtuple

from totpgen.totp_store import TotpSecretStore

Token = namedtuple("Token", ["name", "secret", "issuer", "date"])


def header() -> None:
    print("")
    print(
        f"{'Name':<30}"
        f"{'Issuer':<10}"
        f"{'Date':<20}"
    )

    print("-" * 60)


def ls(args) -> None:
    if args.table is True:
        header()

    with TotpSecretStore() as db:
        for entry in db.get_all():
            if args.table:
                token = Token(*entry)
                print(
                    f"{token.name:<30}"
                    f"{token.issuer:<10}"
                    f"{token.date:<20}"
                )
            else:
                print(*entry)

        print("")
