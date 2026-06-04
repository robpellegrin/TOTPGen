"""
@file    cli.py
@author  Rob Pellegrin
@date    05/27/2026
@license MIT License

Command line args for TOTPGen

TODO:
    + Implement sub-commands:
        - add: add a new secret.
        - remove: remove a secret (using its name).
        - rename: change the name associated with a secret.
    + Implement flag to toggle GUI/CLI.
"""

import argparse
from typing import Callable

from totpgen.add import add


def place_holder() -> None: ...


def init_add_subcommand(
    parser: argparse.ArgumentParser,
) -> argparse.ArgumentParser:
    """ """

    add_parser = parser.add_parser(name="add", help="Add a new secret")
    add_parser.set_defaults(func=add)

    add_parser.add_argument(
        "-n",
        "--name",
        type=str,
        help="Name of service associated with secret.",
    )

    return parser


def init_remove_subcommand(
    parser: argparse.ArgumentParser,
) -> argparse.ArgumentParser:
    """ """

    remove_parser = parser.add_parser(name="remove", help="Remove secret")
    remove_parser.set_defaults(func=place_holder)

    return parser


def init_rename_subcommand(
    parser: argparse.ArgumentParser,
) -> argparse.ArgumentParser:
    """ """

    rename_parser = parser.add_parser(name="rename", help="Rename secret")
    rename_parser.set_defaults(func=place_holder)

    return parser


def init_ls_subcommand(
    parser: argparse.ArgumentParser,
) -> argparse.ArgumentParser:
    """ """

    rename_parser = parser.add_parser(name="ls", help="List all secrets")
    rename_parser.set_defaults(func=place_holder)

    return parser


def init_args() -> argparse.ArgumentParser:
    subcommands: list[Callable] = [
        init_ls_subcommand,
        init_add_subcommand,
        init_remove_subcommand,
        init_rename_subcommand,
    ]

    parser = argparse.ArgumentParser(
        prog="totp",
        description="A minimal, dependency free TOTP generator.",
    )

    subparser = parser.add_subparsers(
        title="Commands",
        dest="subcommands",
    )

    for func in subcommands:
        func(subparser)

    subparser.add_parser(
        name="remove", description="Add a new secret"
    ).set_defaults(func=place_holder)

    subparser.add_parser(name="rename", description="Rename").set_defaults(
        func=place_holder
    )

    return parser


def get_args() -> argparse.Namespace:
    parser = init_args()
    args = parser.parse_args()

    if args.subcommands is None:
        parser.print_help()
        raise SystemExit

    return args
