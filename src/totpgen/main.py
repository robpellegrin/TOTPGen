"""
@file    main.py
@author  Rob Pellegrin
@date    06/04/2025
@license MIT License


"""

from totpgen import cli


def main() -> None:
    args = cli.get_args()

    # Call function associated with sub-command.
    args.func()


if __name__ == "__main__":
    main()
