"""
@author  Rob Pellegrin
@date    12/29/2025
@updated 05/28/2026
@license MIT License

TOTPGen:
    A simple Python program for generating time-based one-time
    passwords (TOTP) from the command line with minimal dependencies.

https://www.ietf.org/rfc/inline-errata/rfc6238.html

"""

import os
from sys import argv

from PyQt6.QtWidgets import QApplication

from totp import TOTP
from view import MainWindow


def load_secrets(filepath):
    """
    Loads secret key-values pairs from a given file.
    Secrets are expected to be formatted as `key=value`, with one pair
    per line.

    Args
        filepath: Path to file containing secrets.

    Returns
        A list of instantiated TOTP objects from the key-value pairs
        in the input file.
    """

    totp_list = []

    try:
        with open(filepath, "r", encoding="UTF-8") as file:
            file_contents = file.readlines()

    except FileNotFoundError as e:
        raise FileNotFoundError(f"Could not open file at {filepath}") from e

    except PermissionError as e:
        raise PermissionError(f"Permission error opening {filepath}") from e

    for line in file_contents:
        if len(line) <= 1:
            continue  # Skip empty lines

        # Ignore comments
        if "#" in line:
            continue

        name, secret, account = line.split(",")

        totp_list.append(
            TOTP(
                name=name.strip(),
                secret=secret.strip(),
                account=account.strip(),
            )
        )
        totp_list.sort()

    return totp_list


def main():
    path_to_secrets = os.path.expanduser("~/.env")

    totp_list = load_secrets(path_to_secrets)

    app = QApplication(argv)

    window = MainWindow(totp_list)
    window.show()
    exit(app.exec())


if __name__ == "__main__":
    main()
