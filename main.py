"""
TOTPGen: A simple Python program for generating Time-based One-Time
Passwords (TOTP) with minimal dependencies.

Dependencies:
    - Requires Python 3.x and no additional libraries.

Author:  Rob Pellegrin
Date:    12/29/2025
Updated: 1/3/2026
License: MIT License

https://www.ietf.org/rfc/inline-errata/rfc6238.html
"""

from sys import exit, argv
from PyQt6.QtWidgets import QApplication

from totp import TOTP
from view import MainWindow
from totp import TOTP


def load_secrets(filepath):
    """
    Loads secret key-values pairs from a given file.
    Secrets are expected to be formatted as `key=value`, with one pair
    per line.

    :param filepath: Path to file containing secrets.
    :return: A list of instantiated TOTP objects from the key-value
             pairs in the input file.
    """

    totp_list = []

    try:
        with open(filepath, "r") as file:
            file_contents = file.readlines()

    except FileNotFoundError:
        raise FileNotFoundError(f"Could not open file at {filepath}")

    except PermissionError:
        raise PermissionError(f"Permission error on when opening {filepath}")

    for line in file_contents:
        if len(line) <= 1:
            continue  # Skip empty lines

        key, value = line.split("=")
        totp_list.append(TOTP(name=key.strip(), secret=value.strip()))

    return totp_list


def main():
    app = QApplication(argv)

    totp_list = load_secrets(".env")

    window = MainWindow(totp_list)
    window.show()

    exit(app.exec())


if __name__ == "__main__":
    main()
