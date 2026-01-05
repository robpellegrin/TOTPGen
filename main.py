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

from sys import argv
from PyQt6.QtWidgets import QApplication

from totp import TOTP
from secrets import SecretsFile
from view import MainWindow


def load_secrets(file_contents):
    """
    Loads secret key-values pairs from a given file.
    Secrets are expected to be formatted as `key=value`, with one pair
    per line.

    :param filepath: Path to file containing secrets.
    :return: A list of instantiated TOTP objects from the key-value
             pairs in the input file.
    """

    totp_list = []

    # try:
    #     with open(filepath, "r", encoding="UTF-8") as file:
    #         file_contents = file.readlines()

    # except FileNotFoundError as e:
    #     raise FileNotFoundError(f"Could not open file at {filepath}") from e

    # except PermissionError as e:
    #     raise PermissionError(f"Permission error opening {filepath}") from e

    pos = 0
    for line in file_contents:
        if len(line) <= 1:
            continue  # Skip empty lines

        print("LINE: " + line)
        key, value = line.split("=")

        pos += 1

        totp_list.append(TOTP(name=key.strip(), secret=value.strip()))
        totp_list.sort()

    return totp_list


def main():
    x = SecretsFile()
    slist = x.data
    print(slist)
    totp_list = load_secrets(slist)
    x.remove_entry("test1")
    x.finalize()

    app = QApplication(argv)

    window = MainWindow(totp_list)
    window.show()
    exit(app.exec())


if __name__ == "__main__":
    main()
