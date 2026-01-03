"""
TOTPGen: A simple Python module for generating Time-based One-Time Passwords (TOTP) with minimal dependencies.

This module provides functionality to generate secure one-time passwords
using a shared secret.

Usage:

Dependencies:
    - Requires Python 3.x and no additional libraries.

Author:  Rob Pellegrin
Date:    12/29/2025
Updated: 12/30/2025
License: MIT License

https://www.ietf.org/rfc/inline-errata/rfc6238.html
"""

from time import sleep
from totp import TOTP


def load_secrets(filepath):
    """
    Loads secret key-values pairs from a given file.
    Secrets are expected to be formatted as `key=value`, with one pair
    per line.

    :param filepath: Path to file containing secrets.
    """

    secrets_dict = {}

    try:
        with open(filepath, "r") as file:
            file_contents = file.readlines()

    except FileNotFoundError:
        raise FileNotFoundError(f"Could not open file at {filepath}")

    except PermissionError:
        raise PermissionError(f"Permission error on when opening {filepath}")

    for line in file_contents:
        # Skip empty lines
        if len(line) <= 1:
            continue

        key, value = line.split("=")

        secrets_dict[key.strip()] = value.strip()

    return secrets_dict


def main():
    secrets_dict = load_secrets(".env")

    totp_list = [TOTP(name=key, secret=value) for key, value in secrets_dict.items()]

    while True:
        for totp in totp_list:
            print(totp)

        print()

        try:
            sleep(5)
        except KeyboardInterrupt:
            return


if __name__ == "__main__":
    main()
