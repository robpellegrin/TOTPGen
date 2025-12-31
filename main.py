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

from datetime import datetime
from hmac import new
from hashlib import sha1
from base64 import b32decode

import time


class TOTP:
    def __init__(self, secret, name="NOT SET", digits=6):
        self.name = name
        self.__secret = secret
        self.__digits = digits
        self.__last_updated = time.time()

        self.__counter = None

        self.totp = None

        self.__update_counter()
        self.__set_hotp()

    def __custom_pack_q(self, value):
        """
        Pack an unsigned long long (8 bytes) into binary format. Can be
        placed with call to: `struct.pack(">Q", self.counter)`.
        """

        if not isinstance(value, int) or value < 0:
            raise ValueError(
                f"Value must be a non-negative integer, received `{value}`"
            )

        # Convert value to 8 bytes in big-endian.
        return value.to_bytes(length=8, byteorder="big")

    def __set_hotp(self):
        """Generate an HMAC-based One-Time Passwords (HOTP) code."""

        # Base32 decoding: Pads with '=' if necessary and converts the secret to bytes.
        secret_padded = self.__secret.upper() + "=" * ((8 - len(self.__secret) % 8) % 8)
        secret_bytes = b32decode(
            secret_padded, casefold=True
        )  # self.__b32decode(secret_padded)

        # Convert the counter to a 64-bit, big-endian integer.
        counter_bytes = self.__custom_pack_q(self.__counter)

        # Calculate HMAC-SHA1 digest
        hmac_digest = new(secret_bytes, counter_bytes, sha1).digest()

        # Use the last 4 bits of the HMAC digets as an offest (0-15).
        offset = hmac_digest[-1] & 15

        # Extract 4 bytes starting from the offset and convert to a 32-bit integer.
        # The most significant bit is masked off (127) to prevent overflow/sign issues.
        truncated = (
            (hmac_digest[offset] & 127) << 24
            | (hmac_digest[offset + 1] & 255) << 16
            | (hmac_digest[offset + 2] & 255) << 8
            | (hmac_digest[offset + 3] & 255)
        )

        # Calculate the final code by taking the integer modulo 10^digits.
        self.totp = str(truncated % (10**self.__digits)).zfill(self.__digits)

    def __update_counter(self):
        TIME_STEP = 30

        self.__counter = int(time.time() // TIME_STEP)
        self.__last_updated = datetime.now()

    def __is_old(self):
        if time.time() - self.__last_updated.timestamp() >= 30:
            return True

        return False

    def get_totp_fmt(self):
        """Prints the TOTP in the format `xxx xxx`."""
        self.get_totp()
        return self.totp[0:3] + " " + self.totp[3:]

    def get_totp(self):
        """Generate a TOTP code for the current time."""
        if self.__is_old():
            self.__update_counter()
            self.__set_hotp()

        return self.totp


def load_secrets(filepath):
    """
    Loads secret key-values pairs from a given file.

    :param filepath: Path to file containing secrets.
    """

    secrets_dict = {}
    file_contents = []

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


if __name__ == "__main__":
    secrets_dict = load_secrets(".env")

    totp = TOTP(secrets_dict["test"])

    while True:
        print(totp.get_totp())
        time.sleep(5)
