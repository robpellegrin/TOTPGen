"""
Author:  Rob Pellegrin
Date:    12/29/2025
File:    totp.py

Updated: 1/3/2026
License: MIT License

A class to generate Time-Based One-Time Passwords (TOTP) using
an HMAC-based One-Time Password (HOTP) algorithm.

This class utilizes a secret key and the current time to generate
a password that is valid for a short duration (default is 30 seconds).
The generated TOTP can be used with two-factor authentication (2FA)
systems.

Attributes:
    secret (str): The base32 encoded secret key used to generate the TOTP.
    digits (int): The number of digits in the TOTP (default is 6).
    last_updated (float): The last time the TOTP was updated (timestamp).
    counter (int): The time-based counter derived from the current time.
    name (str): An optional name to identify the TOTP instance.
    account (str): An optional account identifier, such as an email.

Methods:
    __str__(): Returns a formatted string representation of the TOTP instance.
    get_totp(): Generates and returns the current TOTP code.
    get_totp_fmt(): Returns the current TOTP in a formatted string of the
                    form `xxx xxx`.
    __is_old(): Checks if the current TOTP is old (30 seconds or older).
    __update_counter(): Updates the TOTP counter based on the current time.
    __set_hotp(): Generates the TOTP based on the current counter and
                   secret.
    __custom_pack_q(value): Packs an unsigned long long integer into
                            binary format.

Example:
    totp = TOTP(secret="JBSWY3DPEHPK3PXP", name="My Account", account=
                    "user@example.com")
    print(totp)  # Display the TOTP in a formatted way
    print(totp.get_totp())  # Fetch the current TOTP
    print(totp.get_totp_fmt())  # Fetch the current TOTP in formatted style

https://www.ietf.org/rfc/inline-errata/rfc6238.html
"""

from datetime import datetime
from hmac import new
from hashlib import sha1
from base64 import b32decode

from time import time


class TOTP:
    def __init__(self, secret, name="NOT SET", account="your@email.com", digits=6):
        self.__secret = secret.upper()
        self.__digits = digits
        self.__last_updated = time()

        self.__counter = None

        self.name = name
        self.totp = None
        self.account = account.lower()

        self.__update_counter()
        self.__set_hotp()

    def __str__(self):
        """Allows TOTP objects to be used with the built-in print
        function."""
        return f"{self.name:<10}:  {self.get_totp_fmt()}"

    def __lt__(self, other):
        """
        Allows for TOTP objects to be sorted with the built-in sort
        function. TOTP objects are sorted using using the `name` member
        variable.
        """
        return self.name < other.name

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

        # Base32 decoding: Pads with '=' if necessary and converts the secret
        # to bytes.
        secret_padded = self.__secret + "=" * ((8 - len(self.__secret) % 8) % 8)
        secret_bytes = b32decode(secret_padded, casefold=True)

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
        """Updates the TOTP counter based on the current time."""

        time_step = 30

        self.__counter = int(time() // time_step)
        self.__last_updated = datetime.now()

    def __is_old(self):
        """
        Checks if the current TOTP is 30 seconds old, or older, based
        on the last_updated member variable. Returns true if the TOTP is old,
        false otherwise.
        """

        current_time = time()

        if (current_time - self.__last_updated.timestamp()) >= 30:
            return True

        return False

    def get_totp_fmt(self):
        """Prints the current TOTP in the format `xxx xxx`."""
        self.get_totp()

        return self.totp[:3] + " " + self.totp[3:]

    def get_totp(self):
        """Generate a TOTP code for the current time."""
        if self.__is_old():
            self.__update_counter()
            self.__set_hotp()

        return self.totp
