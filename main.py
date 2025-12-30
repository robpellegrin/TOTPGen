"""
TOTPGen: A simple Python module for generating Time-based One-Time Passwords (TOTP) with minimal dependencies.

This module provides functionality to generate secure one-time passwords
using a shared secret.

Usage:

Dependencies:
    - Requires Python 3.x and no additional libraries.

Author:  Rob Pellegrin
Date:    12/29/2025
Updated: 12/29/2025
License: MIT License

https://www.ietf.org/rfc/inline-errata/rfc6238.html
"""

from datetime import datetime, timedelta
from hmac import new
from hashlib import sha1

import time

TIME_STEP = 30


class TOTP:
    def __init__(self, secret, digits=6, adjusted_time=None):
        self.secret = secret
        self.digits = digits
        self.adjusted_time = adjusted_time
        self.last_updated = time.time()
        self.counter = None
        self.totp = None

        self.__update_counter()

    def __b32decode(self, encoded_str):
        """Performs Bas32Decode. Can be replaced with a call to: `base64.b32decode(secret_padded, casefold=True))`."""

        # Define the Base32 alphabet
        BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        decoded_bytes = bytearray()

        # Convert the encoded string to uppercase
        encoded_str = encoded_str.upper().strip()

        # Remove padding characters
        padding_len = len(encoded_str) % 8
        if padding_len:
            encoded_str += "=" * (8 - padding_len)

        # Process each chunk of 8 characters
        for i in range(0, len(encoded_str), 8):
            chunk = encoded_str[i : i + 8]
            bits = 0
            for char in chunk:
                if char == "=":
                    bits += 5  # Skip padding
                    continue

                bits = (bits << 5) | BASE32_ALPHABET.index(char)

            # Append the decoded bytes
            for j in range(5):
                if (bits >> (8 * (4 - j))) & 0xFF:
                    decoded_bytes.append((bits >> (8 * (4 - j))) & 0xFF)

        return bytes(decoded_bytes)

    def __custom_pack_q(self, value):
        """Pack an unsigned long long (8 bytes) into binary format. Can be placed with call to: `struct.pack(">Q", self.counter)`."""

        if not isinstance(value, int) or value < 0:
            raise ValueError(
                f"Value must be a non-negative integer, received `{value}`"
            )

        # Convert value to 8 bytes in big-endian.
        return value.to_bytes(length=8, byteorder="big")

    def __get_hotp(self):
        """Generate an HMAC-based One-Time Passwords (HOTP) code."""

        # Base32 decoding: Pads with '=' if necessary and converts the secret to bytes.
        secret_padded = self.secret.upper() + "=" * ((8 - len(self.secret) % 8) % 8)
        secret_bytes = self.__b32decode(secret_padded)

        # Convert the counter to a 64-bit, big-endian integer.
        counter_bytes = self.__custom_pack_q(self.counter)

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
        return str(truncated % (10**self.digits)).zfill(self.digits)

    def __update_counter(self):
        if self.adjusted_time is None:
            self.counter = int(time.time() // TIME_STEP)
            return

        adjusted_datetime = datetime.strptime(self.adjusted_time, "%Y-%m-%d %H:%M:%S")

        temp_counter = abs((datetime.now() - adjusted_datetime).total_seconds())

        self.counter = int(temp_counter // TIME_STEP)
        self.last_updated = datetime.now()

    def get_totp(self):
        """Generate a TOTP code for the current time."""

        return self.__get_hotp()


if __name__ == "__main__":
    secrets_dict = {}
    file_contents = []

    try:
        with open("./.env", "r") as file:
            file_contents = file.readlines()

    except FileNotFoundError:
        pass

    for line in file_contents:
        key, value = line.split("=")
        secrets_dict[key.strip()] = value.strip()

    test = "I65VU7K5ZQL7WB4E"

    totp = TOTP(test)

    while True:
        print(totp.get_totp())
        time.sleep(5)
