from datetime import datetime
from hmac import new
from hashlib import sha1
from base64 import b32decode

import time

class TOTP:
    def __init__(self, secret, name="NOT SET", digits=6):
        self.name = name.upper()
        self.__secret = secret
        self.__digits = digits
        self.__last_updated = time.time()

        self.__counter = None

        self.totp = None

        self.__update_counter()
        self.__set_hotp()

    def __str__(self):
        return f"{self.name:<10}:  {self.get_totp_fmt()}"

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
        """
        Generate an HMAC-based One-Time Passwords (HOTP) code.

        :param self:
        """

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
        """
        Method to check if the current TOTP is 30 seconds old or older based
        on the last_updated member variable. Returns true if the TOTP is old,
        false otherwise.

        :param self:
        """

        current_time = time.time()

        if (current_time - self.__last_updated.timestamp()) >= 30:
            return True

        return False

    def get_totp_fmt(self):
        """
        Prints the current TOTP in the format `xxx xxx`.

        :param self:
        """
        self.get_totp()

        return self.totp[:3] + " " + self.totp[3:]

    def get_totp(self):
        """
        Generate a TOTP code for the current time.

        :param self:
        """
        if self.__is_old():
            self.__update_counter()
            self.__set_hotp()

        return self.totp


