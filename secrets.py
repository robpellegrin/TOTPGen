import os
import hashlib
import base64
from cryptography.fernet import Fernet


class SecretsFile:
    def __init__(self, path_to_key="~/.ssh/id_rsa"):
        self.data = []
        self.__key_file = os.path.expanduser(path_to_key)
        self.__db_path = "secrets.db"
        self.__updated = False

        self.read_keyfile()

        self.__cipher_suite = self.derive_key()

        self.decrypt_db()
        self.check_new_entry()

    def remove_entry(self, entry_to_remove):
        print(f"Removing {entry_to_remove}")
        try:
            self.data.remove(entry_to_remove)
            self.__updated = True
        except ValueError:
            pass

    def check_new_entry(self):
        try:
            with open("./secret.txt", "r", encoding="UTF-8") as f:
                self.__updated = True
                for line in f.readlines():
                    if len(line) > 1:
                        line = line.strip()
                        self.data.append(line)  # += "\n" + line + "\n"
                        print("APPENDING: " + line)
            try:
                os.remove("./secret.txt")
            except PermissionError:
                print("WARNING! Failed to delete secret.txt")

        except FileNotFoundError:
            pass

    def read_keyfile(self):
        try:
            with open(self.__key_file, "rb") as key_file:
                self.__key_file = key_file.read()
        except FileNotFoundError as e:
            raise FileNotFoundError from e

    def derive_key(self):
        # Use SHA256 to hash the ssh key
        key = hashlib.sha256(self.__key_file).digest()
        return Fernet(base64.urlsafe_b64encode(key))

    def encrypt_data(self):
        if self.__updated is False:
            return

        self.data = str(self.data)

        self.data = self.data.encode("UTF-8")
        encrypted_data = self.__cipher_suite.encrypt(self.data)

        # Encode the encrypted data to base64
        encrypted_data_b64 = base64.b64encode(encrypted_data).decode("utf-8")

        try:
            # Save encrypted string to a text file
            with open(self.__db_path, "w", encoding="UTF-8") as file:
                for line in self.data:
                    file.write(encrypted_data_b64)
        except PermissionError as e:
            raise PermissionError from e

    def decrypt_db(self):
        try:
            with open(self.__db_path, "r", encoding="UTF-8") as file:
                # encrypted_data_b64 = file.readlines()
                file_contents = file.readlines()
                for encrypted_data_b64 in file_contents:

                    # Decode the base64 string to get the original encrypted data
                    encrypted_data = base64.b64decode(encrypted_data_b64)
                    decrypted_data = self.__cipher_suite.decrypt(encrypted_data)

                    self.data.append(decrypted_data.decode("UTF-8"))

        except FileNotFoundError:
            pass

    def finalize(self):
        if self.__updated is True:
            self.encrypt_data()
