import random
import string
import math
import time
import colorama as cr


def cyan(text: str): return cr.Fore.CYAN + text + cr.Fore.RESET
def red(text: str): return cr.Fore.RED + text + cr.Fore.RESET
def magenta(text: str): return cr.Fore.MAGENTA + text + cr.Fore.RESET
def blue(text: str): return cr.Fore.BLUE + text + cr.Fore.RESET
def green(text: str): return cr.Fore.GREEN + text + cr.Fore.RESET


class EncryptionManager:
    def __init__(self,
                 key: str = "".join(
                     [char for char in random.sample(string.printable, 30) if char not in string.whitespace]
                 ),
                 seed: int = random.randint(1, 1100)):
        self.key = key
        self.seed = seed

    def encrypt(self, path: str, key: str = None, seed: int = None):
        if not path.endswith(".txt"):
            raise self.FileTypeNotSupported("FileTypeNotSupported: The file type passed is not supported.")

        if key is None:
            self.key = "".join(
                [char for char in random.sample(string.printable, 30) if char not in string.whitespace]
            )
        else:
            self.key = key
        if seed is None:
            self.seed = random.randint(1, 1100)
        else:
            self.seed = seed
            if not 1100 >= self.seed >= 0:
                raise self.InvalidSeedError("InvalidSeed: seed number is out of range")

        print(f"Key: {magenta(self.key)}")
        print(f"Seed: {blue(str(self.seed))}")
        try:
            with open(path, 'r', encoding="utf-8") as file:
                content = file.read()
        except FileNotFoundError:
            raise self.FileNotFoundError

        encrypted = ""

        slices = []
        for index in range(0, len(content), len(self.key)):
            slices.append(content[index: index + len(self.key)])

        slice_index = 0
        for _slice in slices:
            slice_index += 1
            if slice_index % 2 == 0:
                ordered_key = reversed(self.key)
            else:
                ordered_key = self.key
            for char, key_char in zip(_slice, ordered_key):
                try:
                    new_ord = ord(char) + ord(key_char) + int(math.sqrt(self.seed))
                    encrypted += chr(new_ord)
                except ValueError:
                    raise self.InvalidKeyError(
                        "InvalidKeyError: The key passed is not Valid or doesn't match to the target passed")

        with open(path[:path.find('.')] + ".enc", 'w', encoding="utf-8") as enc_file:
            enc_file.write(encrypted)

    def decrypt(self, path: str, key: str, seed: int):
        if not path.endswith(".enc"):
            raise self.FileTypeNotSupported("FileTypeNotSupported: The file type passed is not supported.")
        self.key, self.seed = key, seed
        if not 1100 >= self.seed >= 0:
            raise self.InvalidSeedError("InvalidSeed: seed number is out of range")

        try:
            with open(path, 'r', encoding="utf-8") as file:
                content = file.read()
        except FileNotFoundError:
            raise self.FileNotFoundError

        decrypted = ""

        slices = []
        for index in range(0, len(content), len(self.key)):
            slices.append(content[index: index + len(self.key)])

        slice_index = 0
        for _slice in slices:
            slice_index += 1
            if slice_index % 2 == 0:
                ordered_key = reversed(self.key)
            else:
                ordered_key = self.key
            for char, key_char in zip(_slice, ordered_key):
                try:
                    new_ord = ord(char) - ord(key_char) - int(math.sqrt(self.seed))
                    decrypted += chr(new_ord)
                except ValueError:
                    raise self.InvalidKeyError(
                        "InvalidKeyError: The key passed is not Valid or doesn't match to the target passed")

        with open(path[:path.find('.')] + ".dec", 'w', encoding="utf-8") as dec_file:
            dec_file.write(decrypted)

    class InvalidSeedError(Exception): pass
    class InvalidKeyError(Exception): pass
    class FileTypeNotSupported(Exception): pass
    class FileNotFoundError(Exception): pass


def main():
    manager = EncryptionManager()
    while True:
        time.sleep(0.7)
        choices = [f"({cyan('e')}) Encrypt a file",
                   f"({cyan('d')}) Decrypt a file",
                   f"({cyan('q')}) Quit"]
        for ch in choices:
            print(ch)
        choice = input("What would you like to do?\n")
        if choice == "e":
            try:
                path = input(
                    "Enter the path of the file to encrypt\n[note that only files of type '.txt' are accepted]: ")
                while True:
                    choices = [f"({cyan('b')}) Both key and seed",
                               f"({cyan('n')}) Neither",
                               f"({cyan('k')}) Only key",
                               f"({cyan('s')}) Only seed", ]
                    for ch in choices:
                        print(ch)
                    prop = input("What property would you like to set?\n")
                    if prop == "b":
                        key = input("Enter the encryption key: ")
                        seed = int(input("Enter the encryption seed: "))
                        manager.encrypt(path, key=key, seed=seed)
                        break
                    elif prop == "n":
                        print("The encryption properties will be set randomly.")
                        manager.encrypt(path)
                        break
                    elif prop == "k":
                        key = input("Enter the encryption key: ")
                        manager.encrypt(path, key=key)
                        break
                    elif prop == "s":
                        seed = int(input("Enter the encryption seed: "))
                        manager.encrypt(path, seed=seed)
                        break
                    else:
                        print(red("Invalid choice, try again."))

                print(green("Successfully encrypted."))
            except manager.FileNotFoundError:
                print(red("The file wasn't found."))
            except manager.FileTypeNotSupported:
                print(red("Only '.txt' file type is supported."))
            except manager.InvalidSeedError:
                print(red("Seed should always be in range 0x1100"))
        elif choice == "d":
            try:
                path = input(
                    "Enter the path of the file to decrypt\n[note that only files of type '.enc' are accepted]: ")
                key = input("Enter the encryption key: ")
                seed = int(input("Enter the encryption seed: "))
                manager.decrypt(path, key=key, seed=seed)
                print(green("Successfully decrypted."))
            except manager.FileNotFoundError:
                print(red("The file wasn't found."))
            except manager.FileTypeNotSupported:
                print(red("Only '.enc' file type is supported."))
            except manager.InvalidSeedError:
                print(red("Seed should always be in range 0x1100"))
        elif choice == 'q':
            exit(0)
        else:
            print(red("Invalid choice, please try again"))


if __name__ == "__main__":
    main()
