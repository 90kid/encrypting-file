import base64
import sys

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# TODO read this and write better code
"""
Usefull urls to end this project 
https://security.stackexchange.com/questions/17421/how-to-store-salt
https://crypto.stackexchange.com/questions/3484/pbkdf2-and-salt
https://stackoverflow.com/questions/2490334/simple-way-to-encode-a-string-according-to-a-password
https://stackabuse.com/command-line-arguments-in-python
https://docs.python.org/3/library/hashlib.html
https://stackoverflow.com/questions/55105045/python-invalid-base64-encoded-string-number-of-data-characters-5-cannot-be-1
"""
SALT = b'1234567812345678'  # TODO should I keep it like this?
CHARACTER_ENCODING = 'utf-8' # maybe should be in config?
arguments = [
    'FILE_NAME',
    'KEY',
    'MODE',
    'OUTPUT_FILE_NAME'
]


# TODO set default OUTPUT_FILE_NAME as output or sth like this
# TODO add description to all functions

def prepare_arguments() -> dict:
    if len(sys.argv) != 5:
        print('Wrong number of arguments required 4 filepath key e/d output')
        exit(2)

    application_config = {}
    for count, argument in enumerate(arguments):
        application_config[argument] = sys.argv[count + 1]

    return application_config


def read_file(file_name: str) -> bytes:
    with open(file_name, 'rb') as file:
        file_in_bytes = file.read()

    return file_in_bytes


def encrypt_decrypt_file(file_bytes: bytes, mode: str, secret_key: str) -> bytes:
    key = generate_fernet_key(secret_key)
    if mode == 'e':
        encryption_type = Fernet(key)
        return encryption_type.encrypt(file_bytes)
    elif mode == 'd':
        encryption_type = Fernet(key)
        return encryption_type.decrypt(file_bytes)
    else:
        print('Wrong argument only e/d available')
        exit(2)


def generate_fernet_key(secret_key: str) -> bytes:
    # Done https://cryptography.io/en/latest/fernet/#using-passwords-with-fernet
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=100000,
    )
    secret_key_as_bytes = bytes(secret_key, CHARACTER_ENCODING)

    return base64.urlsafe_b64encode(kdf.derive(secret_key_as_bytes))


def save_file(file_in_bytes: bytes, file_name: str = 'output'):
    with open(file_name, 'wb') as file:
        file.write(file_in_bytes)


def main():
    config = prepare_arguments()
    file_in_bytes = encrypt_decrypt_file(
        read_file(config['FILE_NAME']),
        config['MODE'],
        config['KEY']
    )
    save_file(file_in_bytes, config['OUTPUT_FILE_NAME'])


if __name__ == '__main__':
    main()
