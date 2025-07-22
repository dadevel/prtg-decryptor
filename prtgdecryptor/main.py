from argparse import ArgumentParser, FileType
from xml.etree import ElementTree
import re


def main() -> None:
    entrypoint = ArgumentParser()
    parsers = entrypoint.add_subparsers(dest='command', required=True)
    parser = parsers.add_parser('file')
    parser.add_argument('path', type=FileType(mode='r'), default='-')
    parser = parsers.add_parser('blob')
    parser.add_argument('data')
    parser.add_argument('-g', '--guid', required=True)
    opts = entrypoint.parse_args()
    if opts.command == 'file':
        content = opts.path.read()
        root = ElementTree.fromstring(content)
        guid = root.get('guid')
        assert guid
        cipher = PaeCipherAES256(guid=guid)
    elif opts.command == 'blob':
        content = opts.data
        cipher = PaeCipherAES256(guid=opts.guid)
    else:
        raise RuntimeError('unreachable')
    print(re.sub(r'([A-Z0-9]+={1,10})', lambda m: replacer(cipher, m), content))


def replacer(cipher: 'PaeCipherAES256', match: re.Match) -> str:
    ciphertext = match.group(1)
    try:
        plaintext = cipher.decrypt(ciphertext, decode=True)
        # dont know why this happens, but it does
        if plaintext == ciphertext:
            return f'ENCRYPTED:{ciphertext}'
        return f'DECRYPTED:{plaintext or ''}'
    except Exception as e:
        return f'FAILED:{e.__class__.__name__}'


# code below copied from https://github.com/yobabyte/decryptocollection/blob/9eb8188a869745931c164d297b1fbfaf17cbd9db/prtg/prtg_string_decryptor.py

from Crypto.Cipher import AES

from base64 import b32decode
from hashlib import sha256


class PaeCipher:
    _TEXT_ENCODINGS = ('ascii', )

    @property
    def key(self):
        return self._derive_key()

    def decrypt(self, data, decode=True):
        decrypted = self._decrypt_impl(data)
        if decode:
            for encoding in self._TEXT_ENCODINGS:
                try:
                    return decrypted.decode(encoding)
                except:
                    pass
        else:
            return decrypted

    def _derive_key(self):
        raise NotImplementedError()

    def _decrypt_impl(self, data):
        raise NotImplementedError()


class PaeCipherAES256(PaeCipher):
    _KEY_PREFIX = '{FAE6C904-D2CC-453E-81E2-B6D3CFD69B92}'
    _TEXT_ENCODINGS = ('UTF-8', 'UTF-16LE')

    def __init__(self, guid, salt=''):
        self.guid = guid
        self.salt = salt or ''

    def _derive_key(self):
        return sha256((self._KEY_PREFIX + self.guid + self.salt).encode()).digest()

    def _decrypt_impl(self, data):
        data = b32decode(data)
        iv = data[:16]
        ct = data[16:]
        cipher = AES.new(self.key, AES.MODE_OFB, iv=iv)
        return cipher.decrypt(ct)


if __name__ == '__main__':
    main()
