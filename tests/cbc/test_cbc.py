import os
import random
import re
import unittest

import tgcrypto


class TestCBC256NIST(unittest.TestCase):
    def test_cbc256_encrypt(self):
        key = bytes.fromhex(
            "603DEB1015CA71BE2B73AEF0857D7781"
            "1F352C073B6108D72D9810A30914DFF4"
        )
        iv = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
        plaintext = bytes.fromhex(
            "6BC1BEE22E409F96E93D7E117393172A"
            "AE2D8A571E03AC9C9EB76FAC45AF8E51"
            "30C81C46A35CE411E5FBC1191A0A52EF"
            "F69F2445DF4F9B17AD2B417BE66C3710"
        )
        ciphertext = bytes.fromhex(
            "F58C4C04D6E5F1BA779EABFB5F7BFBD6"
            "9CFC4E967EDB808D679F777BC6702C7D"
            "39F23369A9D9BACFA530E26304231461"
            "B2EB05E2C39BE9FCDA6C19078C6A9D1B"
        )
        self.assertEqual(tgcrypto.cbc256_encrypt(plaintext, key, iv), ciphertext)

    def test_cbc256_decrypt(self):
        key = bytes.fromhex(
            "603DEB1015CA71BE2B73AEF0857D7781"
            "1F352C073B6108D72D9810A30914DFF4"
        )
        iv = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
        ciphertext = bytes.fromhex(
            "F58C4C04D6E5F1BA779EABFB5F7BFBD6"
            "9CFC4E967EDB808D679F777BC6702C7D"
            "39F23369A9D9BACFA530E26304231461"
            "B2EB05E2C39BE9FCDA6C19078C6A9D1B"
        )
        plaintext = bytes.fromhex(
            "6BC1BEE22E409F96E93D7E117393172A"
            "AE2D8A571E03AC9C9EB76FAC45AF8E51"
            "30C81C46A35CE411E5FBC1191A0A52EF"
            "F69F2445DF4F9B17AD2B417BE66C3710"
        )
        self.assertEqual(tgcrypto.cbc256_decrypt(ciphertext, key, iv), plaintext)


class TestCBC256Cryptography(unittest.TestCase):
    TEMPLATE = """
    def test_cbc256_{mode}_{name}_{count}(self):
        key = bytes.fromhex("{key}")
        iv = bytes.fromhex("{iv}")
        plaintext = bytes.fromhex("{plaintext}")
        ciphertext = bytes.fromhex("{ciphertext}")

        self.assertEqual(tgcrypto.cbc256_{mode}({input}, key, iv), {output})
    """.replace("\n    ", "\n")

    PATTERN = r"COUNT = (\d+)\nKEY = (\w+)\nIV = (\w+)\n(PLAINTEXT|CIPHERTEXT) = (\w+)\n(PLAINTEXT|CIPHERTEXT) = (\w+)"
    BASE_PATH = os.path.dirname(__file__) + "/vectors"

    for path in os.listdir(BASE_PATH):
        path = BASE_PATH + "/" + path
        with open(path, "r", encoding="utf-8") as f:
            for match in re.finditer(PATTERN, f.read()):
                count, key, iv, plain_or_cipher, bytes1, _, bytes2 = match.groups()
                if plain_or_cipher == "PLAINTEXT":
                    mode, plaintext, ciphertext = "encrypt", bytes1, bytes2
                    input, output = "plaintext", "ciphertext"
                else:
                    mode, plaintext, ciphertext = "decrypt", bytes2, bytes1
                    input, output = "ciphertext", "plaintext"
                exec(
                    TEMPLATE.format(
                        mode=mode, name=os.path.split(path)[-1].split(".")[0],
                        count=count, key=key, iv=iv,
                        plaintext=plaintext, ciphertext=ciphertext,
                        input=input, output=output,
                    )
                )


class TestCBC256Input(unittest.TestCase):
    def test_cbc256_encrypt_empty_data(self):
        with self.assertRaisesRegex(ValueError, r"Data must not be empty"):
            tgcrypto.cbc256_encrypt(b"", os.urandom(32), os.urandom(16))

    def test_cbc256_encrypt_invalid_key_size(self):
        with self.assertRaisesRegex(ValueError, r"Key size must be exactly 32 bytes"):
            tgcrypto.cbc256_encrypt(os.urandom(16), os.urandom(31), os.urandom(16))

    def test_cbc256_encrypt_invalid_iv_size(self):
        with self.assertRaisesRegex(ValueError, r"IV size must be exactly 16 bytes"):
            tgcrypto.cbc256_encrypt(os.urandom(16), os.urandom(32), os.urandom(15))

    def test_cbc256_decrypt_empty_data(self):
        with self.assertRaisesRegex(ValueError, r"Data must not be empty"):
            tgcrypto.cbc256_decrypt(b"", os.urandom(32), os.urandom(16))

    def test_cbc256_decrypt_invalid_key_size(self):
        with self.assertRaisesRegex(ValueError, r"Key size must be exactly 32 bytes"):
            tgcrypto.cbc256_decrypt(os.urandom(16), os.urandom(31), os.urandom(16))

    def test_cbc256_decrypt_invalid_iv_size(self):
        with self.assertRaisesRegex(ValueError, r"IV size must be exactly 16 bytes"):
            tgcrypto.cbc256_decrypt(os.urandom(16), os.urandom(32), os.urandom(15))


class TestCBC256Random(unittest.TestCase):
    DATA_CHUNK_MAX_SIZE = 64
    KEY_SIZE = 32
    IV_SIZE = 16
    TESTS_AMOUNT = 500

    TEMPLATE = """
    def test_cbc256_random_{mode1}_{count}(self):
        data = {data}
        key = {key}
        iv = {iv}
        iv_copy = iv.copy()

        a = tgcrypto.cbc256_{mode1}(data, key, iv)
        b = tgcrypto.cbc256_{mode2}(a, key, iv_copy)

        self.assertEqual(data, b)
    """.replace("\n    ", "\n")

    for count in range(TESTS_AMOUNT):
        exec(
            TEMPLATE.format(
                mode1="encrypt", mode2="decrypt", count=count,
                data=os.urandom(random.randint(1, DATA_CHUNK_MAX_SIZE) * 16),
                key=os.urandom(KEY_SIZE), iv=bytearray(os.urandom(IV_SIZE)),
            )
        )

    for count in range(TESTS_AMOUNT):
        exec(
            TEMPLATE.format(
                mode1="decrypt", mode2="encrypt", count=count,
                data=os.urandom(random.randint(1, DATA_CHUNK_MAX_SIZE) * 16),
                key=os.urandom(KEY_SIZE), iv=bytearray(os.urandom(IV_SIZE)),
            )
        )


if __name__ == "__main__":
    unittest.main()
