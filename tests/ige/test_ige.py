import os
import random
import unittest

import tgcrypto


class TestIGE256Input(unittest.TestCase):
    TYPE_ERROR_PATTERN = (
        r"'\w+' does not (support|have) the buffer interface"
        r"|a bytes-like object is required, not '\w+'"
    )

    def test_ige256_encrypt_invalid_args_count(self):
        with self.assertRaises(TypeError):
            tgcrypto.ige256_encrypt(os.urandom(16), os.urandom(32))

    def test_ige256_encrypt_empty_data(self):
        with self.assertRaisesRegex(ValueError, r"Data must not be empty"):
            tgcrypto.ige256_encrypt(b"", os.urandom(32), os.urandom(32))

    def test_ige256_encrypt_invalid_key_size(self):
        with self.assertRaisesRegex(ValueError, r"Key size must be exactly 32 bytes"):
            tgcrypto.ige256_encrypt(os.urandom(16), os.urandom(31), os.urandom(32))

    def test_ige256_encrypt_invalid_iv_size(self):
        with self.assertRaisesRegex(ValueError, r"IV size must be exactly 32 bytes"):
            tgcrypto.ige256_encrypt(os.urandom(16), os.urandom(32), os.urandom(31))

    def test_ige256_decrypt_empty_data(self):
        with self.assertRaisesRegex(ValueError, r"Data must not be empty"):
            tgcrypto.ige256_decrypt(b"", os.urandom(32), os.urandom(32))

    def test_ige256_decrypt_invalid_key_size(self):
        with self.assertRaisesRegex(ValueError, r"Key size must be exactly 32 bytes"):
            tgcrypto.ige256_decrypt(os.urandom(16), os.urandom(31), os.urandom(32))

    def test_ige256_decrypt_invalid_iv_size(self):
        with self.assertRaisesRegex(ValueError, r"IV size must be exactly 32 bytes"):
            tgcrypto.ige256_decrypt(os.urandom(16), os.urandom(32), os.urandom(31))


class TestIGE256Random(unittest.TestCase):
    DATA_CHUNK_MAX_SIZE = 64
    KEY_SIZE = 32
    IV_SIZE = 32
    TESTS_AMOUNT = 500

    TEMPLATE = """
    def test_ige256_random_{mode1}_{count}(self):
        data = {data}
        key = {key}
        iv = {iv}

        a = tgcrypto.ige256_{mode1}(data, key, iv)
        b = tgcrypto.ige256_{mode2}(a, key, iv)

        self.assertEqual(data, b)
    """.replace("\n    ", "\n")

    for count in range(TESTS_AMOUNT):
        exec(
            TEMPLATE.format(
                mode1="encrypt", mode2="decrypt", count=count,
                data=os.urandom(random.randint(1, DATA_CHUNK_MAX_SIZE) * 16),
                key=os.urandom(KEY_SIZE), iv=os.urandom(IV_SIZE),
            )
        )

    for count in range(TESTS_AMOUNT):
        exec(
            TEMPLATE.format(
                mode1="decrypt", mode2="encrypt", count=count,
                data=os.urandom(random.randint(1, DATA_CHUNK_MAX_SIZE) * 16),
                key=os.urandom(KEY_SIZE), iv=os.urandom(IV_SIZE),
            )
        )


if __name__ == "__main__":
    unittest.main()
