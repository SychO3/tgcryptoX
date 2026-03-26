import os
import random
import unittest

import tgcrypto


class TestCTR256NIST(unittest.TestCase):
    def test_ctr256_encrypt(self):
        key = bytes.fromhex(
            "603DEB1015CA71BE2B73AEF0857D7781"
            "1F352C073B6108D72D9810A30914DFF4"
        )
        iv = bytes.fromhex("F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF")
        plaintext = bytes.fromhex(
            "6BC1BEE22E409F96E93D7E117393172A"
            "AE2D8A571E03AC9C9EB76FAC45AF8E51"
            "30C81C46A35CE411E5FBC1191A0A52EF"
            "F69F2445DF4F9B17AD2B417BE66C3710"
        )
        ciphertext = bytes.fromhex(
            "601EC313775789A5B7A7F504BBF3D228"
            "F443E3CA4D62B59ACA84E990CACAF5C5"
            "2B0930DAA23DE94CE87017BA2D84988D"
            "DFC9C58DB67AADA613C2DD08457941A6"
        )
        self.assertEqual(tgcrypto.ctr256_encrypt(plaintext, key, iv, bytes(1)), ciphertext)

    def test_ctr256_decrypt(self):
        key = bytes.fromhex(
            "603DEB1015CA71BE2B73AEF0857D7781"
            "1F352C073B6108D72D9810A30914DFF4"
        )
        iv = bytes.fromhex("F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF")
        ciphertext = bytes.fromhex(
            "601EC313775789A5B7A7F504BBF3D228"
            "F443E3CA4D62B59ACA84E990CACAF5C5"
            "2B0930DAA23DE94CE87017BA2D84988D"
            "DFC9C58DB67AADA613C2DD08457941A6"
        )
        plaintext = bytes.fromhex(
            "6BC1BEE22E409F96E93D7E117393172A"
            "AE2D8A571E03AC9C9EB76FAC45AF8E51"
            "30C81C46A35CE411E5FBC1191A0A52EF"
            "F69F2445DF4F9B17AD2B417BE66C3710"
        )
        self.assertEqual(tgcrypto.ctr256_decrypt(ciphertext, key, iv, bytes(1)), plaintext)


class TestCTR256Cryptography(unittest.TestCase):
    def test_ctr256_encrypt_extra1(self):
        key = bytes.fromhex("776BEFF2851DB06F4C8A0542C8696F6C6A81AF1EEC96B4D37FC1D689E6C1C104")
        iv = bytes.fromhex("00000060DB5672C97AA8F0B200000001")
        plaintext = bytes.fromhex("53696E676C6520626C6F636B206D7367")
        ciphertext = bytes.fromhex("145AD01DBF824EC7560863DC71E3E0C0")
        self.assertEqual(tgcrypto.ctr256_encrypt(plaintext, key, iv, bytes(1)), ciphertext)

    def test_ctr256_encrypt_extra2(self):
        key = bytes.fromhex("F6D66D6BD52D59BB0796365879EFF886C66DD51A5B6A99744B50590C87A23884")
        iv = bytes.fromhex("00FAAC24C1585EF15A43D87500000001")
        plaintext = bytes.fromhex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
        ciphertext = bytes.fromhex("F05E231B3894612C49EE000B804EB2A9B8306B508F839D6A5530831D9344AF1C")
        self.assertEqual(tgcrypto.ctr256_encrypt(plaintext, key, iv, bytes(1)), ciphertext)

    def test_ctr256_encrypt_extra3(self):
        key = bytes.fromhex("FF7A617CE69148E4F1726E2F43581DE2AA62D9F805532EDFF1EED687FB54153D")
        iv = bytes.fromhex("001CC5B751A51D70A1C1114800000001")
        plaintext = bytes.fromhex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20212223")
        ciphertext = bytes.fromhex("EB6C52821D0BBBF7CE7594462ACA4FAAB407DF866569FD07F48CC0B583D6071F1EC0E6B8")
        self.assertEqual(tgcrypto.ctr256_encrypt(plaintext, key, iv, bytes(1)), ciphertext)


class TestCTR256Input(unittest.TestCase):
    def test_ctr256_encrypt_empty_data(self):
        with self.assertRaisesRegex(ValueError, r"Data must not be empty"):
            tgcrypto.ctr256_encrypt(b"", os.urandom(32), os.urandom(16), bytes(1))

    def test_ctr256_encrypt_invalid_key_size(self):
        with self.assertRaisesRegex(ValueError, r"Key size must be exactly 32 bytes"):
            tgcrypto.ctr256_encrypt(os.urandom(8), os.urandom(31), os.urandom(16), bytes(1))

    def test_ctr256_encrypt_invalid_iv_size(self):
        with self.assertRaisesRegex(ValueError, r"IV size must be exactly 16 bytes"):
            tgcrypto.ctr256_encrypt(os.urandom(8), os.urandom(32), os.urandom(15), bytes(1))

    def test_ctr256_encrypt_invalid_state_size(self):
        with self.assertRaisesRegex(ValueError, r"State size must be exactly 1 byte"):
            tgcrypto.ctr256_encrypt(os.urandom(8), os.urandom(32), os.urandom(16), bytes([1, 2, 3]))

    def test_ctr256_encrypt_invalid_state_value(self):
        with self.assertRaisesRegex(ValueError, r"State value must be in the range"):
            tgcrypto.ctr256_encrypt(os.urandom(8), os.urandom(32), os.urandom(16), bytes([16]))


class TestCTR256Random(unittest.TestCase):
    DATA_MAX_SIZE = 1024
    KEY_SIZE = 32
    IV_SIZE = 16
    TESTS_AMOUNT = 500

    TEMPLATE = """
    def test_ctr256_random_{mode1}_{count}(self):
        data = {data}
        key = {key}
        iv = {iv}
        iv_copy = iv.copy()
        state = {state}
        state_copy = state.copy()

        a = tgcrypto.ctr256_{mode1}(data, key, iv, state)
        b = tgcrypto.ctr256_{mode2}(a, key, iv_copy, state_copy)

        self.assertEqual(data, b)
    """.replace("\n    ", "\n")

    for count in range(TESTS_AMOUNT):
        exec(
            TEMPLATE.format(
                mode1="encrypt", mode2="decrypt", count=count,
                data=os.urandom(random.randint(1, DATA_MAX_SIZE)),
                key=os.urandom(KEY_SIZE),
                iv=bytearray(os.urandom(IV_SIZE)),
                state=bytearray([random.randint(0, 15)]),
            )
        )

    for count in range(TESTS_AMOUNT):
        exec(
            TEMPLATE.format(
                mode1="decrypt", mode2="encrypt", count=count,
                data=os.urandom(random.randint(1, DATA_MAX_SIZE)),
                key=os.urandom(KEY_SIZE),
                iv=bytearray(os.urandom(IV_SIZE)),
                state=bytearray([random.randint(0, 15)]),
            )
        )


if __name__ == "__main__":
    unittest.main()
