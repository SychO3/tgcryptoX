use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes256;

const BLOCK: usize = 16;

#[inline(always)]
fn xor_block(a: &[u8; BLOCK], b: &[u8; BLOCK]) -> [u8; BLOCK] {
    let x = u128::from_ne_bytes(*a) ^ u128::from_ne_bytes(*b);
    x.to_ne_bytes()
}

pub fn encrypt(data: &[u8], key: &[u8; 32], iv: &mut [u8; 16]) -> Vec<u8> {
    let cipher = Aes256::new(GenericArray::from_slice(key));
    let mut out = data.to_vec();

    for i in (0..data.len()).step_by(BLOCK) {
        let chunk: [u8; BLOCK] = out[i..i + BLOCK].try_into().unwrap();
        let xored = xor_block(&chunk, iv);

        let mut block = GenericArray::from(xored);
        cipher.encrypt_block(&mut block);
        out[i..i + BLOCK].copy_from_slice(&block);

        iv.copy_from_slice(&out[i..i + BLOCK]);
    }

    out
}

pub fn decrypt(data: &[u8], key: &[u8; 32], iv: &mut [u8; 16]) -> Vec<u8> {
    let cipher = Aes256::new(GenericArray::from_slice(key));
    let mut out = data.to_vec();
    let mut next_iv = [0u8; BLOCK];

    for i in (0..data.len()).step_by(BLOCK) {
        next_iv.copy_from_slice(&out[i..i + BLOCK]);

        let mut block = GenericArray::clone_from_slice(&out[i..i + BLOCK]);
        cipher.decrypt_block(&mut block);
        let dec: [u8; BLOCK] = block.into();
        let result = xor_block(&dec, iv);
        out[i..i + BLOCK].copy_from_slice(&result);

        iv.copy_from_slice(&next_iv);
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nist_cbc256_encrypt() {
        let key: [u8; 32] = hex_decode(
            "603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4",
        );
        let mut iv: [u8; 16] = hex_decode("000102030405060708090A0B0C0D0E0F");
        let plaintext = hex_decode::<64>(
            "6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E51\
             30C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710",
        );
        let expected = hex_decode::<64>(
            "F58C4C04D6E5F1BA779EABFB5F7BFBD69CFC4E967EDB808D679F777BC6702C7D\
             39F23369A9D9BACFA530E26304231461B2EB05E2C39BE9FCDA6C19078C6A9D1B",
        );
        let result = encrypt(&plaintext, &key, &mut iv);
        assert_eq!(result, expected.as_slice());
    }

    #[test]
    fn nist_cbc256_decrypt() {
        let key: [u8; 32] = hex_decode(
            "603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4",
        );
        let mut iv: [u8; 16] = hex_decode("000102030405060708090A0B0C0D0E0F");
        let ciphertext = hex_decode::<64>(
            "F58C4C04D6E5F1BA779EABFB5F7BFBD69CFC4E967EDB808D679F777BC6702C7D\
             39F23369A9D9BACFA530E26304231461B2EB05E2C39BE9FCDA6C19078C6A9D1B",
        );
        let expected = hex_decode::<64>(
            "6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E51\
             30C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710",
        );
        let result = decrypt(&ciphertext, &key, &mut iv);
        assert_eq!(result, expected.as_slice());
    }

    #[test]
    fn roundtrip() {
        let key: [u8; 32] = hex_decode(
            "603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4",
        );
        let mut iv_enc: [u8; 16] = hex_decode("000102030405060708090A0B0C0D0E0F");
        let mut iv_dec: [u8; 16] = iv_enc;
        let plaintext = hex_decode::<64>(
            "6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E51\
             30C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710",
        );
        let ciphertext = encrypt(&plaintext, &key, &mut iv_enc);
        let decrypted = decrypt(&ciphertext, &key, &mut iv_dec);
        assert_eq!(plaintext.as_slice(), &decrypted);
    }

    fn hex_decode<const N: usize>(s: &str) -> [u8; N] {
        let mut buf = [0u8; N];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            buf[i] = u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap();
        }
        buf
    }
}
