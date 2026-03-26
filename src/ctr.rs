use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes256;

const BLOCK: usize = 16;

pub fn ctr256(data: &[u8], key: &[u8; 32], iv: &mut [u8; 16], state: &mut u8) -> Vec<u8> {
    let cipher = Aes256::new(GenericArray::from_slice(key));
    let mut out = data.to_vec();

    let mut chunk = GenericArray::clone_from_slice(iv);
    cipher.encrypt_block(&mut chunk);

    for byte in out.iter_mut() {
        *byte ^= chunk[*state as usize];
        *state += 1;

        if *state >= BLOCK as u8 {
            *state = 0;
        }

        if *state == 0 {
            for k in (0..BLOCK).rev() {
                iv[k] = iv[k].wrapping_add(1);
                if iv[k] != 0 {
                    break;
                }
            }
            chunk = GenericArray::clone_from_slice(iv.as_ref());
            cipher.encrypt_block(&mut chunk);
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nist_ctr256_encrypt() {
        let key: [u8; 32] = hex_decode(
            "603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4",
        );
        let mut iv: [u8; 16] = hex_decode("F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF");
        let plaintext = hex_decode::<64>(
            "6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E51\
             30C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710",
        );
        let expected = hex_decode::<64>(
            "601EC313775789A5B7A7F504BBF3D228F443E3CA4D62B59ACA84E990CACAF5C5\
             2B0930DAA23DE94CE87017BA2D84988DDFC9C58DB67AADA613C2DD08457941A6",
        );
        let mut state = 0u8;
        let result = ctr256(&plaintext, &key, &mut iv, &mut state);
        assert_eq!(result, expected.as_slice());
    }

    #[test]
    fn nist_ctr256_decrypt() {
        let key: [u8; 32] = hex_decode(
            "603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4",
        );
        let mut iv: [u8; 16] = hex_decode("F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF");
        let ciphertext = hex_decode::<64>(
            "601EC313775789A5B7A7F504BBF3D228F443E3CA4D62B59ACA84E990CACAF5C5\
             2B0930DAA23DE94CE87017BA2D84988DDFC9C58DB67AADA613C2DD08457941A6",
        );
        let expected = hex_decode::<64>(
            "6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E51\
             30C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710",
        );
        let mut state = 0u8;
        let result = ctr256(&ciphertext, &key, &mut iv, &mut state);
        assert_eq!(result, expected.as_slice());
    }

    #[test]
    fn ctr256_extra_vector_1() {
        let key: [u8; 32] =
            hex_decode("776BEFF2851DB06F4C8A0542C8696F6C6A81AF1EEC96B4D37FC1D689E6C1C104");
        let mut iv: [u8; 16] = hex_decode("00000060DB5672C97AA8F0B200000001");
        let plaintext = hex_decode::<16>("53696E676C6520626C6F636B206D7367");
        let expected = hex_decode::<16>("145AD01DBF824EC7560863DC71E3E0C0");
        let mut state = 0u8;
        let result = ctr256(&plaintext, &key, &mut iv, &mut state);
        assert_eq!(result, expected.as_slice());
    }

    fn hex_decode<const N: usize>(s: &str) -> [u8; N] {
        let mut buf = [0u8; N];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            buf[i] = u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap();
        }
        buf
    }
}
