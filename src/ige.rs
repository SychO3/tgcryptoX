use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes256;

const BLOCK: usize = 16;

#[inline(always)]
fn xor_block(a: &[u8; BLOCK], b: &[u8; BLOCK]) -> [u8; BLOCK] {
    let x = u128::from_ne_bytes(*a) ^ u128::from_ne_bytes(*b);
    x.to_ne_bytes()
}

pub fn encrypt(data: &[u8], key: &[u8; 32], iv: &[u8; 32]) -> Vec<u8> {
    let cipher = Aes256::new(GenericArray::from_slice(key));
    let mut out = vec![0u8; data.len()];
    let mut iv1: [u8; BLOCK] = iv[..BLOCK].try_into().unwrap();
    let mut iv2: [u8; BLOCK] = iv[BLOCK..].try_into().unwrap();

    for i in (0..data.len()).step_by(BLOCK) {
        let chunk: [u8; BLOCK] = data[i..i + BLOCK].try_into().unwrap();
        let xored = xor_block(&chunk, &iv1);

        let mut block = GenericArray::from(xored);
        cipher.encrypt_block(&mut block);

        let enc: [u8; BLOCK] = block.into();
        let result = xor_block(&enc, &iv2);
        out[i..i + BLOCK].copy_from_slice(&result);

        iv1 = result;
        iv2 = chunk;
    }

    out
}

pub fn decrypt(data: &[u8], key: &[u8; 32], iv: &[u8; 32]) -> Vec<u8> {
    let cipher = Aes256::new(GenericArray::from_slice(key));
    let mut out = vec![0u8; data.len()];
    let mut iv1: [u8; BLOCK] = iv[BLOCK..].try_into().unwrap();
    let mut iv2: [u8; BLOCK] = iv[..BLOCK].try_into().unwrap();

    for i in (0..data.len()).step_by(BLOCK) {
        let chunk: [u8; BLOCK] = data[i..i + BLOCK].try_into().unwrap();
        let xored = xor_block(&chunk, &iv1);

        let mut block = GenericArray::from(xored);
        cipher.decrypt_block(&mut block);

        let dec: [u8; BLOCK] = block.into();
        let result = xor_block(&dec, &iv2);
        out[i..i + BLOCK].copy_from_slice(&result);

        iv1 = result;
        iv2 = chunk;
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_encrypt_decrypt() {
        let key: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let iv: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let plaintext = b"0123456789abcdef0123456789ABCDEF";

        let ciphertext = encrypt(plaintext, &key, &iv);
        let decrypted = decrypt(&ciphertext, &key, &iv);
        assert_eq!(plaintext.as_slice(), &decrypted);
    }

    #[test]
    fn roundtrip_random() {
        for _ in 0..100 {
            let key: [u8; 32] = rand_bytes();
            let iv: [u8; 32] = rand_bytes();
            let len = (rand_u8() as usize % 64 + 1) * 16;
            let data: Vec<u8> = (0..len).map(|_| rand_u8()).collect();

            let enc = encrypt(&data, &key, &iv);
            let dec = decrypt(&enc, &key, &iv);
            assert_eq!(data, dec);
        }
    }

    fn rand_u8() -> u8 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        use std::time::SystemTime;
        let mut h = DefaultHasher::new();
        SystemTime::now().hash(&mut h);
        std::thread::current().id().hash(&mut h);
        h.finish() as u8
    }

    fn rand_bytes<const N: usize>() -> [u8; N] {
        let mut buf = [0u8; N];
        for b in buf.iter_mut() {
            *b = rand_u8();
            std::thread::yield_now();
        }
        buf
    }
}
