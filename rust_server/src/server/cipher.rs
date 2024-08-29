use std::time::{SystemTime, UNIX_EPOCH};
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;
use std::error::Error;
use std::convert::TryInto;
use crate::server::error::KeySizeError;

const NUM_ROUNDS:   usize = 64;
const BLOCK_SIZE:   usize = 8;
const DELTA:        u32 = 0x9E3779B9;
const FNV_OFFSET:   u32 = 2166136261;
const FNV_PRIME:    u32 = 16777619;
const CHARACTERS:   &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";


struct Cipher {
    table: [u32; NUM_ROUNDS],
}

impl Cipher {
    fn block_size(&self) -> usize {
        BLOCK_SIZE
    }

    fn encrypt(&self, dst: &mut [u8], src: &[u8]) {
        encrypt_block(self, dst, src);
    }

    fn decrypt(&self, dst: &mut [u8], src: &[u8]) {
        decrypt_block(self, dst, src);
    }
}

pub fn crypt_create_key(length: usize) -> Vec<u8> {
    let seed = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let mut rng = StdRng::seed_from_u64(seed as u64);
    let mut key = vec![0u8; length];

    for i in 0..length {
        key[i] = CHARACTERS[rng.gen_range(0..CHARACTERS.len())];
    }

    key
}

fn get_hash_from_string(s: &str, is_unicode: bool) -> u32 {
    let mut hash = FNV_OFFSET;
    let length = if is_unicode { s.len() - 2 } else { s.len() };
    let offset = if is_unicode { 2 } else { 1 };

    for i in (0..length).step_by(offset) {
        hash ^= s.as_bytes()[i] as u32;
        hash = hash.wrapping_mul(FNV_PRIME);
    }

    hash
}

fn create_hash_macro(s: &str) -> String {
    let macro_name  = s.to_uppercase().trim_end().to_string();
    let lower       = s.to_lowercase();
    let (name, is_unicode) = if lower.ends_with(".dll") {
        (encode_utf16(&lower), true)
    } else {
        (lower.into_bytes(), false)
    };

    format!(
        "#define {} 0x{:x}",
        macro_name.split('.').next().unwrap(),
        get_hash_from_string(&String::from_utf8_lossy(&name), is_unicode)
    )
}

fn new_cipher(key: &[u8]) -> Result<Cipher, KeySizeError> {
    if key.len() != 16 {
        return Err(KeySizeError(key.len()));
    }
    let mut cipher = Cipher {
        table: [0u32; NUM_ROUNDS]
    };

    init_cipher(&mut cipher, key);
    Ok(cipher)
}

fn xtea_divide(data: &[u8]) -> Vec<&[u8]> {
    data.chunks(BLOCK_SIZE).collect()
}

pub fn crypt_xtea(config: &[u8], key: &[u8], encrypt: bool) -> Result<Vec<u8>, Box<dyn Error>> {
    let cipher      = new_cipher(key)?;
    let sections    = xtea_divide(config);
    let mut out     = Vec::with_capacity(config.len());

    for section in sections {
        let mut buf = [0u8; BLOCK_SIZE];

        if encrypt  {
            cipher.encrypt(&mut buf, section);
        } else {
            cipher.decrypt(&mut buf, section);
        }

        out.extend_from_slice(&buf);
    }

    Ok(out)
}

fn block_to_u32(src: &[u8]) -> (u32, u32) {
    let r0 = u32::from_be_bytes(src[0..4].try_into().unwrap());
    let r1 = u32::from_be_bytes(src[4..8].try_into().unwrap());
    (r0, r1)
}

fn u32_to_block(v0: u32, v1: u32, dst: &mut [u8]) {
    dst[0..4].copy_from_slice(&v0.to_be_bytes());
    dst[4..8].copy_from_slice(&v1.to_be_bytes());
}

fn encrypt_block(c: &Cipher, dst: &mut [u8], src: &[u8]) {
    let (mut v0, mut v1) = block_to_u32(src);

    for i in 0..NUM_ROUNDS {
        v0 = v0.wrapping_add(((v1 << 4) ^ (v1 >> 5)).wrapping_add(v1) ^ c.table[i]);
        v1 = v1.wrapping_add(((v0 << 4) ^ (v0 >> 5)).wrapping_add(v0) ^ c.table[i]);
    }

    u32_to_block(v0, v1, dst);
}

fn decrypt_block(c: &Cipher, dst: &mut [u8], src: &[u8]) {
    let (mut v0, mut v1) = block_to_u32(src);

    for i in (0..NUM_ROUNDS).rev() {
        v1 = v1.wrapping_sub(((v0 << 4) ^ (v0 >> 5)).wrapping_add(v0) ^ c.table[i]);
        v0 = v0.wrapping_sub(((v1 << 4) ^ (v1 >> 5)).wrapping_add(v1) ^ c.table[i]);
    }

    u32_to_block(v0, v1, dst);
}

fn init_cipher(c: &mut Cipher, key: &[u8]) {
    let mut k = [0u32; 4];
    let mut sum = 0u32;

    for (i, k_val) in k.iter_mut().enumerate() {
        let j = i * 4;
        *k_val = u32::from_be_bytes(key[j..j + 4].try_into().unwrap());
    }

    for i in 0..NUM_ROUNDS {
        c.table[i] = sum.wrapping_add(k[(sum & 3) as usize]);
        sum = sum.wrapping_add(DELTA);
        c.table[i] = sum.wrapping_add(k[((sum >> 11) & 3) as usize]);
    }
}

fn encode_utf16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|c| c.to_be_bytes()).collect()
}