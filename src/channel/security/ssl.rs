use chrono::{Timelike, Utc};
use openssl::hash::{Hasher, MessageDigest};
use rand::Rng;
use std::{time::SystemTime, vec};

use crate::sm::SM3;

pub fn client_random(len: usize) -> Vec<u8> {
    let mut data: Vec<u8> = vec![0; len];
    let mut rng = rand::thread_rng();
    for i in 0..len {
        let n = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
            Ok(n) => n.as_millis(),
            Err(_) => 100,
        };
        let i = rng.gen_range(0..n as usize);
        data[i] = ((n + i as u128) % 256) as u8;
    }
    data
}

pub fn client_gmtunix_time() -> Vec<u8> {
    let mut data: Vec<u8> = vec![];
    let now = Utc::now();
    let hour = now.hour();
    let minute = now.minute();
    data[0] = ((hour & 0x0000ff00) >> 8) as u8;
    data[1] = (hour & 0x000000ff) as u8;
    data[2] = ((minute & 0x0000ff00) >> 8) as u8;
    data[3] = (minute & 0x000000ff) as u8;
    data
}

pub fn change_seed(a: &Vec<u8>, b: &Vec<u8>) -> Vec<u8> {
    let left = SM3::hash(a);
    let right = SM3::hash(b);

    let mut left_md5 = md5(&left);
    let mut right_md5 = md5(&right);

    let mut result: Vec<u8> = vec![];
    result.append(&mut left_md5);
    result.append(&mut right_md5);

    result
}

pub fn md5(data: &Vec<u8>) -> Vec<u8> {
    let mut hasher = Hasher::new(MessageDigest::md5()).unwrap();
    hasher.update(data);
    let res = hasher.finish().unwrap();
    res.to_vec()
}

pub fn key(data: &Vec<u8>) -> Vec<u8> {
    let a = SM3::hash(data);
    let mut a_mut = a[0..16].to_vec();
    a_mut.extend_from_slice(data.as_slice());
    let b = SM3::hash(&a_mut);
    let mut b_mut = b[0..16].to_vec();
    b_mut.extend_from_slice(data.as_slice());
    let c = SM3::hash(&b_mut);

    let mut res = a[0..16].to_vec();
    res.extend_from_slice(&b[0..16]);
    res.extend_from_slice(&c[0..16]);
    res
}

pub fn prf(secret: &Vec<u8>, label: &Vec<u8>, seed: &Vec<u8>, length: usize) -> Vec<u8> {
    let (s1, s2) = match secret.len() % 2 == 0 {
        true => {
            let split_len = secret.len() / 2;
            (
                secret[0..split_len].to_vec(),
                secret[split_len..secret.len()].to_vec(),
            )
        }
        false => {
            let split_len = secret.len() / 2 + 1;
            (
                secret[0..split_len].to_vec(),
                secret[split_len - 1..secret.len()].to_vec(),
            )
        }
    };

    let mut label_seed = vec![];
    label_seed.extend_from_slice(label.as_slice());
    label_seed.extend_from_slice(seed.as_slice());
    let prf_md5 = prf_hash(&s1, &label_seed, length, "HmacMD5");
    let prf_hash = prf_hash(&s2, &label_seed, length, "HmacSM3");
    xor(&prf_md5, &prf_hash)
}

fn prf_hash(s: &Vec<u8>, label_seed: &Vec<u8>, length: usize, mode: &str) -> Vec<u8> {
    let mut buffer: Vec<Vec<u8>> = vec![];
    buffer.push(label_seed.to_vec());
    let mut tmp: Vec<u8> = vec![];

    while tmp.len() < length {
        let buffer_last = buffer.get(buffer.len() - 1).unwrap();
        let current = encrypt_hmac(&buffer_last, &s, mode);
        buffer.push(current.clone());
        let mut neo_seed = vec![];
        neo_seed.extend(current);
        neo_seed.extend(label_seed);
        let byts = encrypt_hmac(&neo_seed, &s, mode);
        tmp.extend(byts);
    }

    tmp.truncate(length);
    tmp
}

fn encrypt_hmac(data: &Vec<u8>, key: &Vec<u8>, mode: &str) -> Vec<u8> {
    if mode.eq("HmacSM3") {
        SM3::hmac(data, key)
    } else if mode.eq("HmacMD5") {
        md5_hmac(data, key)
    } else {
        vec![]
    }
}

fn xor(data1: &Vec<u8>, data2: &Vec<u8>) -> Vec<u8> {
    if data1.len() != data2.len() {
        return vec![];
    }
    let mut result = vec![0; data1.len()];
    for i in 0..data1.len() {
        result[i] = data1[i] ^ data2[i];
    }
    result
}

fn md5_hmac(data: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    let block_length = 64;
    let mut structured_key = vec![0; block_length];
    if key.len() > block_length {
        let md5_key = md5::compute(key).to_vec();
        structured_key[0..md5_key.len()].copy_from_slice(md5_key.as_slice());
    } else {
        structured_key[0..key.len()].copy_from_slice(key.as_slice());
    }
    let mut ipad: Vec<u8> = vec![0; block_length];
    let mut opad: Vec<u8> = vec![0; block_length];
    for i in 0..block_length {
        ipad[i] = 0x36;
        opad[i] = 0x5c;
    }
    let mut ipad_key: Vec<u8> = vec![0; block_length];
    for i in 0..block_length {
        ipad_key[i] = structured_key[i] ^ ipad[i];
    }
    let mut opad_key: Vec<u8> = vec![0; block_length];
    for i in 0..block_length {
        opad_key[i] = structured_key[i] ^ opad[i];
    }
    let mut t3 = vec![];
    t3.extend(ipad_key);
    t3.extend(data);
    let t4 = md5::compute(&t3).to_vec();
    let mut t6 = vec![];
    t6.extend(opad_key);
    t6.extend(t4);
    md5::compute(&t6).to_vec()
}

#[cfg(test)]
mod test {
    use crate::channel::security::ssl::{change_seed, key, prf};

    #[test]
    fn test_change_seed() {
        let a = vec![1, 2, 3, 4, 5, 6];
        let b = vec![11, 22, 33, 44, 55, 66];
        let c = change_seed(&a, &b);
        println!("len: {}", c.len());
    }

    #[test]
    fn test_key() {
        let r = key(&vec![1, 2, 4, 5, 6, 7]);
        assert_eq!(48, r.len());
    }

    #[test]
    fn test_prf() {
        let secret = vec![1, 2, 3, 4, 5, 6, 7, 2, 34, 54, 65, 17, 15, 17, 78, 52];
        let label = "master_secret".as_bytes().to_vec();
        let seed = vec![1, 3, 5, 7, 9, 2, 3, 4, 6, 8, 0, 9];
        let length = 32;
        let actullay = vec![
            207, 121, 186, 77, 127, 135, 51, 154, 169, 134, 245, 161, 234, 88, 72, 104, 66, 248,
            62, 68, 170, 77, 250, 30, 123, 58, 184, 94, 130, 107, 21, 14,
        ];
        let result = prf(&secret, &label, &seed, length);
        assert_eq!(result, actullay);
    }
}
