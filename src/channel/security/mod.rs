use std::{time::SystemTime, vec};

pub mod datapack;
mod models;

use chrono::{Timelike, Utc};
use openssl::hash::{Hasher, MessageDigest};
use rand::Rng;

use crate::sm::SM3;

pub struct SecureAlgo {}

impl SecureAlgo {
    pub fn client_random(len: usize) -> Vec<u8> {
        let mut data: Vec<u8> = vec![0;len];
        let mut rng = rand::thread_rng();
        for i in 0..len {
            let n = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
                Ok(n) => n.as_millis(),
                Err(_) => 100,
            };
            let i = rng.gen_range(0..n as usize);
            data[i] = ((n + i as u128)%256) as u8;
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
        
        let mut left_md5 = SecureAlgo::md5(&left);
        let mut right_md5 = SecureAlgo::md5(&right);
    
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
        
        todo!()    
    }

    fn prf_hash(s: &Vec<u8>, label_seed: &Vec<u8>, length: usize, mode: &str) -> Vec<u8> {
        todo!()
    }

}




#[cfg(test)]
mod test {
    use crate::channel::security::SecureAlgo;

    #[test]
    fn test_change_seed() {
        let a = vec![1,2,3,4,5,6];
        let b = vec![11,22,33,44,55,66];
        let c = SecureAlgo::change_seed(&a, &b);
        println!("len: {}", c.len());
    }

    #[test]
    fn test_key() {
        let r= SecureAlgo::key(&vec![1,2,4,5,6,7]);
        assert_eq!(48, r.len());
    }
}