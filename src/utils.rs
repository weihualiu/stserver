use crate::error::{self, Error, ErrorKind};
use chrono::{Datelike, Local, Timelike};
use openssl::pkcs12::Pkcs12;
use openssl::rsa::{Padding, Rsa};
use openssl::symm::{Cipher, Crypter, Mode};
use rand::Rng;

trait BytesConvert {
    fn to_u32(&self) -> u32;
}

impl BytesConvert for [u8] {
    fn to_u32(&self) -> u32 {
        u32::from(self[0]) << 24
            | u32::from(self[1]) << 16
            | u32::from(self[2]) << 8
            | u32::from(self[3])
    }
}

pub fn u8_array_to_u32(vec: &[u8]) -> u32 {
    vec.to_u32()
}

trait U32Convert {
    fn to_vector(&self) -> Vec<u8>;
}

impl U32Convert for u32 {
    fn to_vector(&self) -> Vec<u8> {
        let mut t: Vec<u8> = vec![0; 4];
        t[0] = (self >> 24) as u8;
        t[1] = ((self & 0xff0000) >> 16) as u8;
        t[2] = ((self & 0xff00) >> 8) as u8;
        t[3] = (self & 0xff) as u8;
        t
    }
}

pub fn u32_to_vector(v: u32) -> Vec<u8> {
    v.to_vector()
}

pub fn current_timestamp() -> Vec<u8> {
    let mut v: Vec<u8> = vec![0; 7];
    let now = Local::now();
    v[0] = (now.year() / 100) as u8;
    v[1] = (now.year() % 100) as u8;
    v[2] = now.month() as u8;
    v[3] = now.day() as u8;
    v[4] = now.hour() as u8;
    v[5] = now.minute() as u8;
    v[6] = now.second() as u8;
    v
}

pub fn timestamp_to_string(v: Vec<u8>) -> String {
    todo!()
}

pub fn aes_256_cbc(data: &Vec<u8>, key: &Vec<u8>, mode: Mode) -> Result<Vec<u8>, Error> {
    let mut encrypter =
        Crypter::new(Cipher::aes_256_cbc(), mode, &key[0..32], Some(&key[32..])).unwrap();
    let block_size = Cipher::aes_256_cbc().block_size();
    let mut ciphertext = vec![0; data.len() + block_size];
    let mut count = encrypter.update(data.as_slice(), &mut ciphertext).unwrap();
    count += encrypter.finalize(&mut ciphertext[count..]).unwrap();
    ciphertext.truncate(count);
    Ok(ciphertext)
}

pub fn rsa_publickey_encrypt(data: &Vec<u8>, publickey: &Vec<u8>) -> Result<Vec<u8>, Error> {
    let rsa = Rsa::public_key_from_pem(publickey).unwrap();
    let mut encrypted_data: Vec<u8> = vec![0; data.len()];
    let len = rsa
        .public_encrypt(data, encrypted_data.as_mut_slice(), Padding::PKCS1)
        .unwrap();
    encrypted_data.truncate(len);
    Ok(encrypted_data)
}

pub fn rsa_privatekey_decrypt(data: &Vec<u8>, privatekey: &Vec<u8>) -> Result<Vec<u8>, Error> {
    let rsa = Rsa::private_key_from_pem(privatekey).unwrap();
    let mut encrypted_data: Vec<u8> = vec![0; data.len()];
    let len = rsa
        .private_decrypt(data, encrypted_data.as_mut_slice(), Padding::PKCS1)
        .unwrap();
    encrypted_data.truncate(len);
    Ok(encrypted_data)
}

pub fn get_random_x509(buff: &[u8], pass: &str) -> error::Result<Vec<u8>> {
    let pkcs12 = Pkcs12::from_der(buff)?;
    let parsepkcs12 = pkcs12.parse(pass)?;
    match parsepkcs12.chain {
        Some(x509_stack) => {
            let mut rng = rand::thread_rng();
            let i = rng.gen_range(0..x509_stack.len() as usize);
            Ok(x509_stack.get(i).unwrap().to_der()?)
        }
        None => Err(Error::new(ErrorKind::ERROR_STACK, "not found cert chain")),
    }
}

pub fn prikey_from_pkcs12(buff: &[u8], pass: &str) -> error::Result<Vec<u8>> {
    let pkcs12 = Pkcs12::from_der(buff)?;
    let parsepkcs12 = pkcs12.parse(pass)?;
    Ok(parsepkcs12.pkey.private_key_to_der()?)
}

pub fn vec_append(data1: &Vec<u8>, data2: &Vec<u8>) -> Vec<u8> {
    let mut t = data1.clone();
    t.extend(data2);
    t
}

#[cfg(test)]
mod test {
    use std::{fs::File, io::Read};

    use openssl::x509::X509;

    use super::*;

    #[test]
    fn bytes_convert() {
        let v: Vec<u8> = vec![1, 2, 3, 4];
        assert_eq!(v[0..4].to_u32(), 0b00000001000000100000001100000100);
        let t: u32 = 0b00000001000000100000001100000100;
        assert_eq!(t.to_vector(), v);
    }

    #[test]
    fn current_timestamp1() {
        let v = current_timestamp();
        println!("{:#?}", v);
    }

    #[test]
    fn pkcs12() {
        let mut file = File::open("test/test.p12").unwrap();
        let mut buff = vec![];
        file.read_to_end(&mut buff).unwrap();

        let x509_data = get_random_x509(&buff, "123456").unwrap();
        let x509 = X509::from_der(x509_data.as_slice()).unwrap();
        println!(
            "public key: {:#?}",
            x509.public_key().unwrap().public_key_to_pem().unwrap()
        );
    }
}
