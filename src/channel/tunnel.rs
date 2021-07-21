/*
   主要实现加密信道两次交互数据处理
   包括以下：
   1 从mysql或者redis读取伪值唯一标识对应的私钥
     先从redis读，如果没有从mysql读，并回写到redis中
   2 生成TOKEN写入redis
       关联预值D
   3
*/

use std::vec;

use rand::Rng;

use crate::{
    error::{self, Error, ErrorKind},
    sm::{SM2, SM3},
    store::{
        cache::Session,
        db::{App, AppClientKey},
    },
    utils,
};

/*
   处理协商第一个请求
*/
pub fn tunnel_first(data: &Vec<u8>) -> error::Result<(Vec<u8>, Vec<u8>)> {
    let data_hash = SM3::hash(&data);
    let unique_id = data[0..32].to_vec();
    // todo 根据唯一标识查询私钥KEY
    let id = String::from_utf8(unique_id)?;
    let (app_id, private_key) = match AppClientKey::get_with_app_client(id.as_str())? {
        Some(app_client_key) => (app_client_key.app_id, app_client_key.prikey.unwrap()),
        None => {
            return Err(Error::new(
                ErrorKind::MYSQL_NO_DATA,
                "not found app_client_key record",
            ))
        }
    };
    let dec_data = SM2::decrypt(&data[32..].to_vec(), &private_key.clone().into_bytes())?;
    let token = create_token();
    let random_a = dec_data[0..32].to_vec();
    let mac = dec_data[32..].to_vec();
    let random_b: Vec<u8> = vec![0];
    // query ca cert chain
    let mut cert = match App::get(app_id)? {
        Some(app) => app.certs.unwrap(),
        None => return Err(Error::new(ErrorKind::MYSQL_NO_DATA, "not found app record")),
    };
    // x509 format der
    cert = utils::get_random_x509(cert.as_slice(), "123456")?;
    // 序列化存入缓存服务
    Session::init(&token, &random_a, &random_b, &mac, &cert).set()?;

    let mut no_sign_data = Vec::new();
    no_sign_data.extend(&random_b);
    no_sign_data.extend(&cert);
    let mut sign_data = SM2::sign(&no_sign_data, &private_key.into_bytes())?;
    sign_data.extend(&random_b);
    sign_data.extend(&cert);
    Ok((sign_data, token))
}

/*
   处理协商第二个请求
*/
pub fn tunnel_second() {}

// 生成Token
fn create_token() -> Vec<u8> {
    // length 40
    let mut data: Vec<u8> = vec![0; 40];
    data[0..32].copy_from_slice(SM3::hash(&utils::current_timestamp()).as_slice());
    let mut rng = rand::thread_rng();
    for i in 0..8 {
        data[32 + i] = rng.gen_range(0..254);
    }
    data
}

fn pre_master_key() {}

fn master_key() {}

fn create_random() -> Vec<u8> {
    todo!()
}