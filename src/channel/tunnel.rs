/*
   主要实现加密信道两次交互数据处理
   包括以下：
   1 从mysql或者redis读取伪值唯一标识对应的私钥
     先从redis读，如果没有从mysql读，并回写到redis中
   2 生成TOKEN写入redis
       关联预值D
   3
*/

use crate::{
    error::{self, Error, ErrorKind},
    sm::{SM2, SM3},
    store::{
        cache::Session,
        db::{App, AppClientKey},
    },
    utils,
};

use super::security::{datapack::DataEntry, ssl};

/*
   处理协商第一个请求
*/
pub fn tunnel_first(data: &Vec<u8>) -> error::Result<(Vec<u8>, Vec<u8>)> {
    let data_hash = SM3::hash(&data);
    let unique_id = data[0..32].to_vec();
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
    let token = ssl::create_token();
    let random_a = dec_data[0..32].to_vec();
    let mac = dec_data[32..].to_vec();
    let random_b: Vec<u8> = ssl::client_random(32);
    // query ca cert chain
    let mut cert = match App::get(app_id)? {
        Some(app) => app.certs.unwrap(),
        None => return Err(Error::new(ErrorKind::MYSQL_NO_DATA, "not found app record")),
    };
    let random_private_key = utils::prikey_from_pkcs12(cert.as_slice(), "123456")?;
    // x509 format der
    cert = utils::get_random_x509(cert.as_slice(), "123456")?;
    // write cache service
    Session::init(
        &token,
        &random_a,
        &random_b,
        &mac,
        &random_private_key,
        &data_hash,
    )
    .set()?;

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
pub fn tunnel_second(entry: &mut DataEntry) -> error::Result<Vec<u8>> {
    let mut session = Session::get(entry.token.clone())?;
    let data = SM2::decrypt(&entry.content, &session.prikey)?;
    let hash = SM3::hash(&entry.content);
    session.random_d = data;
    let random_c = ssl::change_seed(&session.random_a, &session.client_mac);
    let pre_master_key = ssl::prf(
        &session.random_cert,
        &"master_secret".as_bytes().to_vec(),
        &utils::vec_append(&random_c, &session.random_b),
        32,
    );
    session.pre_master_key = pre_master_key.clone();
    let master_key = ssl::prf(
        &pre_master_key,
        &"master_secret1".as_bytes().to_vec(),
        &utils::vec_append(&session.random_d, &session.random_b),
        32,
    );
    let key1 = ssl::prf(
        &master_key,
        &"key_extension".as_bytes().to_vec(),
        &utils::vec_append(&session.random_d, &session.random_b),
        32,
    );
    let session_encrypt_key = ssl::key(&key1);
    session.encrypt_key = session_encrypt_key.clone();
    entry.symmetric_key = session_encrypt_key.clone();
    let response = utils::vec_append(&session.request_hash, &hash);

    Ok(response)
}
