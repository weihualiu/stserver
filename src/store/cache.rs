use std::{time::Duration, vec};

use redis::{Client, Commands, Connection};
use serde::{Deserialize, Serialize};

use super::mem;
use crate::{
    error::{Error, Result},
    sm::SM2,
};

#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub token: Vec<u8>,
    pub random_a: Vec<u8>,
    pub client_mac: Vec<u8>,
    pub random_b: Vec<u8>,
    pub pre_master_key: Vec<u8>,
    pub random_d: Vec<u8>,
    // 客户端预置公钥对应私钥
    pub security_key: Vec<u8>,
    // 给客户端随机分配的证书
    pub random_cert: Vec<u8>,
    // 多证书公用私钥
    pub prikey: Vec<u8>,
    // first request data with hash
    pub request_hash: Vec<u8>,
    // 协商出的对称密钥
    pub encrypt_key: Vec<u8>,
}

impl Session {
    pub fn init(
        token: &Vec<u8>,
        random_a: &Vec<u8>,
        random_b: &Vec<u8>,
        mac: &Vec<u8>,
        prikey: &Vec<u8>,
        request_hash: &Vec<u8>,
    ) -> Session {
        Session {
            token: token.to_vec(),
            random_a: random_a.to_vec(),
            client_mac: mac.to_vec(),
            random_b: random_b.to_vec(),
            pre_master_key: vec![],
            random_d: vec![],
            security_key: vec![],
            prikey: prikey.to_vec(),
            request_hash: request_hash.to_vec(),
            random_cert: vec![],
            encrypt_key: vec![],
        }
    }

    pub fn get(token: Vec<u8>) -> Result<Session> {
        let mut con = init_connect()?;

        let session: String = con.get(token)?;
        let str: Session = serde_json::from_str(&session)?;
        Ok(str)
    }

    pub fn set(&self) -> Result<()> {
        let mut conn = init_connect()?;
        let session = serde_json::to_string(&self)?;
        conn.set(self.token.clone(), session)?;

        Ok(())
    }
}

fn init_connect() -> Result<Connection> {
    let config = &*mem::CONFIG.lock()?;
    let redis_url = &config.redis.as_ref().unwrap().url;
    let client = Client::open(redis_url.as_str())?;
    let mut con = client.get_connection()?;
    con.set_read_timeout(Some(Duration::new(50, 0)))?;
    con.set_write_timeout(Some(Duration::new(50, 0)))?;
    Ok(con)
}
