use std::time::Duration;

use redis::{Client, Commands, Connection};
use serde::{Deserialize, Serialize};

use super::mem;
use crate::error::Error;

#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    token: Vec<u8>,
    random_a: Vec<u8>,
    client_mac: Vec<u8>,
    random_b: Vec<u8>,
    pre_master_key: Vec<u8>,
    random_d: Vec<u8>,
    security_key: Vec<u8>,
    usercert: Vec<u8>,
}

impl Session {
    pub fn init(
        token: &Vec<u8>,
        random_a: &Vec<u8>,
        random_b: &Vec<u8>,
        mac: &Vec<u8>,
        usercert: &Vec<u8>,
    ) -> Session {
        Session {
            token: token.to_vec(),
            random_a: random_a.to_vec(),
            client_mac: mac.to_vec(),
            random_b: random_b.to_vec(),
            pre_master_key: vec![],
            random_d: vec![],
            security_key: vec![],
            usercert: usercert.to_vec(),
        }
    }

    pub fn get(token: Vec<u8>) -> Result<Session, Error> {
        let mut con = init_connect()?;

        let session: String = con.get(token)?;
        let str: Session = serde_json::from_str(&session)?;
        Ok(str)
    }

    pub fn set(&self) -> Result<(), Error> {
        let mut conn = init_connect()?;
        let session = serde_json::to_string(&self)?;
        conn.set(self.token.clone(), session)?;

        Ok(())
    }
}

fn init_connect() -> Result<Connection, Error> {
    let config = &*mem::CONFIG.lock()?;
    let redis_url = &config.redis.as_ref().unwrap().url;
    let client = Client::open(redis_url.as_str())?;
    let mut con = client.get_connection()?;
    con.set_read_timeout(Some(Duration::new(50, 0)))?;
    con.set_write_timeout(Some(Duration::new(50, 0)))?;
    Ok(con)
}

#[cfg(test)]
mod test {
    use super::Session;
    use redis::{Client, Commands};
    use std::{time::Duration, vec};

    #[test]
    fn test_conn() {
        let client = Client::open("redis://dev.liuweihua.cn:5607/").unwrap();
        let mut con = client.get_connection().unwrap();
        con.set_read_timeout(Some(Duration::new(50, 0))).unwrap();
        con.set_write_timeout(Some(Duration::new(50, 0))).unwrap();

        let _: () = con.set("key1", b"foo").unwrap();
        let x: String = redis::cmd("SET")
            .arg("key1")
            .arg("你好")
            .query(&mut con)
            .unwrap();
        println!("x={}", x);
        let _: () = con.set("test", "test_data").unwrap();
        let _: () = con.set("key1", "哈哈").unwrap();
        let _: () = con.set("key2", "haha").unwrap();
    }

    #[test]
    fn operator_session() {
        let session = Session {
            token: vec![1, 2, 13],
            random_a: vec![1, 21, 3],
            client_mac: vec![1, 2, 13],
            random_b: vec![1, 2, 35],
            pre_master_key: vec![1, 22, 3],
            random_d: vec![1, 2, 23, 33],
            security_key: vec![1, 2, 3, 4],
            usercert: vec![],
        };
        let session_str = serde_json::to_string(&session).unwrap();

        let client = Client::open("redis://dev.liuweihua.cn:5607/").unwrap();
        let mut con = client.get_connection().unwrap();

        let _: () = con.set("session", &session_str).unwrap();
        let result: String = con.get("session").unwrap();
        let session_res = serde_json::from_str(&result).unwrap();
        assert_eq!(session, session_res);
    }
}
