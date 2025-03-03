/*
   实现数据管理接口
   负责从redis读取数据，如果redis读取不到则从mysql读取数据，然后再将数据写入redis
   写数据时：
   1 仅redis，直接写入redis
   2 redis和mysql，先写入mysql再写入redis
   3 仅mysql，直接写入mysql
*/

use lazy_static;
use mysql::PooledConn;
use std::collections::HashMap;
use std::sync::Mutex;

use crate::config::Config;
use mysql::Pool;

/*
   存储一些临时变量
*/
pub struct MemEntry {
    pub str: String,
    pub vec: Vec<u8>,
    pub v: u32,
}

impl MemEntry {
    pub fn new() -> MemEntry {
        MemEntry {
            str: "".to_string(),
            vec: vec![],
            v: 0,
        }
    }
}

lazy_static::lazy_static! {
    pub static ref HASHMAP: Mutex<HashMap<String, MemEntry>> = Mutex::new({
        let mut m = HashMap::new();
        m
    });
    pub static ref CONFIG: Mutex<Config> = Mutex::new(Config::default());
    pub static ref MYSQL_POOL: Mutex<Option<Pool>> = Mutex::new(None);

}
