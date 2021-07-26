use mysql::{params, prelude::Queryable, Opts, Pool, PooledConn};

use crate::error::{self};

use super::mem;

pub struct AppClientKey {
    pub app_id: usize,
    pub client_type: usize,
    pub serialid: Option<String>,
    pub pubkey: Option<String>,
    pub prikey: Option<String>,
}

fn db_global_init() -> error::Result<PooledConn> {
    let config = &*mem::CONFIG.lock().unwrap();
    let mysql_name = &config.mysql.as_ref().unwrap().user;
    let mysql_passwd = &config.mysql.as_ref().unwrap().passwd;
    let mysql_host = &config.mysql.as_ref().unwrap().host;
    let mysql_port = &config.mysql.as_ref().unwrap().port;
    let url = format!(
        "mysql://{}:{}@{}:{}/stserver",
        mysql_name, mysql_passwd, mysql_host, mysql_port
    );

    let mut pool = mem::MYSQL_POOL.lock()?;
    if pool.is_none() {
        println!("here is call 444");
        *pool = Some(Pool::new(Opts::from_url(url.as_str())?)?);
    }
    Ok(pool.as_ref().unwrap().get_conn()?)
}

impl AppClientKey {
    pub fn get_with_app_client(serialid: &str) -> error::Result<Option<AppClientKey>> {
        let mut conn = db_global_init()?;
        let res = conn
            .exec_first(
                "select * from stserver.app_client_key where serialid=:serialid",
                params! {
                    "serialid" => serialid,
                },
            )
            .map(|row| {
                row.map(
                    |(app_id, client_type, serialid, pubkey, prikey)| AppClientKey {
                        app_id: app_id,
                        client_type: client_type,
                        serialid: serialid,
                        pubkey: pubkey,
                        prikey: prikey,
                    },
                )
            });

        Ok(res?)
    }
}

pub struct App {
    pub id: usize,
    pub name: String,
    pub description: Option<String>,
    pub certs: Option<Vec<u8>>,
}

impl App {
    pub fn get(id: usize) -> error::Result<Option<App>> {
        let mut conn = db_global_init()?;
        let res = conn
            .exec_first(
                "select * from stserver.app where id=:id",
                params! {
                    "id" => id,
                },
            )
            .map(|row| {
                row.map(|(id, name, description, certs)| App {
                    id: id,
                    name: name,
                    description: description,
                    certs: certs,
                })
            });

        Ok(res?)
    }
}

