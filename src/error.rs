use std::fmt::{Debug, Display, Formatter, Write};

pub struct STError {
    code: ErrorKind,
    msg: String,
}

#[derive(Debug)]
pub enum ErrorKind {
    DATAPACK,
    DATA_INVALID,
    DATATYPE,
    DATA_UNPACK_OLDDATA_NOMATCH,
    OS_ERROR,
}

impl Display for ErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

impl std::error::Error for ErrorKind {}

impl STError {
    pub fn new(kind: ErrorKind, message: &str) -> STError {
        STError {
            code: kind,
            msg: message.to_string(),
        }
    }
}

impl Display for STError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.msg)
    }
}

impl Debug for STError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}, {}", self.code, self.msg)
    }
}

impl std::error::Error for STError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.code {
            ErrorKind::OS_ERROR => None,
            _ => None,
        }
    }
}

pub type IResult<I> = std::result::Result<I, STError>;

impl From<std::io::Error> for STError {
    fn from(err: std::io::Error) -> Self {
        STError::new(ErrorKind::OS_ERROR, err.to_string().as_str())
    }
}
