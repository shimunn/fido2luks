use ctap::FidoError;
use libcryptsetup_rs::LibcryptErr;
use std::io;
use std::io::ErrorKind;
use std::string::FromUtf8Error;
use Fido2LuksError::*;

pub type Fido2LuksResult<T> = Result<T, Fido2LuksError>;

#[derive(Debug, Fail)]
pub enum Fido2LuksError {
    #[fail(display = "unable to retrieve password: {}", cause)]
    AskPassError { cause: AskPassError },
    #[fail(display = "unable to read keyfile: {}", cause)]
    KeyfileError { cause: io::Error },
    #[fail(display = "authenticator error: {}", cause)]
    AuthenticatorError { cause: ctap::FidoError },
    #[fail(display = "no authenticator found, please ensure your device is plugged in")]
    NoAuthenticatorError,
    #[fail(display = " {}", cause)]
    CryptsetupError {
        cause: libcryptsetup_rs::LibcryptErr,
    },
    #[fail(display = "{}", cause)]
    LuksError { cause: LuksError },
    #[fail(display = "{}", cause)]
    IoError { cause: io::Error },
    #[fail(display = "supplied secret isn't valid for this device")]
    WrongSecret,
    #[fail(display = "not an utf8 string")]
    StringEncodingError { cause: FromUtf8Error },
}

impl Fido2LuksError {
    pub fn exit_code(&self) -> i32 {
        use Fido2LuksError::*;
        match self {
            AskPassError { .. } | KeyfileError { .. } => 2,
            AuthenticatorError { .. } => 3,
            NoAuthenticatorError => 4,
            WrongSecret => 5,
            _ => 1,
        }
    }
}

#[derive(Debug, Fail)]
pub enum AskPassError {
    #[fail(display = "unable to retrieve password: {}", _0)]
    IO(io::Error),
    #[fail(display = "provided passwords don't match")]
    Mismatch,
}

#[derive(Debug, Fail)]
pub enum LuksError {
    #[fail(display = "This feature requires to the LUKS device to be formatted as LUKS 2")]
    Luks2Required,
    #[fail(display = "Invalid token: {}", _0)]
    InvalidToken(String),
    #[fail(display = "No token found")]
    NoToken,
    #[fail(display = "The device already exists")]
    DeviceExists,
}

impl LuksError {
    pub fn activate(e: LibcryptErr) -> Fido2LuksError {
        match e {
            LibcryptErr::IOError(ref io) => match io.raw_os_error() {
                Some(1) if io.kind() == ErrorKind::PermissionDenied => Fido2LuksError::WrongSecret,
                Some(17) => Fido2LuksError::LuksError {
                    cause: LuksError::DeviceExists,
                },
                _ => return Fido2LuksError::CryptsetupError { cause: e },
            },
            _ => Fido2LuksError::CryptsetupError { cause: e },
        }
    }
}

impl From<LuksError> for Fido2LuksError {
    fn from(e: LuksError) -> Self {
        Fido2LuksError::LuksError { cause: e }
    }
}

impl From<FidoError> for Fido2LuksError {
    fn from(e: FidoError) -> Self {
        AuthenticatorError { cause: e }
    }
}

impl From<LibcryptErr> for Fido2LuksError {
    fn from(e: LibcryptErr) -> Self {
        match e {
            LibcryptErr::IOError(e) if e.raw_os_error().iter().any(|code| code == &1i32) => {
                WrongSecret
            }
            _ => CryptsetupError { cause: e },
        }
    }
}
impl From<io::Error> for Fido2LuksError {
    fn from(e: io::Error) -> Self {
        IoError { cause: e }
    }
}

impl From<FromUtf8Error> for Fido2LuksError {
    fn from(e: FromUtf8Error) -> Self {
        StringEncodingError { cause: e }
    }
}
