use std::fmt::{Display, Error, Formatter};
use std::path::PathBuf;
use std::str::FromStr;
use structopt::clap::AppSettings;
use structopt::StructOpt;

mod config;

pub use config::*;

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct HexEncoded(pub Vec<u8>);

impl Display for HexEncoded {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        f.write_str(&hex::encode(&self.0))
    }
}

impl AsRef<[u8]> for HexEncoded {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl FromStr for HexEncoded {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(HexEncoded(hex::decode(s)?))
    }
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct CommaSeparated<T: FromStr + Display>(pub Vec<T>);

impl<T: Display + FromStr> Display for CommaSeparated<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        for i in &self.0 {
            f.write_str(&i.to_string())?;
            f.write_str(",")?;
        }
        Ok(())
    }
}

impl<T: Display + FromStr> FromStr for CommaSeparated<T> {
    type Err = <T as FromStr>::Err;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(CommaSeparated(
            s.split(',')
                .map(|part| <T as FromStr>::from_str(part))
                .collect::<Result<Vec<_>, _>>()?,
        ))
    }
}

#[derive(Debug, StructOpt)]
pub struct Credentials {
    /// FIDO credential ids, separated by ',' generate using fido2luks credential
    #[structopt(name = "credential-id", env = "FIDO2LUKS_CREDENTIAL_ID")]
    pub ids: CommaSeparated<HexEncoded>,
}

#[derive(Debug, StructOpt)]
pub struct AuthenticatorParameters {
    /// Request a PIN to unlock the authenticator
    #[structopt(short = "P", long = "pin")]
    pub pin: bool,

    /// Location to read PIN from
    #[structopt(long = "pin-source", env = "FIDO2LUKS_PIN_SOURCE")]
    pub pin_source: Option<PathBuf>,

    /// Await for an authenticator to be connected, timeout after n seconds
    #[structopt(
        long = "await-dev",
        name = "await-dev",
        env = "FIDO2LUKS_DEVICE_AWAIT",
        default_value = "15"
    )]
    pub await_time: u64,
}

#[derive(Debug, StructOpt)]
pub struct LuksParameters {
    #[structopt(env = "FIDO2LUKS_DEVICE")]
    pub device: PathBuf,

    /// Try to unlock the device using a specifc keyslot, ignore all other slots
    #[structopt(long = "slot", env = "FIDO2LUKS_DEVICE_SLOT")]
    pub slot: Option<u32>,
}

#[derive(Debug, StructOpt, Clone)]
pub struct LuksModParameters {
    /// Number of milliseconds required to derive the volume decryption key
    /// Defaults to 10ms when using an authenticator or the default by cryptsetup when using a password
    #[structopt(long = "kdf-time", name = "kdf-time")]
    pub kdf_time: Option<u64>,
}

#[derive(Debug, StructOpt)]
pub struct SecretParameters {
    /// Salt for secret generation, defaults to 'ask'
    ///
    /// Options:{n}
    ///  - ask              : Prompt user using password helper{n}
    ///  - file:<PATH>      : Will read <FILE>{n}
    ///  - string:<STRING>  : Will use <STRING>, which will be handled like a password provided to the 'ask' option{n}
    #[structopt(
        name = "salt",
        long = "salt",
        env = "FIDO2LUKS_SALT",
        default_value = "ask"
    )]
    pub salt: SecretInput,
    /// Script used to obtain passwords, overridden by --interactive flag
    #[structopt(
        name = "password-helper",
        env = "FIDO2LUKS_PASSWORD_HELPER",
        default_value = "/usr/bin/env systemd-ask-password 'Please enter second factor for LUKS disk encryption!'"
    )]
    pub password_helper: PasswordHelper,
}
#[derive(Debug, StructOpt)]
pub struct Args {
    /// Request passwords via Stdin instead of using the password helper
    #[structopt(short = "i", long = "interactive")]
    pub interactive: bool,
    #[structopt(subcommand)]
    pub command: Command,
}

#[derive(Debug, StructOpt, Clone)]
pub struct OtherSecret {
    /// Use a keyfile instead of a password
    #[structopt(short = "d", long = "keyfile", conflicts_with = "fido_device")]
    pub keyfile: Option<PathBuf>,
    /// Use another fido device instead of a password
    /// Note: this requires for the credential fot the other device to be passed as argument as well
    #[structopt(short = "f", long = "fido-device", conflicts_with = "keyfile")]
    pub fido_device: bool,
}

#[derive(Debug, StructOpt)]
pub enum Command {
    #[structopt(name = "print-secret")]
    PrintSecret {
        /// Prints the secret as binary instead of hex encoded
        #[structopt(short = "b", long = "bin")]
        binary: bool,
        #[structopt(flatten)]
        credentials: Credentials,
        #[structopt(flatten)]
        authenticator: AuthenticatorParameters,
        #[structopt(flatten)]
        secret: SecretParameters,
    },
    /// Adds a generated key to the specified LUKS device
    #[structopt(name = "add-key")]
    AddKey {
        #[structopt(flatten)]
        luks: LuksParameters,
        #[structopt(flatten)]
        credentials: Credentials,
        #[structopt(flatten)]
        authenticator: AuthenticatorParameters,
        #[structopt(flatten)]
        secret: SecretParameters,
        /// Will wipe all other keys
        #[structopt(short = "e", long = "exclusive")]
        exclusive: bool,
        /// Will add an token to your LUKS 2 header, including the credential id
        #[structopt(short = "t", long = "token")]
        token: bool,
        #[structopt(flatten)]
        existing_secret: OtherSecret,
        #[structopt(flatten)]
        luks_mod: LuksModParameters,
    },
    /// Replace a previously added key with a password
    #[structopt(name = "replace-key")]
    ReplaceKey {
        #[structopt(flatten)]
        luks: LuksParameters,
        #[structopt(flatten)]
        credentials: Credentials,
        #[structopt(flatten)]
        authenticator: AuthenticatorParameters,
        #[structopt(flatten)]
        secret: SecretParameters,
        /// Add the password and keep the key
        #[structopt(short = "a", long = "add-password")]
        add_password: bool,
        /// Will add an token to your LUKS 2 header, including the credential id
        #[structopt(short = "t", long = "token")]
        token: bool,
        #[structopt(flatten)]
        replacement: OtherSecret,
        #[structopt(flatten)]
        luks_mod: LuksModParameters,
    },
    /// Open the LUKS device
    #[structopt(name = "open")]
    Open {
        #[structopt(flatten)]
        luks: LuksParameters,
        #[structopt(env = "FIDO2LUKS_MAPPER_NAME")]
        name: String,
        #[structopt(flatten)]
        credentials: Credentials,
        #[structopt(flatten)]
        authenticator: AuthenticatorParameters,
        #[structopt(flatten)]
        secret: SecretParameters,
        #[structopt(short = "r", long = "max-retries", default_value = "0")]
        retries: i32,
    },
    /// Open the LUKS device using credentials embedded in the LUKS 2 header
    #[structopt(name = "open-token")]
    OpenToken {
        #[structopt(flatten)]
        luks: LuksParameters,
        #[structopt(env = "FIDO2LUKS_MAPPER_NAME")]
        name: String,
        #[structopt(flatten)]
        authenticator: AuthenticatorParameters,
        #[structopt(flatten)]
        secret: SecretParameters,
        #[structopt(short = "r", long = "max-retries", default_value = "0")]
        retries: i32,
    },
    /// Generate a new FIDO credential
    #[structopt(name = "credential")]
    Credential {
        #[structopt(flatten)]
        authenticator: AuthenticatorParameters,
        /// Name to be displayed on the authenticator if it has a display
        #[structopt(env = "FIDO2LUKS_CREDENTIAL_NAME")]
        name: Option<String>,
    },
    /// Check if an authenticator is connected
    #[structopt(name = "connected")]
    Connected,
    Token(TokenCommand),
    /// Generate bash completion scripts
    #[structopt(name = "completions", setting = AppSettings::Hidden)]
    GenerateCompletions {
        /// Shell to generate completions for: bash, fish
        #[structopt(possible_values = &["bash", "fish"])]
        shell: String,
        out_dir: PathBuf,
    },
}

///LUKS2 token related operations
#[derive(Debug, StructOpt)]
pub enum TokenCommand {
    /// List all tokens associated with the specified device
    List {
        #[structopt(env = "FIDO2LUKS_DEVICE")]
        device: PathBuf,
        /// Dump all credentials as CSV
        #[structopt(long = "csv")]
        csv: bool,
    },
    /// Add credential to a keyslot
    Add {
        #[structopt(env = "FIDO2LUKS_DEVICE")]
        device: PathBuf,
        #[structopt(flatten)]
        credentials: Credentials,
        /// Slot to which the credentials will be added
        #[structopt(long = "slot", env = "FIDO2LUKS_DEVICE_SLOT")]
        slot: u32,
    },
    /// Remove credentials from token(s)
    Remove {
        #[structopt(env = "FIDO2LUKS_DEVICE")]
        device: PathBuf,
        #[structopt(flatten)]
        credentials: Credentials,
        /// Token from which the credentials will be removed
        #[structopt(long = "token")]
        token_id: Option<u32>,
    },
    /// Remove all unassigned tokens
    GC {
        #[structopt(env = "FIDO2LUKS_DEVICE")]
        device: PathBuf,
    },
}
