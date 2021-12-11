use std::fmt::{Display, Error, Formatter};
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::str::FromStr;
use structopt::clap::{AppSettings, Shell};
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

impl Hash for HexEncoded {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state)
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
    #[structopt(
        name = "credential-ids",
        env = "FIDO2LUKS_CREDENTIAL_ID",
        short = "c",
        long = "creds"
    )]
    pub ids: Option<CommaSeparated<HexEncoded>>,
}

#[derive(Debug, StructOpt)]
pub struct AuthenticatorParameters {
    /// Request a PIN to unlock the authenticator if required
    #[structopt(short = "P", long = "pin")]
    pub pin: bool,

    /// Request PIN and password combined `pin:password` when using an password helper
    #[structopt(long = "pin-prefixed")]
    pub pin_prefixed: bool,

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

    /// Disable implicit use of LUKS2 tokens
    #[structopt(
        long = "disable-token",
    //  env = "FIDO2LUKS_DISABLE_TOKEN" // unfortunately clap will convert flags into args if they have an env attribute
    )]
    pub disable_token: bool,
}

#[derive(Debug, StructOpt, Clone)]
pub struct LuksModParameters {
    /// Number of milliseconds required to derive the volume decryption key
    /// Defaults to 10ms when using an authenticator or the default by cryptsetup when using a password
    #[structopt(long = "kdf-time", name = "kdf-time", env = "FIDO2LUKS_KDF_TIME")]
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
        long = "password-helper"
    )]
    pub password_helper: Option<PasswordHelper>,
}
#[derive(Debug, StructOpt)]
pub struct Args {
    /// Request passwords via Stdin instead of using the password helper
    #[structopt(short = "i", long = "interactive")]
    pub interactive: bool,
    #[structopt(short = "v", long = "verbose")]
    pub verbose: bool,
    #[structopt(subcommand)]
    pub command: Command,
}

#[derive(Debug, StructOpt, Clone)]
pub struct OtherSecret {
    /// Use a keyfile instead of a password
    #[structopt(short = "d", long = "keyfile", conflicts_with = "fido_device")]
    pub keyfile: Option<PathBuf>,
    /// Use another fido device instead of a password
    /// Note: this requires for the credential for the other device to be passed as argument as well
    #[structopt(short = "f", long = "fido-device", conflicts_with = "keyfile")]
    pub fido_device: bool,
}

#[derive(Debug, StructOpt)]
pub enum Command {
    #[structopt(name = "print-secret")]
    PrintSecret {
        // version 0.3.0 will store use the lower case ascii encoded hex string making binary output unnecessary
        /// Prints the secret as binary instead of hex encoded
        #[structopt(hidden = true, short = "b", long = "bin")]
        binary: bool,
        #[structopt(flatten)]
        credentials: Credentials,
        #[structopt(flatten)]
        authenticator: AuthenticatorParameters,
        #[structopt(flatten)]
        secret: SecretParameters,
        /// Load credentials from LUKS header
        #[structopt(env = "FIDO2LUKS_DEVICE")]
        device: Option<PathBuf>,
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
        /// Will generate an credential while adding a new key to this LUKS device if supported
        #[structopt(short = "g", long = "gen-cred")]
        generate_credential: bool,
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
        /// Remove the affected credential from LUKS header
        #[structopt(short = "r", long = "remove-cred")]
        remove_cred: bool,
        #[structopt(flatten)]
        replacement: OtherSecret,
        #[structopt(flatten)]
        luks_mod: LuksModParameters,
    },
    /// Open the LUKS device
    #[structopt(name = "open", alias = "open-token")]
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
        /// Perform the whole procedure without mounting the LUKS volume on success
        #[structopt(long = "dry-run")]
        dry_run: bool,
    },
    /// Generate a new FIDO credential
    #[structopt(name = "credential")]
    Credential {
        #[structopt(flatten)]
        authenticator: AuthenticatorParameters,
        /// Name to be displayed on the authenticator display
        #[structopt(env = "FIDO2LUKS_CREDENTIAL_NAME", default_value = "fido2luks")]
        name: String,
    },
    /// Check if an authenticator is connected
    #[structopt(name = "connected")]
    Connected,
    Token(TokenCommand),
    /// Generate bash completion scripts
    /// Example: fido2luks completions --shell bash /usr/share/bash-completion/completions
    #[structopt(name = "completions", setting = AppSettings::Hidden)]
    GenerateCompletions {
        /// Shell to generate completions for
        #[structopt(short = "s", long = "shell",possible_values = &Shell::variants()[..])]
        shell: Option<String>,
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
        /// FIDO credential ids, separated by ',' generate using fido2luks credential
        #[structopt(
            name = "credential-ids",
            env = "FIDO2LUKS_CREDENTIAL_ID",
            short = "c",
            long = "creds"
        )]
        credentials: CommaSeparated<HexEncoded>,
        /// Slot to which the credentials will be added
        #[structopt(long = "slot", env = "FIDO2LUKS_DEVICE_SLOT")]
        slot: u32,
    },
    /// Remove credentials from token(s)
    Remove {
        #[structopt(env = "FIDO2LUKS_DEVICE")]
        device: PathBuf,
        /// FIDO credential ids, separated by ',' generate using fido2luks credential
        #[structopt(
            name = "credential-ids",
            env = "FIDO2LUKS_CREDENTIAL_ID",
            short = "c",
            long = "creds"
        )]
        credentials: CommaSeparated<HexEncoded>,
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
