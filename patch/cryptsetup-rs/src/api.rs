//! High-level API to work with `libcryptsetup` supported devices (disks)

use std::fmt;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::ptr;

use blkid_rs::{BlockDevice, LuksHeader};

use device;
pub use device::enable_debug;
use device::RawDevice;
pub use device::{Error, Keyslot, Result};
use raw;
use uuid;

pub type Luks1CryptDeviceHandle = CryptDeviceHandle<Luks1Params>;

/// Builder to open a crypt device at the specified path
///
/// # Examples
///
/// ```
/// use cryptsetup_rs::*;
/// # fn foo() -> Result<()> {
/// let device = open("/dev/loop0")?.luks1()?;
/// # Ok(())
/// # }
/// ```
pub fn open<P: AsRef<Path>>(path: P) -> Result<CryptDeviceOpenBuilder> {
    let cd = device::init(path.as_ref())?;
    Ok(CryptDeviceOpenBuilder {
        path: path.as_ref().to_owned(),
        cd,
    })
}

/// Builder to format a crypt device at the specified path
///
/// # Examples
///
/// ```
/// # extern crate uuid;
/// # extern crate cryptsetup_rs;
/// use cryptsetup_rs::*;
/// use uuid::Uuid;
///
/// # fn foo() -> Result<()> {
/// let uuid = Uuid::new_v4();
/// let device = format("/dev/loop0")?
///     .rng_type(crypt_rng_type::CRYPT_RNG_URANDOM)
///     .iteration_time(5000)
///     .luks1("aes", "xts-plain", "sha256", 256, Some(&uuid))?;
/// # Ok(())
/// # }
/// ```
pub fn format<P: AsRef<Path>>(path: P) -> Result<CryptDeviceFormatBuilder> {
    let cd = device::init(path.as_ref())?;
    Ok(CryptDeviceFormatBuilder {
        path: path.as_ref().to_owned(),
        cd,
    })
}

/// Read the UUID of a LUKS1 container without opening the device
pub fn luks1_uuid<P: AsRef<Path>>(path: P) -> Result<uuid::Uuid> {
    let device_file = File::open(path.as_ref())?;
    let luks_phdr = BlockDevice::read_luks_header(device_file)?;
    let uuid = luks_phdr.uuid()?;
    Ok(uuid)
}

fn load_luks1_params<P: AsRef<Path>>(path: P) -> Result<Luks1Params> {
    let device_file = File::open(path.as_ref())?;
    let luks_phdr = BlockDevice::read_luks_header(device_file)?;
    Luks1Params::from(luks_phdr)
}

/// Struct containing state for the `open()` builder
pub struct CryptDeviceOpenBuilder {
    path: PathBuf,
    cd: RawDevice,
}

impl CryptDeviceOpenBuilder {
    /// Loads an existing LUKS1 crypt device
    pub fn luks1(self: CryptDeviceOpenBuilder) -> Result<CryptDeviceHandle<Luks1Params>> {
        let _ = device::load(&self.cd, raw::crypt_device_type::LUKS1);
        let params = load_luks1_params(&self.path)?;
        Ok(CryptDeviceHandle {
            cd: self.cd,
            path: self.path,
            params,
        })
    }
}

/// Struct containing state for the `format()` builder
pub struct CryptDeviceFormatBuilder {
    path: PathBuf,
    cd: RawDevice,
}

impl CryptDeviceFormatBuilder {
    /// Set the iteration time for the `PBKDF2` function. Note that this does not affect the MK iterations.
    pub fn iteration_time(mut self, iteration_time_ms: u64) -> Self {
        device::set_iteration_time(&mut self.cd, iteration_time_ms);
        self
    }

    /// Set the random number generator to use
    pub fn rng_type(mut self, rng_type: raw::crypt_rng_type) -> Self {
        device::set_rng_type(&mut self.cd, rng_type);
        self
    }

    /// Formats a new block device as a LUKS1 crypt device with the specified parameters
    pub fn luks1(
        mut self: CryptDeviceFormatBuilder,
        cipher: &str,
        cipher_mode: &str,
        hash: &str,
        mk_bits: usize,
        maybe_uuid: Option<&uuid::Uuid>,
    ) -> Result<CryptDeviceHandle<Luks1Params>> {
        let _ = device::luks1_format(&mut self.cd, cipher, cipher_mode, hash, mk_bits, maybe_uuid)?;
        let params = load_luks1_params(&self.path)?;
        Ok(CryptDeviceHandle {
            cd: self.cd,
            path: self.path,
            params,
        })
    }
}

/// Trait representing common operations on a crypt device
pub trait CryptDevice {
    /// Path the device was opened/created with
    fn path(&self) -> &Path;

    /// Name of cipher used
    fn cipher(&self) -> &str;

    /// Name of cipher mode used
    fn cipher_mode(&self) -> &str;

    /// Path to the underlying device (as reported by `libcryptsetup`)
    fn device_name(&self) -> &str;

    /// Random number generator used for operations on this crypt device
    fn rng_type(&self) -> raw::crypt_rng_type;

    /// Sets the random number generator to use
    fn set_rng_type(&mut self, rng_type: raw::crypt_rng_type);

    /// Sets the iteration time for the `PBKDF2` function. Note that this does not affect the MK iterations.
    fn set_iteration_time(&mut self, iteration_time_ms: u64);

    /// Volume key size (in bytes)
    fn volume_key_size(&self) -> u8;
}

/// Trait for querying the device type at runtime
pub trait CryptDeviceType {
    /// Type of the crypt device
    fn device_type(&self) -> raw::crypt_device_type;
}

/// Trait representing specific operations on a LUKS1 device
pub trait Luks1CryptDevice {
    /// Activate the crypt device, and give it the specified name
    fn activate(&mut self, name: &str, key: &[u8]) -> Result<Keyslot>;

    /// Add a new keyslot with the specified key
    fn add_keyslot(
        &mut self,
        key: &[u8],
        maybe_prev_key: Option<&[u8]>,
        maybe_keyslot: Option<Keyslot>,
    ) -> Result<Keyslot>;

    /// Replace an old key with a new one
    fn update_keyslot(&mut self, key: &[u8], prev_key: &[u8], maybe_keyslot: Option<Keyslot>) -> Result<Keyslot>;

    /// Destroy (and disable) key slot
    fn destroy_keyslot(&mut self, slot: Keyslot) -> Result<()>;

    /// Dump text-formatted information about the current device to stdout
    fn dump(&self);

    /// Get the hash algorithm used
    fn hash_spec(&self) -> &str;

    /// Get status of key slot
    fn keyslot_status(&self, keyslot: Keyslot) -> raw::crypt_keyslot_info;

    /// Number of bits in the master key
    fn mk_bits(&self) -> u32;

    /// Master key header digest
    fn mk_digest(&self) -> &[u8; 20];

    /// Master key `PBKDF2` iterations
    fn mk_iterations(&self) -> u32;

    /// Master key salt
    fn mk_salt(&self) -> &[u8; 32];

    /// Get the offset of the payload
    fn payload_offset(&self) -> u32;

    /// UUID of the current device
    fn uuid(&self) -> uuid::Uuid;
}

/// An opaque handle on an initialized crypt device
#[derive(PartialEq)]
pub struct CryptDeviceHandle<P: fmt::Debug> {
    /// Pointer to the raw device
    cd: RawDevice,

    /// Path to the crypt device (useful for diagnostics)
    path: PathBuf,

    /// Additional parameters depending on type of crypt device opened
    params: P,
}

impl<P: fmt::Debug> fmt::Debug for CryptDeviceHandle<P> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "CryptDeviceHandle(path={}, raw={:p}, params={:?})",
            self.path.display(),
            self.cd,
            self.params
        )
    }
}

impl<P: fmt::Debug> Drop for CryptDeviceHandle<P> {
    fn drop(&mut self) {
        device::free(&mut self.cd);
        self.cd = ptr::null_mut();
    }
}

impl<P: fmt::Debug> CryptDevice for CryptDeviceHandle<P> {
    fn path(&self) -> &Path {
        self.path.as_ref()
    }

    fn cipher(&self) -> &str {
        device::cipher(&self.cd).expect("Initialised device should have cipher")
    }

    fn cipher_mode(&self) -> &str {
        device::cipher_mode(&self.cd).expect("Initialised device should have cipher mode")
    }

    fn device_name(&self) -> &str {
        device::device_name(&self.cd).expect("Initialised device should have an underlying path")
    }

    fn rng_type(&self) -> raw::crypt_rng_type {
        device::rng_type(&self.cd)
    }

    fn set_rng_type(&mut self, rng_type: raw::crypt_rng_type) {
        device::set_rng_type(&mut self.cd, rng_type)
    }

    fn set_iteration_time(&mut self, iteration_time_ms: u64) {
        device::set_iteration_time(&mut self.cd, iteration_time_ms)
    }

    fn volume_key_size(&self) -> u8 {
        device::volume_key_size(&self.cd)
    }
}

/// Struct for storing LUKS1 parameters in memory
#[derive(Debug, PartialEq)]
pub struct Luks1Params {
    hash_spec: String,
    payload_offset: u32,
    mk_bits: u32,
    mk_digest: [u8; 20],
    mk_salt: [u8; 32],
    mk_iterations: u32,
}

impl Luks1Params {
    fn from(header: impl LuksHeader) -> Result<Luks1Params> {
        let hash_spec = header.hash_spec()?.to_owned();
        let payload_offset = header.payload_offset();
        let mk_bits = header.key_bytes() * 8;
        let mut mk_digest = [0u8; 20];
        mk_digest.copy_from_slice(header.mk_digest());
        let mut mk_salt = [0u8; 32];
        mk_salt.copy_from_slice(header.mk_digest_salt());
        let mk_iterations = header.mk_digest_iterations();
        Ok(Luks1Params {
            hash_spec,
            payload_offset,
            mk_bits,
            mk_digest,
            mk_salt,
            mk_iterations,
        })
    }
}

impl Luks1CryptDevice for CryptDeviceHandle<Luks1Params> {
    fn activate(&mut self, name: &str, key: &[u8]) -> Result<Keyslot> {
        device::luks_activate(&mut self.cd, name, key)
    }

    fn add_keyslot(
        &mut self,
        key: &[u8],
        maybe_prev_key: Option<&[u8]>,
        maybe_keyslot: Option<Keyslot>,
    ) -> Result<Keyslot> {
        device::luks_add_keyslot(&mut self.cd, key, maybe_prev_key, maybe_keyslot)
    }

    fn update_keyslot(&mut self, key: &[u8], prev_key: &[u8], maybe_keyslot: Option<Keyslot>) -> Result<Keyslot> {
        device::luks_update_keyslot(&mut self.cd, key, prev_key, maybe_keyslot)
    }

    fn destroy_keyslot(&mut self, slot: Keyslot) -> Result<()> {
        device::luks_destroy_keyslot(&mut self.cd, slot)
    }

    fn dump(&self) {
        device::dump(&self.cd).expect("Dump should be fine for initialised device")
    }

    fn hash_spec(&self) -> &str {
        self.params.hash_spec.as_ref()
    }

    fn keyslot_status(&self, keyslot: Keyslot) -> raw::crypt_keyslot_info {
        device::keyslot_status(&self.cd, keyslot)
    }

    fn mk_bits(&self) -> u32 {
        self.params.mk_bits
    }

    fn mk_digest(&self) -> &[u8; 20] {
        &self.params.mk_digest
    }

    fn mk_iterations(&self) -> u32 {
        self.params.mk_iterations
    }

    fn mk_salt(&self) -> &[u8; 32] {
        &self.params.mk_salt
    }

    fn payload_offset(&self) -> u32 {
        self.params.payload_offset
    }

    fn uuid(&self) -> uuid::Uuid {
        device::uuid(&self.cd).expect("LUKS1 device should have UUID")
    }
}

impl CryptDeviceType for CryptDeviceHandle<Luks1Params> {
    fn device_type(&self) -> raw::crypt_device_type {
        raw::crypt_device_type::LUKS1
    }
}
