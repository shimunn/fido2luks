#![deny(warnings)]
#![allow(non_camel_case_types)]
extern crate libc;

use libc::{c_char, c_double, c_int, c_uint, c_void, size_t};
use std::str::FromStr;

pub enum crypt_device {}

#[repr(i32)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum crypt_log_level {
    CRYPT_LOG_NORMAL = 0,
    CRYPT_LOG_ERROR = 1,
    CRYPT_LOG_VERBOSE = 2,
    CRYPT_LOG_DEBUG = -1,
}

pub type crypt_log_cb = extern "C" fn(crypt_log_level, *const c_char, *mut c_void);
pub type crypt_confirm_cb = extern "C" fn(*const c_char, *mut c_void) -> c_int;
pub type crypt_password_cb =
    extern "C" fn(*const c_char, *mut c_char, size_t, *mut c_void) -> c_int;

#[repr(i32)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum crypt_rng_type {
    CRYPT_RNG_URANDOM = 0,
    CRYPT_RNG_RANDOM = 1,
}

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum crypt_device_type {
    PLAIN,
    LUKS1,
    LOOPAES,
    VERITY,
    TCRYPT,
}

#[repr(C)]
pub struct crypt_params_plain {
    pub hash: *const c_char,
    pub offset: u64,
    pub skip: u64,
    pub size: u64,
}

#[repr(C)]
pub struct crypt_params_luks1 {
    pub hash: *const c_char,
    pub data_alignment: size_t,
    pub data_device: *const c_char,
}

#[repr(C)]
pub struct crypt_params_loopaes {
    pub hash: *const c_char,
    pub offset: u64,
    pub skip: u64,
}

#[repr(C)]
pub struct crypt_params_verity {
    pub hash_name: *const c_char,
    pub data_device: *const c_char,
    pub hash_device: *const c_char,
    pub salt: *const c_char,
    pub salt_size: u32,
    pub hash_type: u32,
    pub data_block_size: u32,
    pub hash_block_size: u32,
    pub data_size: u64,
    pub hash_area_offset: u64,
    pub flags: u32,
}

#[repr(u32)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum crypt_verity_flag {
    CRYPT_VERITY_NO_HEADER = (1 << 0),
    CRYPT_VERITY_CHECK_HASH = (1 << 1),
    CRYPT_VERITY_CREATE_HASH = (1 << 2),
}

#[repr(C)]
pub struct crypt_params_tcrypt {
    pub passphrase: *const c_char,
    pub passphrase_size: size_t,
    pub keyfiles: *const *const c_char,
    pub keyfiles_count: c_uint,
    pub hash_name: *const c_char,
    pub cipher: *const c_char,
    pub mode: *const c_char,
    pub key_size: size_t,
    pub flags: u32,
}

#[repr(u32)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum crypt_tcrypt_flag {
    CRYPT_TCRYPT_LEGACY_MODES = (1 << 0),
    CRYPT_TCRYPT_HIDDEN_HEADER = (1 << 1),
    CRYPT_TCRYPT_BACKUP_HEADER = (1 << 2),
    CRYPT_TCRYPT_SYSTEM_HEADER = (1 << 3),
    CRYPT_TCRYPT_VERA_MODES = (1 << 4),
}

pub const CRYPT_ANY_SLOT: c_int = -1;

#[repr(u32)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum crypt_activation_flag {
    CRYPT_ACTIVATE_READONLY = (1 << 0),
    CRYPT_ACTIVATE_NO_UUID = (1 << 1),
    CRYPT_ACTIVATE_SHARED = (1 << 2),
    CRYPT_ACTIVATE_ALLOW_DISCARDS = (1 << 3),
    CRYPT_ACTIVATE_PRIVATE = (1 << 4),
    CRYPT_ACTIVATE_CORRUPTED = (1 << 5),
    CRYPT_ACTIVATE_SAME_CPU_CRYPT = (1 << 6),
    CRYPT_ACTIVATE_SUBMIT_FROM_CRYPT_CPUS = (1 << 7),
    CRYPT_ACTIVATE_IGNORE_CORRUPTION = (1 << 8),
    CRYPT_ACTIVATE_RESTART_ON_CORRUPTION = (1 << 9),
    CRYPT_ACTIVATE_IGNORE_ZERO_BLOCKS = (1 << 10),
}

#[repr(C)]
pub struct crypt_active_device {
    pub offset: u64,
    pub iv_offset: u64,
    pub size: u64,
    pub flags: u32,
}

#[repr(C)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum crypt_status_info {
    CRYPT_INVALID,
    CRYPT_INACTIVE,
    CRYPT_ACTIVE,
    CRYPT_BUSY,
}

#[repr(C)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum crypt_keyslot_info {
    CRYPT_SLOT_INVALID,
    CRYPT_SLOT_INACTIVE,
    CRYPT_SLOT_ACTIVE,
    CRYPT_SLOT_ACTIVE_LAST,
}

#[repr(C)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum crypt_debug_level {
    CRYPT_DEBUG_ALL = -1,
    CRYPT_DEBUG_NONE = 0,
}

extern "C" {
    pub fn crypt_init(cd: *mut *mut crypt_device, device: *const c_char) -> c_int;
    pub fn crypt_init_by_name_and_header(
        cd: *mut *mut crypt_device,
        name: *const c_char,
        header_device: *const c_char,
    ) -> c_int;
    pub fn crypt_init_by_name(cd: *mut *mut crypt_device, name: *const c_char) -> c_int;

    pub fn crypt_set_log_callback(
        cd: *mut crypt_device,
        log: Option<crypt_log_cb>,
        usrptr: *mut c_void,
    );
    pub fn crypt_log(cd: *mut crypt_device, level: crypt_log_level, msg: *const c_char);

    pub fn crypt_set_confirm_callback(
        cd: *mut crypt_device,
        confirm: crypt_confirm_cb,
        usrptr: *mut c_void,
    );
    #[deprecated]
    pub fn crypt_set_password_callback(
        cd: *mut crypt_device,
        password: crypt_password_cb,
        usrptr: *mut c_void,
    );
    #[deprecated]
    pub fn crypt_set_timeout(cd: *mut crypt_device, timeout: u64);
    #[deprecated]
    pub fn crypt_set_password_retry(cd: *mut crypt_device, tries: c_int);
    pub fn crypt_set_iteration_time(cd: *mut crypt_device, iteration_time_ms: u64);
    #[deprecated]
    pub fn crypt_set_password_verify(cd: *mut crypt_device, password_verify: c_int);
    pub fn crypt_set_data_device(cd: *mut crypt_device, device: *const c_char) -> c_int;

    pub fn crypt_set_rng_type(cd: *mut crypt_device, rng_type: crypt_rng_type);
    pub fn crypt_get_rng_type(cd: *mut crypt_device) -> c_int;

    pub fn crypt_memory_lock(cd: *mut crypt_device, lock: c_int) -> c_int;

    pub fn crypt_get_type(cd: *mut crypt_device) -> *const c_char;

    pub fn crypt_format(
        cd: *mut crypt_device,
        crypt_type: *const c_char,
        cipher: *const c_char,
        cipher_mode: *const c_char,
        uuid: *const c_char,
        volume_key: *const c_char,
        volume_key_size: size_t,
        params: *mut c_void,
    ) -> c_int;

    pub fn crypt_set_uuid(cd: *mut crypt_device, uuid: *const c_char) -> c_int;

    pub fn crypt_load(
        cd: *mut crypt_device,
        requested_type: *const c_char,
        params: *mut c_void,
    ) -> c_int;

    pub fn crypt_repair(
        cd: *mut crypt_device,
        requested_type: *const c_char,
        params: *mut c_void,
    ) -> c_int;

    pub fn crypt_resize(cd: *mut crypt_device, name: *const c_char, new_size: u64) -> c_int;

    pub fn crypt_suspend(cd: *mut crypt_device, name: *const c_char) -> c_int;

    pub fn crypt_resume_by_passphrase(
        cd: *mut crypt_device,
        name: *const c_char,
        keyslot: c_int,
        passphrase: *const c_char,
        passphrase_size: size_t,
    ) -> c_int;
    pub fn crypt_resume_by_keyfile_offset(
        cd: *mut crypt_device,
        name: *const c_char,
        keyslot: c_int,
        keyfile: *const c_char,
        keyfile_size: size_t,
        keyfile_offset: size_t,
    ) -> c_int;
    pub fn crypt_resume_by_keyfile(
        cd: *mut crypt_device,
        name: *const c_char,
        keyslot: c_int,
        keyfile: *const c_char,
        keyfile_size: size_t,
    ) -> c_int;

    pub fn crypt_free(cd: *mut crypt_device);

    pub fn crypt_keyslot_add_by_passphrase(
        cd: *mut crypt_device,
        keyslot: c_int,
        passphrase: *const c_char,
        passphrase_size: size_t,
        new_passphrase: *const c_char,
        new_passphrase_size: size_t,
    ) -> c_int;
    pub fn crypt_keyslot_change_by_passphrase(
        cd: *mut crypt_device,
        keyslot_old: c_int,
        keyslot_new: c_int,
        passphrase: *const c_char,
        passphrase_size: size_t,
        new_passphrase: *const c_char,
        new_passphrase_size: size_t,
    ) -> c_int;

    pub fn crypt_keyslot_add_by_keyfile_offset(
        cd: *mut crypt_device,
        keyslot: c_int,
        keyfile: *const c_char,
        keyfile_size: size_t,
        keyfile_offset: size_t,
        new_keyfile: *const c_char,
        new_keyfile_size: size_t,
        new_keyfile_offset: size_t,
    ) -> c_int;
    pub fn crypt_keyslot_add_by_keyfile(
        cd: *mut crypt_device,
        keyslot: c_int,
        keyfile: *const c_char,
        keyfile_size: size_t,
        new_keyfile: *const c_char,
        new_keyfile_size: size_t,
    ) -> c_int;

    pub fn crypt_keyslot_add_by_volume_key(
        cd: *mut crypt_device,
        keyslot: c_int,
        volume_key: *const c_char,
        volume_key_size: size_t,
        passphrase: *const c_char,
        passphrase_size: size_t,
    ) -> c_int;

    pub fn crypt_keyslot_destroy(cd: *mut crypt_device, keyslot: c_int) -> c_int;

    pub fn crypt_get_active_device(
        cd: *mut crypt_device,
        name: *const c_char,
        cad: *mut crypt_active_device,
    ) -> c_int;

    pub fn crypt_activate_by_passphrase(
        cd: *mut crypt_device,
        name: *const c_char,
        keyslot: c_int,
        passphrase: *const c_char,
        passphrase_size: size_t,
        flags: u32,
    ) -> c_int;

    pub fn crypt_activate_by_keyfile_offset(
        cd: *mut crypt_device,
        name: *const c_char,
        keyslot: c_int,
        keyfile: *const c_char,
        keyfile_size: size_t,
        keyfile_offset: size_t,
        flags: u32,
    ) -> c_int;
    pub fn crypt_activate_by_keyfile(
        cd: *mut crypt_device,
        name: *const c_char,
        keyslot: c_int,
        keyfile: *const c_char,
        keyfile_size: size_t,
        flags: u32,
    ) -> c_int;

    pub fn crypt_activate_by_volume_key(
        cd: *mut crypt_device,
        name: *const c_char,
        volume_key: *const c_char,
        volume_key_size: size_t,
        flags: u32,
    ) -> c_int;

    pub fn crypt_deactivate(cd: *mut crypt_device, name: *const c_char) -> c_int;

    pub fn crypt_volume_key_get(
        cd: *mut crypt_device,
        keyslot: c_int,
        volume_key: *mut c_char,
        volume_key_size: *mut size_t,
        passphrase: *const c_char,
        passphrase_size: size_t,
    ) -> c_int;

    pub fn crypt_volume_key_verify(
        cd: *mut crypt_device,
        volume_key: *const c_char,
        volume_key_size: size_t,
    ) -> c_int;

    pub fn crypt_status(cd: *mut crypt_device, name: *const c_char) -> crypt_status_info;

    pub fn crypt_dump(cd: *mut crypt_device) -> c_int;

    pub fn crypt_get_cipher(cd: *mut crypt_device) -> *const c_char;
    pub fn crypt_get_cipher_mode(cd: *mut crypt_device) -> *const c_char;
    pub fn crypt_get_uuid(cd: *mut crypt_device) -> *const c_char;
    pub fn crypt_get_device_name(cd: *mut crypt_device) -> *const c_char;
    pub fn crypt_get_data_offset(cd: *mut crypt_device) -> u64;
    pub fn crypt_get_iv_offset(cd: *mut crypt_device) -> u64;
    pub fn crypt_get_volume_key_size(cd: *mut crypt_device) -> c_int;
    pub fn crypt_get_verity_info(cd: *mut crypt_device, vp: *mut crypt_params_verity);

    pub fn crypt_benchmark(
        cd: *mut crypt_device,
        cipher: *const c_char,
        cipher_mode: *const c_char,
        volume_key_size: size_t,
        iv_size: size_t,
        buffer_size: size_t,
        encryption_mbs: *mut c_double,
        decryption_mbs: *mut c_double,
    ) -> c_int;
    pub fn crypt_benchmark_kdf(
        cd: *mut crypt_device,
        kdf: *const c_char,
        hash: *const c_char,
        password: *const c_char,
        password_size: size_t,
        salt: *const c_char,
        salt_size: size_t,
        iterations_sec: *mut u64,
    ) -> c_int;

    pub fn crypt_keyslot_status(cd: *mut crypt_device, keyslot: c_int) -> crypt_keyslot_info;

    pub fn crypt_keyslot_max(crypt_device_type: *const c_char) -> c_int;

    pub fn crypt_keyslot_area(
        cd: *mut crypt_device,
        keyslot: c_int,
        offset: *mut u64,
        length: *mut u64,
    ) -> c_int;

    pub fn crypt_header_backup(
        cd: *mut crypt_device,
        requested_type: *const c_char,
        backup_file: *const c_char,
    ) -> c_int;
    pub fn crypt_header_restore(
        cd: *mut crypt_device,
        requested_type: *const c_char,
        backup_file: *const c_char,
    ) -> c_int;

    #[deprecated]
    pub fn crypt_last_error(cd: *mut crypt_device, buf: *mut c_char, size: size_t);
    #[deprecated]
    pub fn crypt_get_error(buf: *mut c_char, size: size_t);

    pub fn crypt_get_dir() -> *const c_char;

    pub fn crypt_set_debug_level(level: crypt_debug_level);
}

impl FromStr for crypt_device_type {
    type Err = ();

    fn from_str(s: &str) -> Result<crypt_device_type, ()> {
        match s {
            "PLAIN" => Ok(crypt_device_type::PLAIN),
            "LUKS1" => Ok(crypt_device_type::LUKS1),
            "LOOPAES" => Ok(crypt_device_type::LOOPAES),
            "VERITY" => Ok(crypt_device_type::VERITY),
            "TCRYPT" => Ok(crypt_device_type::TCRYPT),
            _ => Err(()),
        }
    }
}

impl crypt_device_type {
    pub fn to_str(&self) -> &str {
        match self {
            &crypt_device_type::PLAIN => "PLAIN",
            &crypt_device_type::LUKS1 => "LUKS1",
            &crypt_device_type::LOOPAES => "LOOPAES",
            &crypt_device_type::VERITY => "VERITY",
            &crypt_device_type::TCRYPT => "TCRYPT",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::str::FromStr;

    #[test]
    fn test_device_type_conversion() {
        assert_eq!(
            Ok(crypt_device_type::PLAIN),
            crypt_device_type::from_str("PLAIN")
        );
        assert_eq!(
            Ok(crypt_device_type::LUKS1),
            crypt_device_type::from_str("LUKS1")
        );
        assert_eq!(
            Ok(crypt_device_type::LOOPAES),
            crypt_device_type::from_str("LOOPAES")
        );
        assert_eq!(
            Ok(crypt_device_type::VERITY),
            crypt_device_type::from_str("VERITY")
        );
        assert_eq!(
            Ok(crypt_device_type::TCRYPT),
            crypt_device_type::from_str("TCRYPT")
        );
    }

    #[test]
    fn test_keyslot_max_gt_zero() {
        unsafe {
            let luks_type = CString::new("LUKS1").unwrap();
            assert!(crypt_keyslot_max(luks_type.as_ptr()) > 0);
        }
    }
}
