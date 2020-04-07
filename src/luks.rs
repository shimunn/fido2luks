use crate::error::*;

use libcryptsetup_rs::{CryptActivateFlags, CryptDevice, CryptInit, EncryptionFormat, KeyslotInfo};
use std::path::Path;

fn load_device_handle<P: AsRef<Path>>(path: P) -> Fido2LuksResult<CryptDevice> {
    let mut device = CryptInit::init(path.as_ref())?;
    //TODO: determine luks version some way other way than just trying
    let mut load = |format| device.context_handle().load::<()>(format, None).map(|_| ());
    vec![EncryptionFormat::Luks2, EncryptionFormat::Luks1]
        .into_iter()
        .fold(None, |res, format| match res {
            Some(Ok(())) => res,
            Some(e) => Some(e.or_else(|_| load(format))),
            None => Some(load(format)),
        })
        .unwrap()?;
    Ok(device)
}

pub fn open_container<P: AsRef<Path>>(path: P, name: &str, secret: &[u8]) -> Fido2LuksResult<()> {
    let mut device = load_device_handle(path)?;
    device
        .activate_handle()
        .activate_by_passphrase(Some(name), None, secret, CryptActivateFlags::empty())
        .map(|_slot| ())
        .map_err(|_e| Fido2LuksError::WrongSecret)
}

pub fn add_key<P: AsRef<Path>>(
    path: P,
    secret: &[u8],
    old_secret: &[u8],
    iteration_time: Option<u64>,
) -> Fido2LuksResult<u32> {
    let mut device = load_device_handle(path)?;
    if let Some(millis) = iteration_time {
        device.settings_handle().set_iteration_time(millis)
    }
    let slot = device
        .keyslot_handle(None)
        .add_by_passphrase(old_secret, secret)?;
    Ok(slot)
}

pub fn remove_keyslots<P: AsRef<Path>>(path: P, exclude: &[u32]) -> Fido2LuksResult<u32> {
    let mut device = load_device_handle(path)?;
    let mut handle;
    let mut destroyed = 0;
    //TODO: detect how many keyslots there are instead of trying within a given range
    for slot in 0..1024 {
        handle = device.keyslot_handle(Some(slot));
        match handle.status()? {
            KeyslotInfo::Inactive => continue,
            KeyslotInfo::Active if !exclude.contains(&slot) => {
                handle.destroy()?;
                destroyed += 1;
            }
            _ => (),
        }
        if let KeyslotInfo::ActiveLast = handle.status()? {
            break;
        }
    }
    Ok(destroyed)
}

pub fn replace_key<P: AsRef<Path>>(
    path: P,
    secret: &[u8],
    old_secret: &[u8],
    iteration_time: Option<u64>,
) -> Fido2LuksResult<u32> {
    let mut device = load_device_handle(path)?;
    // Set iteration time not sure wether this applies to luks2 as well
    if let Some(millis) = iteration_time {
        device.settings_handle().set_iteration_time(millis)
    }
    Ok(device
        .keyslot_handle(None)
        .change_by_passphrase(None, None, old_secret, secret)? as u32)
}
