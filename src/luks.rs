use crate::error::*;

use libcryptsetup_rs::{
    CryptActivateFlags, CryptDevice, CryptInit, CryptTokenInfo, EncryptionFormat, KeyslotInfo,
    TokenInput,
};
use std::collections::{HashMap, HashSet};
use std::path::Path;

fn load_device_handle<P: AsRef<Path>>(path: P) -> Fido2LuksResult<CryptDevice> {
    let mut device = CryptInit::init(path.as_ref())?;
    device.context_handle().load::<()>(None, None)?;
    Ok(device)
}

fn check_luks2(device: &mut CryptDevice) -> Fido2LuksResult<()> {
    match device.format_handle().get_type()? {
        EncryptionFormat::Luks2 => Ok(()),
        _ => Err(Fido2LuksError::LuksError {
            cause: LuksError::Luks2Required,
        }),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Fido2LuksToken {
    #[serde(rename = "type")]
    type_: String,
    credential: Vec<String>,
    keyslots: Vec<String>,
}

impl Fido2LuksToken {
    fn new(credential_id: impl AsRef<[u8]>, slot: u32) -> Self {
        Self {
            type_: "fido2luks\0".into(), // Doubles as c style string
            credential: vec![hex::encode(credential_id)],
            keyslots: vec![slot.to_string()],
        }
    }
}

pub fn open_container<P: AsRef<Path>>(
    path: P,
    name: &str,
    secret: &[u8],
    slot_hint: Option<u32>,
) -> Fido2LuksResult<()> {
    let mut device = load_device_handle(path)?;
    device
        .activate_handle()
        .activate_by_passphrase(Some(name), slot_hint, secret, CryptActivateFlags::empty())
        .map(|_slot| ())
        .map_err(|_e| Fido2LuksError::WrongSecret)
}

pub fn open_container_token<P: AsRef<Path>>(
    path: P,
    name: &str,
    secret: impl Fn(Vec<String>) -> Fido2LuksResult<([u8; 32], String)>,
) -> Fido2LuksResult<()> {
    let mut device = load_device_handle(path)?;
    check_luks2(&mut device)?;

    let mut creds = HashMap::new();
    for i in 0..256 {
        let status = device.token_handle().status(i)?;
        match status {
            CryptTokenInfo::Inactive => break,
            CryptTokenInfo::Internal(s)
            | CryptTokenInfo::InternalUnknown(s)
            | CryptTokenInfo::ExternalUnknown(s)
            | CryptTokenInfo::External(s)
                if &s != "fido2luks" =>
            {
                continue
            }
            _ => (),
        };
        let json = device.token_handle().json_get(i)?;
        let info: Fido2LuksToken =
            serde_json::from_value(json.clone()).map_err(|_| Fido2LuksError::LuksError {
                cause: LuksError::InvalidToken(json.to_string()),
            })?;
        let slots = || {
            info.keyslots
                .iter()
                .filter_map(|slot| slot.parse::<u32>().ok())
        };
        for cred in info.credential.iter().cloned() {
            creds
                .entry(cred)
                .or_insert_with(|| slots().collect::<HashSet<u32>>())
                .extend(slots());
        }
    }
    if creds.is_empty() {
        return Err(Fido2LuksError::LuksError {
            cause: LuksError::NoToken,
        });
    }
    let (secret, credential) = secret(creds.keys().cloned().collect())?;
    let slots = creds.get(&credential).unwrap();
    let slots = slots
        .iter()
        .cloned()
        .map(Option::Some)
        .chain(std::iter::once(None).take(slots.is_empty() as usize));
    for slot in slots {
        match device
            .activate_handle()
            .activate_by_passphrase(Some(name), slot, &secret, CryptActivateFlags::empty())
            .map(|_slot| ())
            .map_err(LuksError::activate)
        {
            Err(Fido2LuksError::WrongSecret) => (),
            res => return res,
        }
    }
    Err(Fido2LuksError::WrongSecret)
}

pub fn add_key<P: AsRef<Path>>(
    path: P,
    secret: &[u8],
    old_secret: &[u8],
    iteration_time: Option<u64>,
    credential_id: Option<&[u8]>,
) -> Fido2LuksResult<u32> {
    let mut device = load_device_handle(path)?;
    if let Some(millis) = iteration_time {
        device.settings_handle().set_iteration_time(millis)
    }
    let slot = device
        .keyslot_handle()
        .add_by_passphrase(None, old_secret, secret)?;
    if let Some(id) = credential_id {
        /*  if let e @ Err(_) = check_luks2(&mut device) {
            //rollback
            device.keyslot_handle(Some(slot)).destroy()?;
            return e.map(|_| 0u32);
        }*/
        device.token_handle().json_set(TokenInput::AddToken(
            &serde_json::to_value(&Fido2LuksToken::new(id, slot)).unwrap(),
        ))?;
    }

    Ok(slot)
}

fn find_token(
    device: &mut CryptDevice,
    slot: u32,
) -> Fido2LuksResult<Option<(u32, Fido2LuksToken)>> {
    for i in 0..256 {
        let status = device.token_handle().status(i)?;
        match status {
            CryptTokenInfo::Inactive => break,
            CryptTokenInfo::Internal(s)
            | CryptTokenInfo::InternalUnknown(s)
            | CryptTokenInfo::ExternalUnknown(s)
            | CryptTokenInfo::External(s)
                if &s != "fido2luks" =>
            {
                continue
            }
            _ => (),
        };
        let json = device.token_handle().json_get(i)?;
        let info: Fido2LuksToken =
            serde_json::from_value(json.clone()).map_err(|_| Fido2LuksError::LuksError {
                cause: LuksError::InvalidToken(json.to_string()),
            })?;
        if info.keyslots.contains(&slot.to_string()) {
            return Ok(Some((i, info)));
        }
    }
    Ok(None)
}

pub fn remove_keyslots<P: AsRef<Path>>(path: P, exclude: &[u32]) -> Fido2LuksResult<u32> {
    let mut device = load_device_handle(path)?;
    let mut destroyed = 0;
    let mut tokens = Vec::new();
    for slot in 0..256 {
        match device.keyslot_handle().status(slot)? {
            KeyslotInfo::Inactive => continue,
            KeyslotInfo::Active | KeyslotInfo::ActiveLast if !exclude.contains(&slot) => {
                if let Ok(_) = check_luks2(&mut device) {
                    if let Some((token, _)) = dbg!(find_token(&mut device, slot))? {
                        tokens.push(token);
                    }
                }
                device.keyslot_handle().destroy(slot)?;
                destroyed += 1;
            }
            KeyslotInfo::ActiveLast => break,
            _ => (),
        }
        if device.keyslot_handle().status(slot)? == KeyslotInfo::ActiveLast {
            break;
        }
    }
    for token in tokens.iter() {
        device
            .token_handle()
            .json_set(TokenInput::RemoveToken(*token))?;
    }
    Ok(destroyed)
}

pub fn replace_key<P: AsRef<Path>>(
    path: P,
    secret: &[u8],
    old_secret: &[u8],
    iteration_time: Option<u64>,
    credential_id: Option<&[u8]>,
) -> Fido2LuksResult<u32> {
    let mut device = load_device_handle(path)?;
    // Set iteration time not sure wether this applies to luks2 as well
    if let Some(millis) = iteration_time {
        device.settings_handle().set_iteration_time(millis)
    }
    let slot = device
        .keyslot_handle()
        .change_by_passphrase(None, None, old_secret, secret)? as u32;
    if let Some(id) = credential_id {
        if check_luks2(&mut device).is_ok() {
            let token = find_token(&mut device, slot)?.map(|(t, _)| t);
            if let Some(token) = token {
                device.token_handle().json_set(TokenInput::ReplaceToken(
                    token,
                    &serde_json::to_value(&Fido2LuksToken::new(id, slot)).unwrap(),
                ))?;
            }
        }
    }
    Ok(slot)
}
