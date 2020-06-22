use crate::error::*;

use libcryptsetup_rs::{
    CryptActivateFlags, CryptDevice, CryptInit, CryptTokenInfo, EncryptionFormat, KeyslotInfo,
    TokenInput,
};
use std::collections::{HashMap, HashSet};
use std::path::Path;

pub struct LuksDevice {
    device: CryptDevice,
    luks2: Option<bool>,
}

impl LuksDevice {
    pub fn load<P: AsRef<Path>>(path: P) -> Fido2LuksResult<LuksDevice> {
        let mut device = CryptInit::init(path.as_ref())?;
        device.context_handle().load::<()>(None, None)?;
        Ok(Self {
            device,
            luks2: None,
        })
    }

    pub fn is_luks2(&mut self) -> Fido2LuksResult<bool> {
        if let Some(luks2) = self.luks2 {
            Ok(luks2)
        } else {
            self.luks2 = Some(match self.device.format_handle().get_type()? {
                EncryptionFormat::Luks2 => true,
                _ => false,
            });
            self.is_luks2()
        }
    }

    fn require_luks2(&mut self) -> Fido2LuksResult<()> {
        if !self.is_luks2()? {
            return Err(LuksError::Luks2Required.into());
        }
        Ok(())
    }

    pub fn tokens<'a>(
        &'a mut self,
    ) -> Fido2LuksResult<Box<dyn Iterator<Item = Fido2LuksResult<(u32, Fido2LuksToken)>> + 'a>>
    {
        self.require_luks2()?;
        Ok(Box::new(
            (0..32)
                .map(move |i| {
                    let status = match self.device.token_handle().status(i) {
                        Ok(status) => status,
                        Err(err) => return Some(Err(Fido2LuksError::from(err))),
                    };
                    match status {
                        CryptTokenInfo::Inactive => return None,
                        CryptTokenInfo::Internal(s)
                        | CryptTokenInfo::InternalUnknown(s)
                        | CryptTokenInfo::ExternalUnknown(s)
                        | CryptTokenInfo::External(s)
                            if &s != Fido2LuksToken::default_type() =>
                        {
                            return None
                        }
                        _ => (),
                    };
                    let json = match self.device.token_handle().json_get(i) {
                        Ok(json) => json,
                        Err(err) => return Some(Err(Fido2LuksError::from(err))),
                    };
                    let info: Fido2LuksToken =
                        match serde_json::from_value(json.clone()).map_err(|_| {
                            Fido2LuksError::LuksError {
                                cause: LuksError::InvalidToken(json.to_string()),
                            }
                        }) {
                            Ok(info) => info,
                            Err(err) => return Some(Err(Fido2LuksError::from(err))),
                        };
                    Some(Ok((i, info)))
                })
                .filter_map(|o| o),
        ))
    }

    pub fn find_token(&mut self, slot: u32) -> Fido2LuksResult<Option<(u32, Fido2LuksToken)>> {
        let slot_str = slot.to_string();
        for token in self.tokens()? {
            let (id, token) = token?;
            if token.keyslots.contains(&slot_str) {
                return Ok(Some((id, token)));
            }
        }
        Ok(None)
    }

    pub fn add_token(&mut self, data: &Fido2LuksToken) -> Fido2LuksResult<()> {
        self.require_luks2()?;
        self.device
            .token_handle()
            .json_set(TokenInput::AddToken(&serde_json::to_value(&data).unwrap()))?;
        Ok(())
    }

    pub fn remove_token(&mut self, token: u32) -> Fido2LuksResult<()> {
        self.require_luks2()?;
        self.device
            .token_handle()
            .json_set(TokenInput::RemoveToken(token))?;
        Ok(())
    }

    pub fn update_token(&mut self, token: u32, data: &Fido2LuksToken) -> Fido2LuksResult<()> {
        self.require_luks2()?;
        self.device
            .token_handle()
            .json_set(TokenInput::ReplaceToken(
                token,
                &serde_json::to_value(&data).unwrap(),
            ))?;
        Ok(())
    }

    pub fn add_key(
        &mut self,
        secret: &[u8],
        old_secret: &[u8],
        iteration_time: Option<u64>,
        credential_id: Option<&[u8]>,
    ) -> Fido2LuksResult<u32> {
        if let Some(millis) = iteration_time {
            self.device.settings_handle().set_iteration_time(millis)
        }
        let slot = self
            .device
            .keyslot_handle()
            .add_by_passphrase(None, old_secret, secret)?;
        if let Some(id) = credential_id {
            self.device.token_handle().json_set(TokenInput::AddToken(
                &serde_json::to_value(&Fido2LuksToken::new(id, slot)).unwrap(),
            ))?;
        }

        Ok(slot)
    }

    pub fn remove_keyslots(&mut self, exclude: &[u32]) -> Fido2LuksResult<u32> {
        let mut destroyed = 0;
        let mut tokens = Vec::new();
        for slot in 0..256 {
            match self.device.keyslot_handle().status(slot)? {
                KeyslotInfo::Inactive => continue,
                KeyslotInfo::Active | KeyslotInfo::ActiveLast if !exclude.contains(&slot) => {
                    if self.is_luks2()? {
                        if let Some((id, _token)) = self.find_token(slot)? {
                            tokens.push(id);
                        }
                    }
                    self.device.keyslot_handle().destroy(slot)?;
                    destroyed += 1;
                }
                KeyslotInfo::ActiveLast => break,
                _ => (),
            }
            if self.device.keyslot_handle().status(slot)? == KeyslotInfo::ActiveLast {
                break;
            }
        }
        // Ensure indices stay valid
        tokens.sort();
        for token in tokens.iter().rev() {
            self.remove_token(*token)?;
        }
        Ok(destroyed)
    }

    pub fn replace_key(
        &mut self,
        secret: &[u8],
        old_secret: &[u8],
        iteration_time: Option<u64>,
        credential_id: Option<&[u8]>,
    ) -> Fido2LuksResult<u32> {
        if let Some(millis) = iteration_time {
            self.device.settings_handle().set_iteration_time(millis)
        }
        // Use activate dry-run to locate keyslot
        let slot = self.device.activate_handle().activate_by_passphrase(
            None,
            None,
            old_secret,
            CryptActivateFlags::empty(),
        )?;
        self.device.keyslot_handle().change_by_passphrase(
            Some(slot),
            Some(slot),
            old_secret,
            secret,
        )? as u32;
        if let Some(id) = credential_id {
            if self.is_luks2()? {
                let token = self.find_token(slot)?.map(|(t, _)| t);
                let json = serde_json::to_value(&Fido2LuksToken::new(id, slot)).unwrap();
                if let Some(token) = token {
                    self.device
                        .token_handle()
                        .json_set(TokenInput::ReplaceToken(token, &json))?;
                } else {
                    self.device
                        .token_handle()
                        .json_set(TokenInput::AddToken(&json))?;
                }
            }
        }
        Ok(slot)
    }

    pub fn activate(
        &mut self,
        name: &str,
        secret: &[u8],
        slot_hint: Option<u32>,
    ) -> Fido2LuksResult<u32> {
        self.device
            .activate_handle()
            .activate_by_passphrase(Some(name), slot_hint, secret, CryptActivateFlags::empty())
            .map_err(LuksError::activate)
    }

    pub fn activate_token(
        &mut self,
        name: &str,
        secret: impl Fn(Vec<String>) -> Fido2LuksResult<([u8; 32], String)>,
        slot_hint: Option<u32>,
    ) -> Fido2LuksResult<u32> {
        if !self.is_luks2()? {
            return Err(LuksError::Luks2Required.into());
        }
        let mut creds: HashMap<String, HashSet<u32>> = HashMap::new();
        for token in self.tokens()? {
            let token = match token {
                Ok((_id, t)) => t,
                _ => continue, // An corrupted token should't lock the user out
            };
            let slots = || {
                token
                    .keyslots
                    .iter()
                    .filter_map(|slot| slot.parse::<u32>().ok())
            };
            for cred in token.credential.iter() {
                creds
                    .entry(cred.clone())
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
        let empty;
        let slots = if let Some(slots) = creds.get(&credential) {
            slots
        } else {
            empty = HashSet::new();
            &empty
        };
        //Try slots associated with the credential used
        let slots = slots.iter().cloned().map(Option::Some).chain(
            std::iter::once(slot_hint) // Try slot hint if there is one
                .take(slot_hint.is_some() as usize)
                .chain(std::iter::once(None).take(slots.is_empty() as usize)), // Try all slots as last resort
        );
        for slot in slots {
            match self.activate(name, &secret, slot) {
                Err(Fido2LuksError::WrongSecret) => (),
                res => return res,
            }
        }
        Err(Fido2LuksError::WrongSecret)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fido2LuksToken {
    #[serde(rename = "type")]
    pub type_: String,
    pub credential: HashSet<String>,
    pub keyslots: HashSet<String>,
}

impl Fido2LuksToken {
    pub fn new(credential_id: impl AsRef<[u8]>, slot: u32) -> Self {
        Self::with_credentials(std::iter::once(credential_id), slot)
    }

    pub fn with_credentials<I: IntoIterator<Item = B>, B: AsRef<[u8]>>(
        credentials: I,
        slot: u32,
    ) -> Self {
        Self {
            credential: credentials
                .into_iter()
                .map(|cred| hex::encode(cred.as_ref()))
                .collect(),
            keyslots: vec![slot.to_string()].into_iter().collect(),
            ..Default::default()
        }
    }
    pub fn default_type() -> &'static str {
        "fido2luks"
    }
}

impl Default for Fido2LuksToken {
    fn default() -> Self {
        Self {
            type_: Self::default_type().into(),
            credential: HashSet::new(),
            keyslots: HashSet::new(),
        }
    }
}
