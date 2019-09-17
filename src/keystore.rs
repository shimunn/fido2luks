use keyutils::Keyring;

fn get_passphrase() -> Vec<u8> {
    Keyring::request("user")
        .unwrap()
        .request_key("fido2luks")
        .unwrap()
        .read()
        .unwrap()
}

fn add_secret(secret: &[u8]) {
    Keyring::request("session")
        .unwrap()
        .add_key("cryptsetup", secret)
        .unwrap();
}
