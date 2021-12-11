## 0.3.0

* LUKS2 Tokens are now supported by every subcommand
* `<credential>` has been converted into the flag `--creds`  
credentials provided by `--creds` will be supplemented from the LUKS header unless this is disabled by `--disable-token`
* `fido2luks add-key` will take an `--auto-cred` flag which allows for credentials to be generated and stored without having to use `fido2luks credential`  
`fido2luks replace-key` will allow for credentials to be removed using the `--remove-cred` flag respectively 
* Removed `fido2luks open-token` subcommand  
  `fido2luks open` now fulfills both functions
* Added `fido2luks open --dry-run` flag, to perform the whole procedure apart from mounting the LUKS volume
* Added an `--verbose` flag to display additional information like credentials and keyslots used if desired