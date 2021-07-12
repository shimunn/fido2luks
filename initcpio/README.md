## fido2luks hook for mkinitcpio (ArchLinux and derivatives)

> ⚠️ Before proceeding, it is very advised to [backup your existing LUKS2 header](https://wiki.archlinux.org/title/dm-crypt/Device_encryption#Backup_using_cryptsetup) to external storage

### Setup

1. Connect your FIDO2 authenticator
2. Generate credential id

```shell
fido2luks credential
```

3. Generate salt (random string)

```shell
pwgen 48 1
```

4. Add key to your LUKS2 device

```shell
fido2luks add-key -Pt --salt <salt> <block_device> <credential_id>
```

`-P` - request PIN to unlock the authenticator  
`-t` - add token (including credential id) to the LUKS2 header  
`-e` - wipe all other keys  

For the full list of options see `fido2luks add-key --help`

5. Edit [/etc/fido2luks.conf](/initcpio/fido2luks.conf)

Keyslot (`FIDO2LUKS_DEVICE_SLOT`) can be obtained from the output of

```shell
cryptsetup luksDump <block_device>
```

6. Add fido2luks hook to /etc/mkinitcpio.conf

Before or instead of `encrypt` hook, for example:

```shell
HOOKS=(base udev autodetect modconf keyboard block fido2luks filesystems fsck)
```

7. Recreate initial ramdisk

```shell
mkinitcpio -p <preset>
```
