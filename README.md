# fido2luks

This will allow you to unlock your luks encrypted disk with an fido2 compatable key

Note: This has only been tested under Fedora 30 using a Solo Key

## Setup

### Prerequisites

```
dnf install cargo cryptsetup-devel -y
```

### Device

```
git clone https://github.com/shimunn/fido2luks.git && cd fido2luks

#Alternativly cargo build --release && sudo cp target/release/fido2luks /usr/bin/
CARGO_INSTALL_ROOT=/usr sudo -E cargo install -f --path .

echo FIDO2LUKS_CREDENTIAL_ID=$(fido2luks credential) >> fido2luks.conf

set -a
. fido2luks.conf

#Repeat for each luks volume
sudo -E fido2luks -i addkey /dev/disk/by-uuid/<DISK_UUID>

#Test(only works if the luks container isn't active)
sudo -E fido2luks -i open /dev/disk/by-uuid/<DISK_UUID> luks-<DISK_UUID>

```

### Dracut

```
cd dracut

sudo make install
```

### Grub

Add `rd.luks.2fa=<CREDENTIAL_ID>:<DISK_UUID>` to `GRUB_CMDLINE_LINUX`

Note: This is only required for your root disk, systemd will try to unlock all other luks partions using the same key if you added it using `fido2luks addkey`

```
grub2-mkconfig > /boot/grub2/grub.cfg
```

## Test

Just reboot and see if it works, if thats the case you should remove your old less secure password from your luks header:

```
#Recommend in case you lose your authenticator, store this backupfile somewhere safe
cryptsetup luksHeaderBackup /dev/disk/by-uuid/<DISK_UUID> --header-backup-file luks_backup_<DISK_UUID>
#There is no turning back if you mess this up, make sure you made a backup
fido2luks -i add-key --exclusive /dev/disk/by-uuid/<DISK_UUID>
```
