## Initramfs-tools based systems(Ubuntu and derivatives)

For easiest installation [download and install the precompiled deb from releases.](https://github.com/shimunn/fido2luks/releases). However it is possible to build from source via the instructions on the main readme.

```
sudo -s

# Insert FIDO key.
fido2luks credential
# Tap FIDO key
# Copy returned string <CREDENTIAL>

nano /etc/fido2luks.conf
# Insert <CREDENTIAL> 
# FIDO2LUKS_CREDENTIAL_ID=<CREDENTIAL> 

set -a
. /etc/fido2luks.conf
fido2luks -i add-key /dev/<LUKS PARTITION>
# Current password: <Any current LUKS password>
# Password: <Password used as FIDO challange>
# Tap FIDO key

nano /etc/crypttab
# Append to end ",discard,initramfs,keyscript=fido2luks"
# E.g. sda6_crypt UUID=XXXXXXXXXX none luks,discard,initramfs,keyscript=fido2luks

update-initramfs -u


```

[Recording showing part of the setup](https://shimun.net/fido2luks/setup.svg)

