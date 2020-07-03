## Initramfs-tools based systems(Ubuntu and derivatives)

After installation generate your credentials and add keys to your disk as described in the top-level README
then add `initramfs,keyscript=fido2luks` to your `/etc/crypttab`

Example:
```
sda6_crypt UUID=9793d81a-4cfb-4712-85f3-c7a8d715112c none luks,discard,initramfs,keyscript=fido2luks
```

But don't forget to run `make install` which will install all necessary scripts and regenerate your intrid.

[Recording showing part of the setup](https://shimun.net/fido2luks/setup.svg)