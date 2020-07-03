.PHONY: install clean

DRACUT_MODULES_D=/usr/lib/dracut/modules.d
DRACUT_CONF_D=/etc/dracut.conf.d

MODULE_CONF_D=dracut.conf.d
MODULE_CONF=luks-2fa.conf
MODULE_DIR=96luks-2fa

help:
	@echo make help to show this help
	@echo make install to install
	@echo make clean to remove

install:
	chmod +x hook/fido2luks.sh keyscript.sh
	cp -f hook/fido2luks.sh /etc/initramfs-tools/hooks/
	mkdir -p /usr/share/fido2luks
	cp -f keyscript.sh /lib/cryptsetup/scripts/fido2luks
	update-initramfs -u
remove:
	rm /etc/initramfs-tools/hooks/fido2luks.sh
	update-initramfs -u
