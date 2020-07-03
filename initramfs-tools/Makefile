.PHONY: install
install:
	chmod +x hook/fido2luks.sh keyscript.sh
	cp -f hook/fido2luks.sh /etc/initramfs-tools/hooks/
	mkdir -p /usr/share/fido2luks
	cp -f keyscript.sh /lib/cryptsetup/scripts/fido2luks
	update-initramfs -u
remove:
	rm /etc/initramfs-tools/hooks/fido2luks.sh /lib/cryptsetup/scripts/fido2luks
	update-initramfs -u
