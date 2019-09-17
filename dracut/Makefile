.PHONY: install

DRACUT_MODULE_D=/usr/lib/dracut/modules.d/95fido2luks
DRACUT_CONF_D=/etc/dracut.conf.d

build:
	cargo install --root . --path ../ --force 
install: build
	sudo mkdir -p ${DRACUT_MODULE_D}
	sudo cp bin/* /usr/local/bin/
	sudo cp bin/* ${DRACUT_MODULE_D}/
	sudo cp module-setup.sh fido2luks.sh bin/* ${DRACUT_MODULE_D}/
	sudo chown -R root: ${DRACUT_MODULE_D}/
setup: install
	sudo bin/fido2luks setup
	sudo cp fido2luks.json /etc/fido2luks.json
clean:
	cargo clean
	rm -rf bin fido2luks.json
	rm -f .crates.toml
uninstall:
	rm -rf /etc/fido2luks.json ${DRACUT_CONF_D}/fido2luks.conf ${DRACUT_MODULES_D}/95fido2luks

