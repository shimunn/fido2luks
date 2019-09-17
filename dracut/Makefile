.PHONY: install

DRACUT_MODULE_D=/usr/lib/dracut/modules.d/95fido2luks
DRACUT_CONF_D=/etc/dracut.conf.d

build:
	cargo install --root . --path ../ --force 
	rm -f .crates.toml
install: build
	mkdir -p ${DRACUT_MODULE_D}
	cp bin/* /usr/local/bin/
	cp module-setup.sh ykluks.sh bin/* ${DRACUT_MODULE_D}/
	chown -R root: ${DRACUT_MODULE_D}/
setup: install
	bin/fido2luks setup
	cp fido2luks.json /etc/fido2luks.json
clean:
	cargo clean
	rm -rf bin fido2luks.json
uninstall:
	rm -rf /etc/fido2luks.json ${DRACUT_CONF_D}/fido2luks.conf ${DRACUT_MODULES_D}/95fido2luks

