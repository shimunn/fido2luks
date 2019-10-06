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
	cp ${MODULE_CONF_D}/${MODULE_CONF} ${DRACUT_CONF_D}/
	cp -r ${MODULE_DIR} ${DRACUT_MODULES_D}/
	cp ${MODULE_DIR}/fido2luks.conf /etc/fido2luks.conf
	dracut -fv
clean:
	rm ${DRACUT_CONF_D}/${MODULE_CONF}
	rm -r ${DRACUT_MODULES_D}/${MODULE_DIR}
	dracut -fv
