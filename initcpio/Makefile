.PHONY: install remove

install:
	install -Dm644 hooks/fido2luks -t /usr/lib/initcpio/hooks
	install -Dm644 install/fido2luks -t /usr/lib/initcpio/install
ifdef preset
	mkinitcpio -p $(preset)
else
	mkinitcpio -P
endif

remove:
	rm /usr/lib/initcpio/{hooks,install}/fido2luks
ifdef preset
	mkinitcpio -p $(preset)
else
	mkinitcpio -P
endif
