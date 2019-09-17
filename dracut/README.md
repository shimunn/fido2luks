# ykluks
Dracut module to use yubikey in challenge/response mode to unlock LUKS partition.

This module is written to work with Qubes OS 3.2. It may work with other dracut
based distributions but there are other more complete tools you may want to try
(e.g. https://github.com/bpereto/ykfde).

For ubuntu based distributions you may want to try this one: https://github.com/cornelinux/yubikey-luks


WARNING
-------

Please note that the current version is tested with a LVM-on-LUKS setup only. The default Qubes OS installation
is a LUKS-on-LVM setup which will not work yet. Patches for LUKS-on-LVM are welcome as well as experienced testers
because a dont have a LUKS-on-LVM installation to test with.


Initialize Yubikey
------------------

Install yubikey tools.

	qubes-dom0-update ykpers

Initialize the Yubikey for challenge/response in slot 2.

	ykpersonalize -2 -ochal-resp -ochal-hmac -ohmac-lt64 -oserial-api-visible


Add luks slot
-------------

You need to manually add a new luks slot with the response you get when sending your
password to the yubikey.

Get response from yubikey.

	ykchalresp -2 mypassword

You may want to check which LUKS key slots are currently used. Make sure you use the correct device file.
This may help if you want to replace your current password with a more secure backup password later.

	sudo cryptsetup LuksDump /dev/sdXX

Use the output from the previous command as new passphrase.

	sudo cryptsetup luksAddKey --key-slot a_free_key_slot /dev/sdXX


Install ykluks
--------------

To get the ykluks archive to dom0 you can run the following command where downloadvm is the VM you want to use for downloading ykluks.

	qvm-run --pass-io downloadvm "wget -O - https://github.com/the2nd/ykluks/archive/master.zip" > ykluks.zip

Unzip it.

	unzip ykluks.zip
	rm ykluks.zip


Run the installer script. This will copy all files to the right place.

	cd ykluks-master
	sudo ./install.sh


Prepare system for ykluks enabled initramfs
-------------------------------------------

Now we need to do some modifications for ykluks to work.

You may want to make a backup of your current initramfs. You can use the old initramfs in case something went wrong (see "something went wrong" below).

	sudo cp -av /boot/initramfs-4.8.12-12.pvops.qubes.x86_64.img /boot/initramfs-4.8.12-12.pvops.qubes.x86_64.img.org

1. Comment out all lines in crypttab.
2. Change the line with "rd.luks.uuid=..." in /etc/default/grub to "rd.ykluks.uuid=..."
3. Change the line with "rd.qubes.hide_all_usb" in /etc/default/grub to "rd.ykluks.hide_all_usb"


Now we have to recreate the grub config and the initramfs.

	sudo grub2-mkconfig > /boot/grub2/grub.cfg
	sudo dracut -f

That's it. After a reboot you should be able to unlock your LUKS partition with your password and your yubikey.


Remove normal password and add secure backup password
-----------------------------------------------------
If everyting works as expected you may want to replace your (probably) insecure LUKS password with a secure backup password.

Add the new backup password.

	sudo cryptsetup luksAddKey --key-slot a_free_key_slot /dev/sdXX
	sudo cryptsetup luksKillslot --key-slot your_old_key_slot /dev/sdXX


Something went wrong :(
-----------------------

In case you run into any trouble after ykluks installation you can use the backup initramfs you (hopefully) created before generating a new one.

1. Select the Qubes OS boot entry in the grub boot menu.
2. Press "e" to get into edit mode.
3. First we need to change the "rd.ykluks.uuid=..." parameter back to "rd.luks.uuid=...". This is normally in the line that starts with "module /vmlinuz-...".
4. Then we need to get the line that loads the initramfs. This line normally starts with "module --nounzip /initramfs-..". Just append .org to this line.
5. Press "CTRL+X" to boot this configuration.

