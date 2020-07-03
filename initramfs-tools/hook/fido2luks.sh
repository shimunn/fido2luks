#!/bin/sh

case "$1" in
prereqs)
	echo ""
	exit 0
	;;

esac

. /usr/share/initramfs-tools/hook-functions
copy_file config /etc/fido2luks.conf /etc/fido2luks.conf
copy_exec /usr/bin/fido2luks
exit 0
