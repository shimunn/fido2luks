#!/bin/bash
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh

check() {
	return 0
}

depends() {
    echo crypt
}

install() {

    #inst_hook pre-trigger 91 "$moddir/ykluks.sh"
    #inst_hook initqueue 01 "$moddir/fido2luks.sh"
    #inst_hook pre-mount 1 "$moddir/fix_crypttab.sh"
    #inst_hook pre-trigger 10 "$moddir/ykluks.sh"
    #inst_hook cmdline 5 "$moddir/ykluks.sh"

    #inst_simple "/bin/bash" "/bin/bash"
    inst tr
    inst cut
    inst true
    inst find
    inst blkid
    inst lsusb
    inst cryptsetup
    # inst fido2luks
    # Stolen from qubes-pciback module.
    inst lspci
    inst grep
    inst awk
    #inst_simple "/usr/bin/tr" "/bin/tr"
    #inst_simple "/usr/bin/cut" "/bin/cut"
    #inst_simple "/usr/bin/true" "/bin/true"
    #inst_simple "/usr/sbin/blkid" "/bin/blkid"
    #inst_simple "/usr/bin/ykchalresp" "/bin/ykchalresp"
    inst_simple "/usr/bin/xxd" "/usr/bin/xxd"
    inst_simple "$moddir/fido2luks" "/usr/bin/fido2luks"
    inst_simple "$moddir/dracut-crypt-fido2-lib.sh" "/lib/dracut-crypt-fido2-lib.sh"
    #inst_rules "$moddir/20-ykfde.rules"
    inst_rules "/usr/lib/udev/rules.d/60-u2f-hidraw.rules"
    #inst_simple "$moddir/ykluks.sh" "/bin/ykluks.sh"
    #inst_hook cmdline 30 "$moddir/parse-mod.sh"
    #inst_simple "$moddir/ykfde.sh" /sbin/ykfde.sh
    #inst_simple /usr/lib/udev/ykfde
    #inst_simple /etc/ykfde.conf
    #inst_dir /etc/ykfde.d/*

    inst_multiple -o \
        $systemdsystemunitdir/systemd-ask-password-console.path \
        $systemdsystemunitdir/systemd-ask-password-console.service \
        systemd-ask-password systemd-tty-ask-password-agent

    #dracut_need_initqueue
}

installkernel() {
    # Stolen from qubes-pciback module.
    local mod=
    for mod in pciback xen-pciback; do
        if modinfo -k "${kernel}" "${mod}" >/dev/null 2>&1; then
            hostonly='' instmods "${mod}"
        fi
    done
}
