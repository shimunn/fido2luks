#!/bin/bash

NORMAL_DIR="/run/systemd/system"
LUKS_2FA_WANTS="/etc/systemd/system/luks-2fa.target.wants"

CRYPTSETUP="/usr/lib/systemd/systemd-cryptsetup"
FIDO2LUKS="/usr/bin/fido2luks"
MOUNT=$(command -v mount)
UMOUNT=$(command -v umount)

TIMEOUT=120
CON_MSG="Please connect your authenticator"

generate_service () {
        local credential_id=$1 target_uuid=$2 timeout=$3 sd_dir=${4:-$NORMAL_DIR}

        local sd_target_uuid=$(systemd-escape -p $target_uuid)
        local target_dev="dev-disk-by\x2duuid-${sd_target_uuid}.device"

        local crypto_target_service="systemd-cryptsetup@luks\x2d${sd_target_uuid}.service"
        local sd_service="${sd_dir}/luks-2fa@luks\x2d${sd_target_uuid}.service"
        local fido2luks_args="--bin"
        if [ ! -z "$timeout" ]; then
          fido2luks_args="$fido2luks_args --await-dev ${timeout}"
        fi
        {
                printf -- "[Unit]"
                printf -- "\nDescription=%s" "2fa for luks"
                printf -- "\nBindsTo=%s" "$target_dev"
                printf -- "\nAfter=%s cryptsetup-pre.target systemd-journald.socket" "$target_dev"
                printf -- "\nBefore=%s umount.target luks-2fa.target" "$crypto_target_service"
                printf -- "\nConflicts=umount.target"
                printf -- "\nDefaultDependencies=no"
                [ ! -z "$timeout" ] && printf -- "\nJobTimeoutSec=%s" "$timeout"
                printf -- "\n\n[Service]"
                printf -- "\nType=oneshot"
                printf -- "\nRemainAfterExit=yes"
                printf -- "\nEnvironmentFile=%s" "/etc/fido2luks.conf"
                [ ! -z "$credential_id" ] && printf -- "\nEnvironment=FIDO2LUKS_CREDENTIAL_ID='%s'" "$credential_id"
                printf -- "\nKeyringMode=%s" "shared"
		            printf -- "\nExecStartPre=-/usr/bin/plymouth display-message --text \"${CON_MSG}\""
                printf -- "\nExecStart=/bin/bash -c \"${FIDO2LUKS} print-secret $fido2luks_args | ${CRYPTSETUP} attach 'luks-%s' '/dev/disk/by-uuid/%s' '/dev/stdin'\"" "$target_uuid" "$target_uuid"
                printf -- "\nExecStop=${CRYPTSETUP} detach 'luks-%s'" "$target_uuid"
        } > "$sd_service"

        mkdir -p "${sd_dir}/${crypto_target_service}.d"
        {
                printf -- "[Unit]"
                printf -- "\nConditionPathExists=!/dev/mapper/luks-%s" "$target_uuid"
        } > "${sd_dir}/${crypto_target_service}.d/drop-in.conf"

        ln -sf "$sd_service" "${LUKS_2FA_WANTS}/"
}

parse_cmdline () {
        local CMDLINE
        IFS=':' read -ra CMDLINE <<<${1#rd.luks.2fa=}

        local __k_uuid=$2
        eval $__k_uuid=${CMDLINE[0]#UUID=}

        local __t_uuid=$3
        eval $__t_uuid=${CMDLINE[1]#UUID=}

        local __t=$4
        eval $__t=${CMDLINE[2]:-$TIMEOUT}

}

generate_from_cmdline () {
        local credential_id= target_uuid= timeout=

        for argv in $(cat /proc/cmdline); do
                case $argv in
                        rd.luks.2fa=*)
                                parse_cmdline $argv credential_id target_uuid timeout
                                generate_service $credential_id $target_uuid $timeout
                                ;;
                esac
        done
}

generate_from_cmdline
