#!/usr/bin/sh

command -v ask_for_password >/dev/null || . /lib/dracut-crypt-lib.sh

fido2_decrypt() {
        #Unused local mntp="$1"
        local keypath="$2"
        #Unused local keydev=$3
        #Unused local device=$4
        . /etc/$keypath
        export FIDO2LUKS_CREDENTIAL_ID="${CREDENTIAL_ID:-$FIDO2LUKS_CREDENTIAL_ID}"
        export FIDO2LUKS_SALT="$(getargs rd.fido2luks.salt)"
        export FIDO2LUKS_PASSWORD_HELPER="/usr/bin/systemd-ask-password 'Disk 2fa password'"
        if [ -z "$FIDO2LUKS_SALT" ]; then
               export FIDO2LUKS_SALT="Ask"
        fi
        /bin/fido2luks print-secret | xxd -r -p -
}
