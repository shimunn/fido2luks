#!/bin/sh

LUKS_UUIDS="$(getargs rd.fido2luks.uuid | tr ' ' '\n'| cut -d '-' -f 2-)"
CREDENTIAL_ID="$(getargs rd.fido2luks.credentialid)"
SALT="$(getargs rd.fido2luks.salt)"

MESSAGE_TIMEOUT=5

display_msg_timeout () {
	local MSG="$1"
	(plymouth display-message --text="$MSG";sleep $MESSAGE_TIMEOUT;plymouth hide-message --text="$MSG") &
}

display_msg () {
	local MSG="$1"
	plymouth display-message --text="$MSG" &
}

hide_msg () {
	local MSG="$1"
	plymouth hide-message --text="$MSG" &
}

handle_authenticator () {

        while ! /bin/f2l connected; do
              display_msg_timeout "Please connect your authenicator"
              sleep 1
        done

        export FIDO2LUKS_CREDENTIAL_ID="$CREDENTIAL_ID"
        export FIDO2LUKS_SALT="${SALT:-Ask}"
        export FIDO2LUKS_PASSWORD_HELPER="/usr/bin/systemd-ask-password --no-tty 'Disk 2fa password'"
        for UUID in $LUKS_UUIDS ; do
          export FIDO2LUKS_UUID="$UUID"
          export FIDO2LUKS_MAPPER_NAME="${MAPPER_NAME:-luks-$FIDO2LUKS_UUID}"
          display_msg_timeout "Watch your authenicator"
          ERR="$(/bin/f2l open -e 2>&1)"
          if [ "$?" -eq 1 ]; then
            display_msg_timeout "Failed to unlock: $ERR"
            sleep 15
          fi
        done
        
}
