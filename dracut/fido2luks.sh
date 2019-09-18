#!/bin/sh

LUKS_DEVICES="$(getargs rd.fido2luks.devices | tr ' ' '\n')"
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

handle_authenticator() {

        while ! /bin/f2l connected; do
              display_msg_timeout "Please connect your authenicator"
              sleep 1
        done

        export FIDO2LUKS_CREDENTIAL_ID="$CREDENTIAL_ID"
        export FIDO2LUKS_SALT="${SALT:-Ask}"
        export FIDO2LUKS_PASSWORD_HELPER="/usr/bin/systemd-ask-password --no-tty 'Disk 2fa password'"
        for DEV in $LUKS_DEVICES ; do
          export FIDO2LUKS_DEVICE="$DEV"
          export FIDO2LUKS_MAPPER_NAME="${MAPPER_NAME:-luks-$DEV}"
          TRIES="0"
          while true; do
                  ERR="$(/bin/f2l open -e 2>&1)"
                  if [ "$?" -eq 1 ]; then
                    display_msg_timeout "Failed to unlock: $ERR"
                    TRIES="$[$TRIES+1]"
                    if [ "$TRIES" -gt 5 ]; then
                        exit 1
                    fi
                    sleep 5
                  else
                    exit 0
                  fi
          done
        done
        
}

if [ ! -z "$LUKS_DEVICES" ]; then
        handle_authenticator
fi
