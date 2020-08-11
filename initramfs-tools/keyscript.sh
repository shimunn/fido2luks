#!/bin/sh
set -a
. /etc/fido2luks.conf

if [ -z "$FIDO2LUKS_PASSWORD_HELPER" ]; then
	MSG="FIDO2 password salt for $CRYPTTAB_NAME"
	export FIDO2LUKS_PASSWORD_HELPER="plymouth ask-for-password --promt '$MSG'"
	plymouth message --text "$MSG"
fi

fido2luks print-secret --bin
