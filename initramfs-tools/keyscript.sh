#!/bin/sh
set -a
. /etc/fido2luks.conf

if [ -z "$FIDO2LUKS_PASSWORD_HELPER" ]; then
	export FIDO2LUKS_PASSWORD_HELPER="plymouth ask-for-password --promt 'FIDO2 password salt for $CRYPTTAB_NAME'"
fi

fido2luks print-secret --bin
