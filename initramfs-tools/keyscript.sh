#!/bin/sh
set -a
. /etc/fido2luks.conf

if [ -z "$FIDO2LUKS_PASSWORD_HELPER" ]; then
	MSG="FIDO2 password salt for $CRYPTTAB_NAME"
	export FIDO2LUKS_PASSWORD_HELPER="plymouth ask-for-password --prompt '$MSG'"
fi

if [ "$FIDO2LUKS_USE_TOKEN" -eq 1 ]; then
	export FIDO2LUKS_CREDENTIAL_ID="$FIDO2LUKS_CREDENTIAL_ID,$(fido2luks token list --csv $CRYPTTAB_SOURCE)"
fi

fido2luks print-secret --bin
