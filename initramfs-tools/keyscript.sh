#!/bin/sh
set -a
. /etc/fido2luks.conf

# Set Defaults
if [ -z "$FIDO2LUKS_USE_TOKEN" ]; then
    FIDO2LUKS_USE_TOKEN=0
fi

if [ -z "$FIDO2LUKS_PASSWORD_FALLBACK" ]; then
    FIDO2LUKS_PASSWORD_FALLBACK=1
fi



if [ -z "$FIDO2LUKS_PASSWORD_HELPER" ]; then
	MSG="FIDO2 password salt for $CRYPTTAB_NAME"
	export FIDO2LUKS_PASSWORD_HELPER="plymouth ask-for-password --prompt '$MSG'"
fi

if [ "$FIDO2LUKS_USE_TOKEN" -eq 1 ]; then
	export FIDO2LUKS_CREDENTIAL_ID="$FIDO2LUKS_CREDENTIAL_ID,$(fido2luks token list --csv $CRYPTTAB_SOURCE)"
fi

fido2luks print-secret --bin

# Fall back to passphrase-based unlock if fido2luks fails
if [ "$?" -gt 0 ] && [ "$FIDO2LUKS_PASSWORD_FALLBACK" -eq 1 ]; then
  plymouth ask-for-password --prompt "Password for $CRYPTTAB_SOURCE"
fi
