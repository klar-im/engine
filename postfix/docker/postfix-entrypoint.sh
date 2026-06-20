#!/bin/bash
set -e

# Resolve Docker service hostnames and inject IPs into Postfix config.
# Postfix's built-in DNS resolver doesn't work well with Docker's embedded DNS.

MILTER_IP=$(getent hosts klar-milterd | awk '{print $1}')
DOVECOT_IP=$(getent hosts dovecot | awk '{print $1}')

if [ -z "$MILTER_IP" ]; then
    echo "WARNING: Could not resolve klar-milterd, milter will be unavailable"
    MILTER_IP="127.0.0.1"
fi

if [ -z "$DOVECOT_IP" ]; then
    echo "WARNING: Could not resolve dovecot, delivery will fail"
    DOVECOT_IP="127.0.0.1"
fi

echo "Resolved klar-milterd -> $MILTER_IP"
echo "Resolved dovecot -> $DOVECOT_IP"

# Substitute hostnames with IPs in Postfix config
postconf -e "smtpd_milters = inet:${MILTER_IP}:8891"
postconf -e "non_smtpd_milters = inet:${MILTER_IP}:8891"
postconf -e "virtual_transport = lmtp:inet:${DOVECOT_IP}:24"

exec postfix start-fg
