#!/bin/sh
# Post-install for the heplify deb/rpm (nfpm). Runs on fresh install and upgrade.
set -e

if ! getent group heplify >/dev/null 2>&1; then
    groupadd --system heplify
fi
if ! getent passwd heplify >/dev/null 2>&1; then
    nologin=/usr/sbin/nologin
    [ -x "$nologin" ] || nologin=/sbin/nologin
    useradd --system --gid heplify --home-dir /var/lib/heplify --no-create-home \
        --shell "$nologin" --comment "heplify HEP agent" heplify
fi

# The config may hold HEP/Prometheus passwords: readable by the service only.
if [ -f /etc/heplify/heplify.json ]; then
    chgrp heplify /etc/heplify/heplify.json
    chmod 0640 /etc/heplify/heplify.json
fi

# No-op without systemd (containers, chroots).
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
    # Restarts only if already running: a fresh install is not started with
    # the default config, edit /etc/heplify/heplify.json first.
    systemctl try-restart heplify.service || true
fi
