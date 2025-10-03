#! /bin/ash

(
ctl_socket=/var/run/charon.vici
while ! [ -e $ctl_socket ]; do echo "waiting for $ctl_socket"; sleep 1; done
swanctl --load-all --noprompt
) &

exec /usr/libexec/ipsec/charon "$@"
