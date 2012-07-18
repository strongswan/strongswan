#!/bin/sh
ipsec attest --add --product "$1" --sha1-ima --dir  /sbin 
ipsec attest --add --product "$1" --sha1-ima --dir  /usr/sbin
ipsec attest --add --product "$1" --sha1-ima --dir  /bin
ipsec attest --add --product "$1" --sha1-ima --dir  /usr/bin
ipsec attest --add --product "$1" --sha1-ima --dir  /etc/acpi
ipsec attest --add --product "$1" --sha1-ima --file /etc/init.d/rc
ipsec attest --add --product "$1" --sha1-ima --file /etc/init.d/rcS
ipsec attest --add --product "$1" --sha1-ima --dir  /etc/network/if-pre-up.d
ipsec attest --add --product "$1" --sha1-ima --dir  /etc/network/if-up.d
ipsec attest --add --product "$1" --sha1-ima --file /etc/NetworkManager/dispatcher.d/01ifupdown
ipsec attest --add --product "$1" --sha1-ima --dir  /etc/ppp/ip-down.d
ipsec attest --add --product "$1" --sha1-ima --dir  /etc/rc2.d
ipsec attest --add --product "$1" --sha1-ima --dir  /etc/rcS.d
ipsec attest --add --product "$1" --sha1-ima --file /etc/rc.local
ipsec attest --add --product "$1" --sha1-ima --dir  /etc/resolvconf/update.d
ipsec attest --add --product "$1" --sha1-ima --file /etc/resolvconf/update-libc.d/avahi-daemon
ipsec attest --add --product "$1" --sha1-ima --dir  /etc/update-motd.d
ipsec attest --add --product "$1" --sha1-ima --file /lib/crda/setregdomain
ipsec attest --add --product "$1" --sha1-ima --file /lib/init/apparmor-profile-load
ipsec attest --add --product "$1" --sha1-ima --file /lib/resolvconf/list-records
ipsec attest --add --product "$1" --sha1-ima --dir  /lib/udev
ipsec attest --add --product "$1" --sha1-ima --file /lib/ufw/ufw-init
ipsec attest --add --product "$1" --sha1-ima --file /usr/lib/accountsservice/accounts-daemon
ipsec attest --add --product "$1" --sha1-ima --dir  /usr/lib/at-spi2-core
ipsec attest --add --product "$1" --sha1-ima --file /usr/lib/avahi/avahi-daemon-check-dns.sh
ipsec attest --add --product "$1" --sha1-ima --dir  /usr/lib/ConsoleKit
ipsec attest --add --product "$1" --sha1-ima --dir  /usr/lib/ConsoleKit/run-seat.d
ipsec attest --add --product "$1" --sha1-ima --dir  /usr/lib/ConsoleKit/run-session.d
ipsec attest --add --product "$1" --sha1-ima --dir  /usr/lib/cups/notifier
ipsec attest --add --product "$1" --sha1-ima --file /usr/lib/dconf/dconf-service
ipsec attest --add --product "$1" --sha1-ima --file /usr/lib/dbus-1.0/dbus-daemon-launch-helper
ipsec attest --add --product "$1" --sha1-ima --dir  /usr/lib/gvfs
ipsec attest --add --product "$1" --sha1-ima --file /usr/lib/gvfs//gvfs-fuse-daemon
ipsec attest --add --product "$1" --sha1-ima --file /usr/lib/gnome-settings-daemon/gnome-settings-daemon
ipsec attest --add --product "$1" --sha1-ima --file /usr/lib/i386-linux-gnu/colord/colord
ipsec attest --add --product "$1" --sha1-ima --dir  /usr/lib/lightdm
ipsec attest --add --product "$1" --sha1-ima --file /usr/lib/NetworkManager/nm-dhcp-client.action
ipsec attest --add --product "$1" --sha1-ima --file /usr/lib/NetworkManager/nm-dispatcher.action
ipsec attest --add --product "$1" --sha1-ima --dir  /usr/lib/pm-utils/power.d
ipsec attest --add --product "$1" --sha1-ima --file /usr/lib/policykit-1/polkitd
ipsec attest --add --product "$1" --sha1-ima --file /usr/lib/update-manager/release-upgrade-motd
ipsec attest --add --product "$1" --sha1-ima --dir  /usr/lib/update-notifier
ipsec attest --add --product "$1" --sha1-ima --dir  /usr/share/language-tools
ipsec attest --add --product "$1" --sha1-ima --file /usr/share/virtualbox/VBoxCreateUSBNode.sh
ipsec attest --add --product "$1" --sha1-ima --relative --dir  /lib
ipsec attest --add --product "$1" --sha1-ima --relative --dir  /lib/i386-linux-gnu
ipsec attest --add --product "$1" --sha1-ima --relative --dir  /lib/i386-linux-gnu/security
ipsec attest --add --product "$1" --sha1-ima --relative --file /lib/plymouth/details.so
ipsec attest --add --product "$1" --sha1-ima --relative --dir  /lib/plymouth/renderers
ipsec attest --add --product "$1" --sha1-ima --relative --dir  /lib/security
ipsec attest --add --product "$1" --sha1-ima --relative --dir  /usr/lib
ipsec attest --add --product "$1" --sha1-ima --relative --dir  /usr/lib/apache2/modules
ipsec attest --add --product "$1" --sha1-ima --relative --dir  /usr/lib/gtk-3.0/3.0.0/theming-engines/
ipsec attest --add --product "$1" --sha1-ima --relative --dir  /usr/lib/i386-linux-gnu
ipsec attest --add --product "$1" --sha1-ima --relative --dir  /usr/lib/i386-linux-gnu/alsa-lib
ipsec attest --add --product "$1" --sha1-ima --relative --dir  /usr/lib/i386-linux-gnu/dri
ipsec attest --add --product "$1" --sha1-ima --relative --dir  /usr/lib/i386-linux-gnu/gdk-pixbuf-2.0/2.10.0/loaders
ipsec attest --add --product "$1" --sha1-ima --relative --dir  /usr/lib/i386-linux-gnu/gio/modules
ipsec attest --add --product "$1" --sha1-ima --relative --dir  /usr/lib/i386-linux-gnu/gtk-2.0/modules/
ipsec attest --add --product "$1" --sha1-ima --relative --dir  /usr/lib/i386-linux-gnu/gtk-3.0/modules/
ipsec attest --add --product "$1" --sha1-ima --relative --dir  /usr/lib/i386-linux-gnu/gvfs
ipsec attest --add --product "$1" --sha1-ima --relative --dir  /usr/lib/i386-linux-gnu/mit-krb5
ipsec attest --add --product "$1" --sha1-ima --relative --dir  /usr/lib/i386-linux-gnu/openssl-1.0.0/engines
ipsec attest --add --product "$1" --sha1-ima --relative --dir  /usr/lib/i386-linux-gnu/pkcs11
ipsec attest --add --product "$1" --sha1-ima --relative --dir  /usr/lib/i386-linux-gnu/polkit-1/extensions
ipsec attest --add --product "$1" --sha1-ima --relative --dir  /usr/lib/i386-linux-gnu/nss
ipsec attest --add --product "$1" --sha1-ima --relative --dir  /usr/lib/i386-linux-gnu/sane
ipsec attest --add --product "$1" --sha1-ima --relative --dir  /usr/lib/ModemManager
ipsec attest --add --product "$1" --sha1-ima --relative --file /usr/lib/NetworkManager/libnm-settings-plugin-ifupdown.so
ipsec attest --add --product "$1" --sha1-ima --relative --dir  /usr/lib/rsyslog
ipsec attest --add --product "$1" --sha1-ima --relative --dir  /usr/lib/sane
ipsec attest --add --product "$1" --sha1-ima --relative --dir  /usr/lib/xorg/modules
ipsec attest --add --product "$1" --sha1-ima --relative --dir  /usr/lib/xorg/modules/drivers
ipsec attest --add --product "$1" --sha1-ima --relative --dir  /usr/lib/xorg/modules/extensions
ipsec attest --add --product "$1" --sha1-ima --relative --dir  /usr/lib/xorg/modules/input

