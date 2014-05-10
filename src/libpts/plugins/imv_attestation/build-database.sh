#!/bin/sh

p="Ubuntu 14.04 x86_64"
a="x86_64-linux-gnu"
k="3.13.0-24-generic"

for hash in sha1 sha256
do
  ipsec attest --add --product "$p" --$hash --dir  /sbin
  ipsec attest --add --product "$p" --$hash --dir  /usr/sbin
  ipsec attest --add --product "$p" --$hash --dir  /bin
  ipsec attest --add --product "$p" --$hash --dir  /usr/bin

  ipsec attest --add --product "$p" --$hash --dir  /etc/network/if-pre-up.d
  ipsec attest --add --product "$p" --$hash --dir  /etc/network/if-up.d
  ipsec attest --add --product "$p" --$hash --dir  /etc/rcS.d
  ipsec attest --add --product "$p" --$hash --dir  /etc/rc2.d
  ipsec attest --add --product "$p" --$hash --dir  /etc/resolvconf/update.d
  ipsec attest --add --product "$p" --$hash --file /etc/resolvconf/update-libc.d/avahi-daemon
  ipsec attest --add --product "$p" --$hash --dir  /etc/update-motd.d

  ipsec attest --add --product "$p" --$hash --dir  /lib
  ipsec attest --add --product "$p" --$hash --dir  /lib/ebtables
  ipsec attest --add --product "$p" --$hash --file /lib/resolvconf/list-records
  ipsec attest --add --product "$p" --$hash --dir  /lib/ufw
  ipsec attest --add --product "$p" --$hash --dir  /lib/udev
  ipsec attest --add --product "$p" --$hash --dir  /lib/systemd
  ipsec attest --add --product "$p" --$hash --dir  /lib/xtables
  ipsec attest --add --product "$p" --$hash --dir  /lib/$a
  ipsec attest --add --product "$p" --$hash --dir  /lib/$a/plymouth
  ipsec attest --add --product "$p" --$hash --dir  /lib/$a/plymouth/renderers
  ipsec attest --add --product "$p" --$hash --dir  /lib/$a/security

  ipsec attest --add --product "$p" --$hash --file /lib64/ld-linux-x86-64.so.2

  ipsec attest --add --product "$p" --$hash --dir  /usr/lib
  ipsec attest --add --product "$p" --$hash --file /usr/lib/avahi/avahi-daemon-check-dns.sh
  ipsec attest --add --product "$p" --$hash --dir  /usr/lib/compiz
  ipsec attest --add --product "$p" --$hash --dir  /usr/lib/gvfs
  ipsec attest --add --product "$p" --$hash --dir  /usr/lib/libvirt/connection-driver
  ipsec attest --add --product "$p" --$hash --dir  /usr/lib/nautilus/extensions-3.0
  ipsec attest --add --product "$p" --$hash --dir  /usr/lib/NetworkManager
  ipsec attest --add --product "$p" --$hash --dir  /usr/lib/pm-utils/power.d/
  ipsec attest --add --product "$p" --$hash --dir  /usr/lib/pulse-4.0/modules
  ipsec attest --add --product "$p" --$hash --dir  /usr/lib/rsyslog
  ipsec attest --add --product "$p" --$hash --dir  /usr/lib/ubuntu-release-upgrader
  ipsec attest --add --product "$p" --$hash --dir  /usr/lib/unity-settings-daemon-1.0
  ipsec attest --add --product "$p" --$hash --dir  /usr/lib/update-notifier
  ipsec attest --add --product "$p" --$hash --dir  /usr/lib/xorg/modules
  ipsec attest --add --product "$p" --$hash --dir  /usr/lib/xorg/modules/drivers
  ipsec attest --add --product "$p" --$hash --dir  /usr/lib/xorg/modules/extensions
  ipsec attest --add --product "$p" --$hash --dir  /usr/lib/xorg/modules/input

  ipsec attest --add --product "$p" --$hash --dir  /usr/lib/$a
  ipsec attest --add --product "$p" --$hash --dir  /usr/lib/$a/alsa-lib
  ipsec attest --add --product "$p" --$hash --dir  /usr/lib/$a/colord-plugins
  ipsec attest --add --product "$p" --$hash --dir  /usr/lib/$a/gconv/
  ipsec attest --add --product "$p" --$hash --file /usr/lib/$a/libgedit-private.so
  ipsec attest --add --product "$p" --$hash --dir  /usr/lib/$a/gedit/plugins
  ipsec attest --add --product "$p" --$hash --dir  /usr/lib/$a/gio/modules
  ipsec attest --add --product "$p" --$hash --dir  /usr/lib/$a/ModemManager
  ipsec attest --add --product "$p" --$hash --dir  /usr/lib/$a/NetworkManager
  ipsec attest --add --product "$p" --$hash --dir  /usr/lib/$a/nss
  ipsec attest --add --product "$p" --$hash --dir  /usr/lib/$a/pkcs11
  ipsec attest --add --product "$p" --$hash --dir  /usr/lib/$a/pulseaudio
  ipsec attest --add --product "$p" --$hash --dir  /usr/lib/$a/samba
  ipsec attest --add --product "$p" --$hash --dir  /usr/lib/$a/sasl2

  ipsec attest --add --product "$p" --$hash --file /init \
                     --measdir /usr/share/initramfs-tools

  ipsec attest --add --product "$p" --$hash --file /scripts/functions \
                     --measdir /usr/share/initramfs-tools/scripts

  for file in `find /usr/lib/evolution-data-server -name *.so`
  do
    ipsec attest --add --product "$p" --$hash --file $file
  done

  for file in /usr/lib/firefox/*.so
  do
    ipsec attest --add --product "$p" --$hash --file $file
  done

  for file in /usr/lib/thunderbird/*.so
  do
    ipsec attest --add --product "$p" --$hash --file $file
  done

  for file in `find /lib/modules/$k -name *.ko`
  do
    ipsec attest --add --product "$p" --$hash --file $file
  done
done

