#!/bin/sh

p="Ubuntu 12.04 i686"

ipsec attest --add --product "$p" --sha1-ima --dir  /sbin 
ipsec attest --add --product "$p" --sha1-ima --dir  /usr/sbin
ipsec attest --add --product "$p" --sha1-ima --dir  /bin
ipsec attest --add --product "$p" --sha1-ima --dir  /usr/bin
ipsec attest --add --product "$p" --sha1-ima --dir  /etc/acpi
ipsec attest --add --product "$p" --sha1-ima --file /etc/init.d/rc
ipsec attest --add --product "$p" --sha1-ima --file /etc/init.d/rcS
ipsec attest --add --product "$p" --sha1-ima --dir  /etc/network/if-post-down.d
ipsec attest --add --product "$p" --sha1-ima --dir  /etc/network/if-pre-up.d
ipsec attest --add --product "$p" --sha1-ima --dir  /etc/network/if-up.d
ipsec attest --add --product "$p" --sha1-ima --file /etc/NetworkManager/dispatcher.d/01ifupdown
ipsec attest --add --product "$p" --sha1-ima --dir  /etc/ppp/ip-down.d
ipsec attest --add --product "$p" --sha1-ima --dir  /etc/rc2.d
ipsec attest --add --product "$p" --sha1-ima --dir  /etc/rcS.d
ipsec attest --add --product "$p" --sha1-ima --file /etc/rc.local
ipsec attest --add --product "$p" --sha1-ima --dir  /etc/resolvconf/update.d
ipsec attest --add --product "$p" --sha1-ima --file /etc/resolvconf/update-libc.d/avahi-daemon
ipsec attest --add --product "$p" --sha1-ima --dir  /etc/update-motd.d
ipsec attest --add --product "$p" --sha1-ima --file /lib/crda/setregdomain
ipsec attest --add --product "$p" --sha1-ima --file /lib/init/apparmor-profile-load
ipsec attest --add --product "$p" --sha1-ima --file /lib/resolvconf/list-records
ipsec attest --add --product "$p" --sha1-ima --dir  /lib/udev
ipsec attest --add --product "$p" --sha1-ima --file /lib/ufw/ufw-init
ipsec attest --add --product "$p" --sha1-ima --file /opt/Adobe/Reader9/Reader/intellinux/bin/acroread
ipsec attest --add --product "$p" --sha1-ima --file /usr/lib/accountsservice/accounts-daemon
ipsec attest --add --product "$p" --sha1-ima --dir  /usr/lib/apt/methods
ipsec attest --add --product "$p" --sha1-ima --dir  /usr/lib/at-spi2-core
ipsec attest --add --product "$p" --sha1-ima --file /usr/lib/avahi/avahi-daemon-check-dns.sh
ipsec attest --add --product "$p" --sha1-ima --file /usr/lib/bamf/bamfdaemon
ipsec attest --add --product "$p" --sha1-ima --dir  /usr/lib/ConsoleKit
ipsec attest --add --product "$p" --sha1-ima --dir  /usr/lib/ConsoleKit/run-seat.d
ipsec attest --add --product "$p" --sha1-ima --dir  /usr/lib/ConsoleKit/run-session.d
ipsec attest --add --product "$p" --sha1-ima --dir  /usr/lib/cups/notifier
ipsec attest --add --product "$p" --sha1-ima --file /usr/lib/dconf/dconf-service
ipsec attest --add --product "$p" --sha1-ima --file /usr/lib/dbus-1.0/dbus-daemon-launch-helper
ipsec attest --add --product "$p" --sha1-ima --file /usr/lib/deja-dup/deja-dup/deja-dup-monitor
ipsec attest --add --product "$p" --sha1-ima --file /usr/lib/evolution/3.2/evolution-alarm-notify
ipsec attest --add --product "$p" --sha1-ima --file /usr/lib/firefox/firefox
ipsec attest --add --product "$p" --sha1-ima --file /usr/lib/firefox/plugin-container
ipsec attest --add --product "$p" --sha1-ima --file /usr/lib/gcc/i686-linux-gnu/4.6/cc1
ipsec attest --add --product "$p" --sha1-ima --file /usr/lib/gcc/i686-linux-gnu/4.6/collect2
ipsec attest --add --product "$p" --sha1-ima --file /usr/lib/geoclue/geoclue-master
ipsec attest --add --product "$p" --sha1-ima --dir  /usr/lib/git-core
ipsec attest --add --product "$p" --sha1-ima --file /usr/lib/gnome-desktop3/check_gl_texture_size
ipsec attest --add --product "$p" --sha1-ima --file /usr/lib/gnome-disk-utility/gdu-notification-daemon
ipsec attest --add --product "$p" --sha1-ima --file /usr/lib/gnome-online-accounts/goa-daemon
ipsec attest --add --product "$p" --sha1-ima --dir  /usr/lib/gnome-settings-daemon
ipsec attest --add --product "$p" --sha1-ima --file /usr/lib/gnome-user-share/gnome-user-share
ipsec attest --add --product "$p" --sha1-ima --file /usr/lib/gnome-screensaver/gnome-screensaver-dialog
ipsec attest --add --product "$p" --sha1-ima --dir  /usr/lib/gvfs
ipsec attest --add --product "$p" --sha1-ima --file /usr/lib/gvfs//gvfs-fuse-daemon
ipsec attest --add --product "$p" --sha1-ima --file /usr/lib/i386-linux-gnu/colord/colord
ipsec attest --add --product "$p" --sha1-ima --dir  /usr/lib/i386-linux-gnu/gconf
ipsec attest --add --product "$p" --sha1-ima --file /usr/lib/indicator-application/indicator-application-service
ipsec attest --add --product "$p" --sha1-ima --file /usr/lib/indicator-appmenu/hud-service
ipsec attest --add --product "$p" --sha1-ima --file /usr/lib/indicator-datetime/indicator-datetime-service
ipsec attest --add --product "$p" --sha1-ima --file /usr/lib/indicator-messages/indicator-messages-service
ipsec attest --add --product "$p" --sha1-ima --file /usr/lib/indicator-printers/indicator-printers-service
ipsec attest --add --product "$p" --sha1-ima --file /usr/lib/indicator-session/indicator-session-service
ipsec attest --add --product "$p" --sha1-ima --file /usr/lib/indicator-sound/indicator-sound-service
ipsec attest --add --product "$p" --sha1-ima --dir  /usr/lib/lightdm
ipsec attest --add --product "$p" --sha1-ima --file /usr/lib/NetworkManager/nm-dhcp-client.action
ipsec attest --add --product "$p" --sha1-ima --file /usr/lib/NetworkManager/nm-dispatcher.action
ipsec attest --add --product "$p" --sha1-ima --file /usr/lib/notify-osd/notify-osd
ipsec attest --add --product "$p" --sha1-ima --file /usr/lib/nux/unity_support_test
ipsec attest --add --product "$p" --sha1-ima --dir  /usr/lib/pm-utils/power.d
ipsec attest --add --product "$p" --sha1-ima --dir  /usr/lib/pm-utils/sleep.d
ipsec attest --add --product "$p" --sha1-ima --file /usr/lib/policykit-1/polkitd
ipsec attest --add --product "$p" --sha1-ima --file /usr/lib/policykit-1-gnome/polkit-gnome-authentication-agent-1
ipsec attest --add --product "$p" --sha1-ima --file /usr/lib/pulseaudio/pulse/gconf-helper
ipsec attest --add --product "$p" --sha1-ima --file /usr/lib/rtkit/rtkit-daemon
ipsec attest --add --product "$p" --sha1-ima --file /usr/lib/system-service/system-service-d
ipsec attest --add --product "$p" --sha1-ima --file /usr/lib/telepathy/mission-control-5
ipsec attest --add --product "$p" --sha1-ima --file /usr/lib/thunderbird/thunderbird
ipsec attest --add --product "$p" --sha1-ima --dir  /usr/lib/ubuntuone-client
ipsec attest --add --product "$p" --sha1-ima --file /usr/lib/ubuntu-geoip/ubuntu-geoip-provider
ipsec attest --add --product "$p" --sha1-ima --dir  /usr/lib/ubuntu-sso-client
ipsec attest --add --product "$p" --sha1-ima --dir  /usr/lib/udisks
ipsec attest --add --product "$p" --sha1-ima --file /usr/lib/unity/unity-panel-service
ipsec attest --add --product "$p" --sha1-ima --file /usr/lib/unity-lens-applications/unity-applications-daemon
ipsec attest --add --product "$p" --sha1-ima --file /usr/lib/unity-lens-files/unity-files-daemon
ipsec attest --add --product "$p" --sha1-ima --dir /usr/lib/unity-lens-music
ipsec attest --add --product "$p" --sha1-ima --file /usr/lib/unity-lens-video/unity-lens-video
ipsec attest --add --product "$p" --sha1-ima --file /usr/lib/unity-scope-video-remote/unity-scope-video-remote
ipsec attest --add --product "$p" --sha1-ima --file /usr/lib/update-manager/release-upgrade-motd
ipsec attest --add --product "$p" --sha1-ima --dir  /usr/lib/update-notifier
ipsec attest --add --product "$p" --sha1-ima --file /usr/lib/upower/upowerd
ipsec attest --add --product "$p" --sha1-ima --file /usr/lib/libvte-2.90-9/gnome-pty-helper
ipsec attest --add --product "$p" --sha1-ima --file /usr/lib/zeitgeist/zeitgeist-fts
ipsec attest --add --product "$p" --sha1-ima --file /usr/share/apport/apport
ipsec attest --add --product "$p" --sha1-ima --file /usr/share/apport/apport-checkreports
ipsec attest --add --product "$p" --sha1-ima --file /usr/share/apport/apport-gtk
ipsec attest --add --product "$p" --sha1-ima --dir  /usr/share/language-tools
ipsec attest --add --product "$p" --sha1-ima --file /usr/share/virtualbox/VBoxCreateUSBNode.sh
ipsec attest --add --product "$p" --sha1-ima --relative --file /etc/ld.so.cache
ipsec attest --add --product "$p" --sha1-ima --relative --dir  /lib
ipsec attest --add --product "$p" --sha1-ima --relative --dir  /lib/i386-linux-gnu
ipsec attest --add --product "$p" --sha1-ima --relative --dir  /lib/i386-linux-gnu/security
for file in `find /lib/modules/3.2.21ima/kernel -name *.ko`
do
ipsec attest --add --product "$p" --sha1-ima --relative --file $file
done
ipsec attest --add --product "$p" --sha1-ima --relative --dir  /lib/plymouth
ipsec attest --add --product "$p" --sha1-ima --relative --dir  /lib/plymouth/renderers
ipsec attest --add --product "$p" --sha1-ima --relative --dir  /lib/security
ipsec attest --add --product "$p" --sha1-ima --relative --dir  /opt/Adobe/Reader9/Reader/intellinux/lib
ipsec attest --add --product "$p" --sha1-ima --relative --dir  /usr/lib
ipsec attest --add --product "$p" --sha1-ima --relative --dir  /usr/lib/apache2/modules
ipsec attest --add --product "$p" --sha1-ima --relative --dir  /usr/lib/compiz
ipsec attest --add --product "$p" --sha1-ima --relative --dir  /usr/lib/compizconfig/backends/
ipsec attest --add --product "$p" --sha1-ima --relative --dir  /usr/lib/enchant
ipsec attest --add --product "$p" --sha1-ima --relative --file /usr/lib/evolution/3.2/libemiscwidgets.so.0.0.0
ipsec attest --add --product "$p" --sha1-ima --relative --file /usr/lib/evolution/3.2/libeutil.so.0.0.0
ipsec attest --add --product "$p" --sha1-ima --relative --file /usr/lib/evolution/3.2/libgnomecanvas.so.0.0.0
for file in /usr/lib/firefox/*.so
do
ipsec attest --add --product "$p" --sha1-ima --relative --file $file
done
ipsec attest --add --product "$p" --sha1-ima --relative --file /usr/lib/firefox/components/libbrowsercomps.so
ipsec attest --add --product "$p" --sha1-ima --relative --file /usr/lib/firefox/components/libdbusservice.so
ipsec attest --add --product "$p" --sha1-ima --relative --file /usr/lib/firefox/components/libmozgnome.so
ipsec attest --add --product "$p" --sha1-ima --relative --file /usr/lib/firefox-addons/extensions/globalmenu@ubuntu.com/components/libglobalmenu.so
ipsec attest --add --product "$p" --sha1-ima --relative --file /usr/lib/firefox-addons/plugins/nppdf.so
ipsec attest --add --product "$p" --sha1-ima --relative --file /usr/lib/flashplugin-installer/libflashplayer.so
ipsec attest --add --product "$p" --sha1-ima --relative --dir  /usr/lib/gedit/plugins
ipsec attest --add --product "$p" --sha1-ima --relative --dir  /usr/lib/gnome-bluetooth
ipsec attest --add --product "$p" --sha1-ima --relative --dir  /usr/lib/gnome-settings-daemon-3.0
ipsec attest --add --product "$p" --sha1-ima --relative --dir  /usr/lib/gtk-2.0/2.10.0/menuproxies
ipsec attest --add --product "$p" --sha1-ima --relative --dir  /usr/lib/gtk-3.0/3.0.0/menuproxies
ipsec attest --add --product "$p" --sha1-ima --relative --dir  /usr/lib/gtk-3.0/3.0.0/theming-engines
ipsec attest --add --product "$p" --sha1-ima --relative --dir  /usr/lib/i386-linux-gnu
ipsec attest --add --product "$p" --sha1-ima --relative --dir  /usr/lib/i386-linux-gnu/alsa-lib
ipsec attest --add --product "$p" --sha1-ima --relative --dir  /usr/lib/i386-linux-gnu/dri
ipsec attest --add --product "$p" --sha1-ima --relative --dir  /usr/lib/i386-linux-gnu/gconf/2
ipsec attest --add --product "$p" --sha1-ima --relative --dir  /usr/lib/i386-linux-gnu/gconv
ipsec attest --add --product "$p" --sha1-ima --relative --dir  /usr/lib/i386-linux-gnu/gdk-pixbuf-2.0/2.10.0/loaders
ipsec attest --add --product "$p" --sha1-ima --relative --dir  /usr/lib/i386-linux-gnu/gio/modules
ipsec attest --add --product "$p" --sha1-ima --relative --dir  /usr/lib/i386-linux-gnu/gtk-2.0/modules
ipsec attest --add --product "$p" --sha1-ima --relative --dir  /usr/lib/i386-linux-gnu/gtk-2.0/2.10.0/engines
ipsec attest --add --product "$p" --sha1-ima --relative --dir  /usr/lib/i386-linux-gnu/gtk-2.0/2.10.0/immodules
ipsec attest --add --product "$p" --sha1-ima --relative --dir  /usr/lib/i386-linux-gnu/gtk-3.0/modules
ipsec attest --add --product "$p" --sha1-ima --relative --dir  /usr/lib/i386-linux-gnu/gtk-3.0/3.0.0/immodules
ipsec attest --add --product "$p" --sha1-ima --relative --dir  /usr/lib/i386-linux-gnu/gvfs
ipsec attest --add --product "$p" --sha1-ima --relative --dir  /usr/lib/i386-linux-gnu/libcanberra-0.28
ipsec attest --add --product "$p" --sha1-ima --relative --dir  /usr/lib/i386-linux-gnu/mesa
ipsec attest --add --product "$p" --sha1-ima --relative --dir  /usr/lib/i386-linux-gnu/mit-krb5
ipsec attest --add --product "$p" --sha1-ima --relative --dir  /usr/lib/i386-linux-gnu/openssl-1.0.0/engines
ipsec attest --add --product "$p" --sha1-ima --relative --dir  /usr/lib/i386-linux-gnu/pango/1.6.0/modules
ipsec attest --add --product "$p" --sha1-ima --relative --dir  /usr/lib/i386-linux-gnu/pkcs11
ipsec attest --add --product "$p" --sha1-ima --relative --dir  /usr/lib/i386-linux-gnu/polkit-1/extensions
ipsec attest --add --product "$p" --sha1-ima --relative --dir  /usr/lib/i386-linux-gnu/nss
ipsec attest --add --product "$p" --sha1-ima --relative --dir  /usr/lib/i386-linux-gnu/sane
ipsec attest --add --product "$p" --sha1-ima --relative --dir  /usr/lib/i386-linux-gnu/sse2
ipsec attest --add --product "$p" --sha1-ima --relative --dir  /usr/lib/indicators3/7
ipsec attest --add --product "$p" --sha1-ima --relative --dir  /usr/lib/indicator-messages/status-providers/1
ipsec attest --add --product "$p" --sha1-ima --relative --dir  /usr/lib/libpeas-1.0/loaders
ipsec attest --add --product "$p" --sha1-ima --relative --file /usr/lib/man-db/libman-2.6.1.so
ipsec attest --add --product "$p" --sha1-ima --relative --file /usr/lib/man-db/libmandb-2.6.1.so
ipsec attest --add --product "$p" --sha1-ima --relative --dir  /usr/lib/mission-control-plugins.0
ipsec attest --add --product "$p" --sha1-ima --relative --dir  /usr/lib/ModemManager
ipsec attest --add --product "$p" --sha1-ima --relative --dir  /usr/lib/nautilus/extensions-3.0
ipsec attest --add --product "$p" --sha1-ima --relative --file /usr/lib/NetworkManager/libnm-settings-plugin-ifupdown.so
ipsec attest --add --product "$p" --sha1-ima --relative --file /usr/lib/perl/5.14.2/auto/File/Glob/Glob.so
ipsec attest --add --product "$p" --sha1-ima --relative --dir  /usr/lib/pulse-1.1/modules
ipsec attest --add --product "$p" --sha1-ima --relative --dir  /usr/lib/python2.7/lib-dynload
ipsec attest --add --product "$p" --sha1-ima --relative --file /usr/lib/python2.7/dist-packages/apt_inst.so
ipsec attest --add --product "$p" --sha1-ima --relative --file /usr/lib/python2.7/dist-packages/apt_pkg.so
ipsec attest --add --product "$p" --sha1-ima --relative --file /usr/lib/python2.7/dist-packages/cairo/_cairo.so
ipsec attest --add --product "$p" --sha1-ima --relative --file /usr/lib/python2.7/dist-packages/dbus/mainloop/qt.so
ipsec attest --add --product "$p" --sha1-ima --relative --file /usr/lib/python2.7/dist-packages/_dbus_bindings.so
ipsec attest --add --product "$p" --sha1-ima --relative --file /usr/lib/python2.7/dist-packages/_dbus_glib_bindings.so
ipsec attest --add --product "$p" --sha1-ima --relative --file /usr/lib/python2.7/dist-packages/duplicity/_librsync.so
ipsec attest --add --product "$p" --sha1-ima --relative --file /usr/lib/python2.7/dist-packages/gi/_gi.so
ipsec attest --add --product "$p" --sha1-ima --relative --file /usr/lib/python2.7/dist-packages/gi/_gobject/_gobject.so
ipsec attest --add --product "$p" --sha1-ima --relative --file /usr/lib/python2.7/dist-packages/gi/_glib/_glib.so
ipsec attest --add --product "$p" --sha1-ima --relative --file /usr/lib/python2.7/dist-packages/glib/_glib.so
ipsec attest --add --product "$p" --sha1-ima --relative --file /usr/lib/python2.7/dist-packages/gobject/_gobject.so
ipsec attest --add --product "$p" --sha1-ima --relative --file /usr/lib/python2.7/dist-packages/gtk-2.0/atk.so
ipsec attest --add --product "$p" --sha1-ima --relative --file /usr/lib/python2.7/dist-packages/gtk-2.0/gtk/_gtk.so
ipsec attest --add --product "$p" --sha1-ima --relative --file /usr/lib/python2.7/dist-packages/gtk-2.0/gio/_gio.so
ipsec attest --add --product "$p" --sha1-ima --relative --file /usr/lib/python2.7/dist-packages/gtk-2.0/gio/unix.so
ipsec attest --add --product "$p" --sha1-ima --relative --file /usr/lib/python2.7/dist-packages/gtk-2.0/pango.so
ipsec attest --add --product "$p" --sha1-ima --relative --file /usr/lib/python2.7/dist-packages/gtk-2.0/pangocairo.so
ipsec attest --add --product "$p" --sha1-ima --relative --file /usr/lib/python2.7/dist-packages/gtk-2.0/pynotify/_pynotify.so
ipsec attest --add --product "$p" --sha1-ima --relative --file /usr/lib/python2.7/dist-packages/OpenSSL/crypto.so
ipsec attest --add --product "$p" --sha1-ima --relative --file /usr/lib/python2.7/dist-packages/OpenSSL/rand.so
ipsec attest --add --product "$p" --sha1-ima --relative --file /usr/lib/python2.7/dist-packages/OpenSSL/SSL.so
ipsec attest --add --product "$p" --sha1-ima --relative --file /usr/lib/python2.7/dist-packages/PyQt4/QtCore.so
ipsec attest --add --product "$p" --sha1-ima --relative --file /usr/lib/python2.7/dist-packages/simplejson/_speedups.so
ipsec attest --add --product "$p" --sha1-ima --relative --file /usr/lib/python2.7/dist-packages/sip.so
ipsec attest --add --product "$p" --sha1-ima --relative --file /usr/lib/python2.7/dist-packages/twisted/internet/_sigchld.so
ipsec attest --add --product "$p" --sha1-ima --relative --file /usr/lib/python2.7/dist-packages/twisted/python/_initgroups.so
ipsec attest --add --product "$p" --sha1-ima --relative --file /usr/lib/python2.7/dist-packages/xapian/_xapian.so
ipsec attest --add --product "$p" --sha1-ima --relative --file /usr/lib/python2.7/dist-packages/zope/interface/_zope_interface_coptimizations.so
ipsec attest --add --product "$p" --sha1-ima --relative --dir  /usr/lib/rsyslog
ipsec attest --add --product "$p" --sha1-ima --relative --dir  /usr/lib/sane
ipsec attest --add --product "$p" --sha1-ima --relative --dir  /usr/lib/sse2
ipsec attest --add --product "$p" --sha1-ima --relative --dir  /usr/lib/sudo
for file in /usr/lib/thunderbird/*.so
do
ipsec attest --add --product "$p" --sha1-ima --relative --file $file
done
ipsec attest --add --product "$p" --sha1-ima --relative --file /usr/lib/thunderbird/components/libdbusservice.so
ipsec attest --add --product "$p" --sha1-ima --relative --file /usr/lib/thunderbird/components/libmozgnome.so
ipsec attest --add --product "$p" --sha1-ima --relative --file /usr/lib/thunderbird-addons/extensions/globalmenu@ubuntu.com/components/libglobalmenu.so
ipsec attest --add --product "$p" --sha1-ima --relative --dir  /usr/lib/xorg/modules
ipsec attest --add --product "$p" --sha1-ima --relative --dir  /usr/lib/xorg/modules/drivers
ipsec attest --add --product "$p" --sha1-ima --relative --dir  /usr/lib/xorg/modules/extensions
ipsec attest --add --product "$p" --sha1-ima --relative --dir  /usr/lib/xorg/modules/input
ipsec attest --add --product "$p" --sha1-ima --relative --dir  /usr/share/fonts/truetype/ubuntu-font-family
ipsec attest --del --product "$p" --sha1                --file /lib/resolvconf/list-records
ipsec attest --del --product "$p" --sha1-ima            --file /lib/resolvconf/list-records
ipsec attest --del --product "$p" --sha1                --file /usr/bin/lsb_release
ipsec attest --del --product "$p" --sha1-ima            --file /usr/bin/lsb_release
ipsec attest --del --product "$p" --sha1                --file /usr/share/language-tools/language-options
ipsec attest --del --product "$p" --sha1-ima            --file /usr/share/language-tools/language-options

