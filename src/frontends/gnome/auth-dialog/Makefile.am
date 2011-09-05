libexec_PROGRAMS = nm-strongswan-auth-dialog

nm_strongswan_auth_dialog_CPPFLAGS = \
	$(GTHREAD_CFLAGS) \
	$(GTK_CFLAGS) \
	$(LIBGNOMEUI_CFLAGS) \
	$(GNOMEKEYRING_CFLAGS) \
	$(NETWORK_MANAGER_CFLAGS) \
	$(NM_UTILS_CFLAGS) \
	-DG_DISABLE_DEPRECATED \
	-DGNOME_DISABLE_DEPRECATED \
	-DGNOMELOCALEDIR=\"$(datadir)/locale\" \
	-DVERSION=\"$(VERSION)\"

nm_strongswan_auth_dialog_SOURCES =	\
	main.c

nm_strongswan_auth_dialog_LDADD = \
	$(GTK_LIBS) \
	$(LIBGNOMEUI_LIBS) \
	$(GNOMEKEYRING_LIBS) \
	$(NM_UTILS_LIBS)

