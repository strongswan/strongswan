
SUBDIRS =

if USE_LEGACY_SYSTEMD
if USE_FILE_CONFIG
if USE_CHARON
  SUBDIRS += systemd-starter
endif
endif
endif

if USE_SYSTEMD
if USE_SWANCTL
  SUBDIRS += systemd
endif
endif
