
SUBDIRS =

if USE_LEGACY_SYSTEMD
if USE_CHARON
if USE_FILE_CONFIG
  SUBDIRS += systemd-starter
endif
endif
endif

if USE_SYSTEMD
if USE_SWANCTL
  SUBDIRS += systemd
endif
endif
