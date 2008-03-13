SUBDIRS = include

if USE_FILE_CONFIG
  SUBDIRS += libfreeswan starter ipsec _copyright
endif

if USE_LIBSTRONGSWAN
  SUBDIRS += libstrongswan
endif

if USE_PLUTO
  SUBDIRS += libcrypto pluto whack
endif
if USE_CHARON
  SUBDIRS += charon
endif

if USE_STROKE
  SUBDIRS += stroke
endif

if USE_PLUTO_OR_CHARON
  SUBDIRS += _updown _updown_espmark
endif

if USE_TOOLS
  SUBDIRS += openac scepclient
endif

if USE_UML
  SUBDIRS += dumm
endif

if USE_FAST
  SUBDIRS += libfast
endif

if USE_MANAGER
  SUBDIRS += manager
endif

