ipsec_PROGRAMS = stroke

stroke_SOURCES = stroke.c stroke_msg.h stroke_keywords.c stroke_keywords.h
INCLUDES = -I$(top_srcdir)/src/libstrongswan
EXTRA_DIST = stroke_keywords.txt
MAINTAINERCLEANFILES = stroke_keywords.c
AM_CFLAGS = -DIPSEC_PIDDIR=\"${piddir}\"

stroke_keywords.c:	stroke_keywords.txt stroke_keywords.h
		$(GPERF) -C -G -t < $< > $@
