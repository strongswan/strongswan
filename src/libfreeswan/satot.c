/*
 * convert from binary form of SA ID to text
 * Copyright (C) 2000, 2001  Henry Spencer.
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/lgpl.txt>.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Library General Public
 * License for more details.
 */
#include <sys/socket.h>

#include "internal.h"
#include "freeswan.h"

static struct typename {
	char type;
	char *name;
} typenames[] = {
	{ SA_AH,	"ah" },
	{ SA_ESP,	"esp" },
	{ SA_IPIP,	"tun" },
	{ SA_COMP,	"comp" },
	{ SA_INT,	"int" },
	{ 0,		NULL }
};

/*
 - satot - convert SA to text "ah507@1.2.3.4"
 */
size_t				/* space needed for full conversion */
satot(sa, format, dst, dstlen)
const ip_said *sa;
int format;			/* character */
char *dst;			/* need not be valid if dstlen is 0 */
size_t dstlen;
{
	size_t len = 0;		/* 0 means "not recognized yet" */
	int base;
	int showversion;	/* use delimiter to show IP version? */
	struct typename *tn;
	char *p;
	char *pre;
	char buf[10+1+ULTOT_BUF+ADDRTOT_BUF];
	char unk[10];

	switch (format) {
	case 0:
		base = 16;
		showversion = 1;
		break;
	case 'f':
		base = 17;
		showversion = 1;
		break;
	case 'x':
		base = 'x';
		showversion = 0;
		break;
	case 'd':
		base = 10;
		showversion = 0;
		break;
	default:
		return 0;
		break;
	}

	pre = NULL;
	for (tn = typenames; tn->name != NULL; tn++)
		if (sa->proto == tn->type) {
			pre = tn->name;
			break;			/* NOTE BREAK OUT */
		}
	if (pre == NULL) {		/* unknown protocol */
		strcpy(unk, "unk");
		(void) ultot((unsigned char)sa->proto, 10, unk+strlen(unk),
						sizeof(unk)-strlen(unk));
		pre = unk;
	}

	if (strcmp(pre, PASSTHROUGHTYPE) == 0 &&
					sa->spi == PASSTHROUGHSPI &&
					isunspecaddr(&sa->dst)) {
		strcpy(buf, (addrtypeof(&sa->dst) == AF_INET) ?
							PASSTHROUGH4NAME :
							PASSTHROUGH6NAME);
		len = strlen(buf);
	}

	if (sa->proto == SA_INT && addrtypeof(&sa->dst) == AF_INET &&
						isunspecaddr(&sa->dst)) {
		switch (ntohl(sa->spi)) {
		case SPI_PASS:	p = "%pass";	break;
		case SPI_DROP:	p = "%drop";	break;
		case SPI_REJECT:	p = "%reject";	break;
		case SPI_HOLD:	p = "%hold";	break;
		case SPI_TRAP:	p = "%trap";	break;
		case SPI_TRAPSUBNET:	p = "%trapsubnet";	break;
		default:	p = NULL;	break;
		}
		if (p != NULL) {
			strcpy(buf, p);
			len = strlen(buf);
		}
	}

	if (len == 0) {			/* general case needed */
		strcpy(buf, pre);
		len = strlen(buf);
		if (showversion) {
			*(buf+len) = (addrtypeof(&sa->dst) == AF_INET) ? '.' :
									':';
			len++;
			*(buf+len) = '\0';
		}
		len += ultot(ntohl(sa->spi), base, buf+len, sizeof(buf)-len);
		*(buf+len-1) = '@';
		len += addrtot(&sa->dst, 0, buf+len, sizeof(buf)-len);
	}

	if (dst != NULL) {
		if (len > dstlen)
			*(buf+dstlen-1) = '\0';
		strcpy(dst, buf);
	}
	return len;
}
