/*
 * convert from binary form of SA ID to ASCII
 * Copyright (C) 1998, 1999, 2001  Henry Spencer.
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
 - satoa - convert SA to ASCII "ah507@1.2.3.4"
 */
size_t				/* space needed for full conversion */
satoa(sa, format, dst, dstlen)
struct sa_id sa;
int format;			/* character */
char *dst;			/* need not be valid if dstlen is 0 */
size_t dstlen;
{
	size_t len = 0;		/* 0 means not handled yet */
	int base;
	struct typename *tn;
	char buf[30+ADDRTOA_BUF];

	switch (format) {
	case 0:
		base = 16;	/* temporarily at least */
		break;
	case 'd':
		base = 10;
		break;
	default:
		return 0;
		break;
	}

	for (tn = typenames; tn->name != NULL; tn++)
		if (sa.proto == tn->type)
			break;
	if (tn->name == NULL)
		return 0;

	if (strcmp(tn->name, PASSTHROUGHTYPE) == 0 &&
					sa.spi == PASSTHROUGHSPI &&
					sa.dst.s_addr == PASSTHROUGHDST) {
		strcpy(buf, PASSTHROUGHNAME);
		len = strlen(buf);
	} else if (sa.proto == SA_INT && sa.dst.s_addr == 0) {
		char *p;

		switch (ntohl(sa.spi)) {
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

	if (len == 0) {
		strcpy(buf, tn->name);
		len = strlen(buf);
		len += ultoa(ntohl(sa.spi), base, buf+len, sizeof(buf)-len);
		*(buf+len-1) = '@';
		len += addrtoa(sa.dst, 0, buf+len, sizeof(buf)-len);
	}

	if (dst != NULL) {
		if (len > dstlen)
			*(buf+dstlen-1) = '\0';
		strcpy(dst, buf);
	}
	return len;
}
