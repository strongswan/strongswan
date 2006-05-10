/*
 * @(#) Definitions relevant to the IPSEC <> radij tree interfacing
 * Copyright (C) 1996, 1997  John Ioannidis.
 * Copyright (C) 1998, 1999, 2000, 2001  Richard Guy Briggs.
 * 
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 * RCSID $Id: ipsec_radij.h,v 1.3 2004/04/28 05:44:29 as Exp $
 */

#ifndef _IPSEC_RADIJ_H

#include <freeswan.h>

int ipsec_walk(char *);

int ipsec_rj_walker_procprint(struct radij_node *, void *);
int ipsec_rj_walker_delete(struct radij_node *, void *);

/* This structure is used to pass information between
 * ipsec_eroute_get_info and ipsec_rj_walker_procprint
 * (through rj_walktree) and between calls of ipsec_rj_walker_procprint.
 */
struct wsbuf
{
	/* from caller of ipsec_eroute_get_info: */
	char *const buffer;	/* start of buffer provided */
	const int length;	/* length of buffer provided */
	const off_t offset;	/* file position of first character of interest */
	/* accumulated by ipsec_rj_walker_procprint: */
	int len;		/* number of character filled into buffer */
	off_t begin;		/* file position contained in buffer[0] (<=offset) */
};


extern struct radij_node_head *rnh;
extern spinlock_t eroute_lock;

struct eroute * ipsec_findroute(struct sockaddr_encap *);

#define O1(x) (int)(((x)>>24)&0xff)
#define O2(x) (int)(((x)>>16)&0xff)
#define O3(x) (int)(((x)>>8)&0xff)
#define O4(x) (int)(((x))&0xff)

#ifdef CONFIG_IPSEC_DEBUG
extern int debug_radij;
void rj_dumptrees(void);

#define DB_RJ_DUMPTREES	0x0001
#define DB_RJ_FINDROUTE 0x0002
#endif /* CONFIG_IPSEC_DEBUG */

#define _IPSEC_RADIJ_H
#endif
