/*
 * IP-in-IP Header declarations
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
 * RCSID $Id: ipsec_ipe4.h,v 1.1 2004/03/15 20:35:25 as Exp $
 */

/* The packet header is an IP header! */

struct ipe4_xdata			/* transform table data */
{
	struct in_addr	i4_src;
	struct in_addr	i4_dst;
};

#define EMT_IPE4_ULEN	8	/* coming from user mode */
