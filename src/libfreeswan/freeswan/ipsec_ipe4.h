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
 

/*
 * $Log: ipsec_ipe4.h,v $
 * Revision 1.1  2004/03/15 20:35:25  as
 * added files from freeswan-2.04-x509-1.5.3
 *
 * Revision 1.5  2002/04/24 07:36:46  mcr
 * Moved from ./klips/net/ipsec/ipsec_ipe4.h,v
 *
 * Revision 1.4  2001/06/14 19:35:08  rgb
 * Update copyright date.
 *
 * Revision 1.3  1999/04/11 00:28:57  henry
 * GPL boilerplate
 *
 * Revision 1.2  1999/04/06 04:54:25  rgb
 * Fix/Add RCSID Id: and Log: bits to make PHMDs happy.  This includes
 * patch shell fixes.
 *
 * Revision 1.1  1998/06/18 21:27:47  henry
 * move sources from klips/src to klips/net/ipsec, to keep stupid
 * kernel-build scripts happier in the presence of symlinks
 *
 * Revision 1.1  1998/04/09 03:06:07  henry
 * sources moved up from linux/net/ipsec
 *
 * Revision 1.1.1.1  1998/04/08 05:35:03  henry
 * RGB's ipsec-0.8pre2.tar.gz ipsec-0.8
 *
 * Revision 0.4  1997/01/15 01:28:15  ji
 * No changes.
 *
 * Revision 0.3  1996/11/20 14:48:53  ji
 * Release update only.
 *
 * Revision 0.2  1996/11/02 00:18:33  ji
 * First limited release.
 *
 *
 */
