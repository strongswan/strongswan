/*
 * Definitions relevant to IPSEC lifetimes
 * Copyright (C) 2001  Richard Guy Briggs  <rgb@freeswan.org>
 *                 and Michael Richardson  <mcr@freeswan.org>
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
 * RCSID $Id$
 *
 * This file derived from ipsec_xform.h on 2001/9/18 by mcr.
 *
 */

/* 
 * This file describes the book keeping fields for the 
 *   IPsec Security Association Structure. ("ipsec_sa")
 *
 * This structure is never allocated directly by kernel code,
 * (it is always a static/auto or is part of a structure)
 * so it does not have a reference count.
 *
 */

#ifndef _IPSEC_LIFE_H_

/*
 *  _count is total count.
 *  _hard is hard limit (kill SA after this number)
 *  _soft is soft limit (try to renew SA after this number)
 *  _last is used in some special cases.
 *
 */

struct ipsec_lifetime64
{
	__u64           ipl_count;
	__u64           ipl_soft;
	__u64           ipl_hard;
	__u64           ipl_last;  
};

struct ipsec_lifetimes
{
	/* number of bytes processed */
	struct ipsec_lifetime64 ipl_bytes;

	/* number of packets processed */
	struct ipsec_lifetime64 ipl_packets;

	/* time since SA was added */
	struct ipsec_lifetime64 ipl_addtime;

	/* time since SA was first used */
	struct ipsec_lifetime64 ipl_usetime;

	/* from rfc2367:  
         *         For CURRENT, the number of different connections,
         *         endpoints, or flows that the association has been
         *          allocated towards. For HARD and SOFT, the number of
         *          these the association may be allocated towards
         *          before it expires. The concept of a connection,
         *          flow, or endpoint is system specific.
	 *
	 * mcr(2001-9-18) it is unclear what purpose these serve for FreeSWAN.
	 *          They are maintained for PF_KEY compatibility. 
	 */
	struct ipsec_lifetime64 ipl_allocations;
};

enum ipsec_life_alive {
	ipsec_life_harddied = -1,
	ipsec_life_softdied = 0,
	ipsec_life_okay     = 1
};

enum ipsec_life_type {
	ipsec_life_timebased = 1,
	ipsec_life_countbased= 0
};

#define _IPSEC_LIFE_H_
#endif /* _IPSEC_LIFE_H_ */
