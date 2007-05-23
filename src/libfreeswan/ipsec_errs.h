/*
 * @(#) definition of ipsec_errs structure
 *
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
 * RCSID $Id: ipsec_errs.h,v 1.1 2004/03/15 20:35:25 as Exp $
 *
 */

/* 
 * This file describes the errors/statistics that FreeSWAN collects.
 *
 */

struct ipsec_errs {
	__u32		ips_alg_errs;	       /* number of algorithm errors */
	__u32		ips_auth_errs;	       /* # of authentication errors */
	__u32		ips_encsize_errs;      /* # of encryption size errors*/
	__u32		ips_encpad_errs;       /* # of encryption pad  errors*/
	__u32		ips_replaywin_errs;    /* # of pkt sequence errors */
};
