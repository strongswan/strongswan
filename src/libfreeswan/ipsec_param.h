/*
 * @(#) FreeSWAN tunable paramaters
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
 */

/* 
 * This file provides a set of #define's which may be tuned by various
 * people/configurations. It keeps all compile-time tunables in one place.
 *
 * This file should be included before all other IPsec kernel-only files.
 *
 */

#ifndef _IPSEC_PARAM_H_

/*
 * This is for the SA reference table. This number is related to the
 * maximum number of SAs that KLIPS can concurrently deal with, plus enough
 * space for keeping expired SAs around.
 *
 * TABLE_MAX_WIDTH is the number of bits that we will use.
 * MAIN_TABLE_WIDTH is the number of bits used for the primary index table.
 *
 */
#ifndef IPSEC_SA_REF_TABLE_IDX_WIDTH
# define IPSEC_SA_REF_TABLE_IDX_WIDTH 16
#endif

#ifndef IPSEC_SA_REF_MAINTABLE_IDX_WIDTH 
# define IPSEC_SA_REF_MAINTABLE_IDX_WIDTH 4 
#endif

#ifndef IPSEC_SA_REF_FREELIST_NUM_ENTRIES 
# define IPSEC_SA_REF_FREELIST_NUM_ENTRIES 256
#endif

#ifndef IPSEC_SA_REF_CODE 
# define IPSEC_SA_REF_CODE 1 
#endif

#define _IPSEC_PARAM_H_
#endif /* _IPSEC_PARAM_H_ */
