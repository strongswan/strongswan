/*
 * @(#) pfkey version 2 debugging messages
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
 * RCSID $Id: pfkey_v2_debug.c,v 1.2 2004/03/22 21:53:18 as Exp $
 *
 */

#ifdef __KERNEL__

# include <linux/kernel.h>  /* for printk */

# include "freeswan/ipsec_kversion.h" /* for malloc switch */
# ifdef MALLOC_SLAB
#  include <linux/slab.h> /* kmalloc() */
# else /* MALLOC_SLAB */
#  include <linux/malloc.h> /* kmalloc() */
# endif /* MALLOC_SLAB */
# include <linux/errno.h>  /* error codes */
# include <linux/types.h>  /* size_t */
# include <linux/interrupt.h> /* mark_bh */

# include <linux/netdevice.h>   /* struct device, and other headers */
# include <linux/etherdevice.h> /* eth_type_trans */
extern int debug_pfkey;

#else /* __KERNEL__ */

# include <sys/types.h>
# include <linux/types.h>
# include <linux/errno.h>

#endif /* __KERNEL__ */

#include "freeswan.h"
#include "pfkeyv2.h"
#include "pfkey.h"

/* 
 * This file provides ASCII translations of PF_KEY magic numbers.
 *
 */

static char *pfkey_sadb_ext_strings[]={
  "reserved",                     /* SADB_EXT_RESERVED             0 */
  "security-association",         /* SADB_EXT_SA                   1 */
  "lifetime-current",             /* SADB_EXT_LIFETIME_CURRENT     2 */
  "lifetime-hard",                /* SADB_EXT_LIFETIME_HARD        3 */
  "lifetime-soft",                /* SADB_EXT_LIFETIME_SOFT        4 */
  "source-address",               /* SADB_EXT_ADDRESS_SRC          5 */
  "destination-address",          /* SADB_EXT_ADDRESS_DST          6 */
  "proxy-address",                /* SADB_EXT_ADDRESS_PROXY        7 */
  "authentication-key",           /* SADB_EXT_KEY_AUTH             8 */
  "cipher-key",                   /* SADB_EXT_KEY_ENCRYPT          9 */
  "source-identity",              /* SADB_EXT_IDENTITY_SRC         10 */
  "destination-identity",         /* SADB_EXT_IDENTITY_DST         11 */
  "sensitivity-label",            /* SADB_EXT_SENSITIVITY          12 */
  "proposal",                     /* SADB_EXT_PROPOSAL             13 */
  "supported-auth",               /* SADB_EXT_SUPPORTED_AUTH       14 */
  "supported-cipher",             /* SADB_EXT_SUPPORTED_ENCRYPT    15 */
  "spi-range",                    /* SADB_EXT_SPIRANGE             16 */
  "X-kmpprivate",                 /* SADB_X_EXT_KMPRIVATE          17 */
  "X-satype2",                    /* SADB_X_EXT_SATYPE2            18 */
  "X-security-association",       /* SADB_X_EXT_SA2                19 */
  "X-destination-address2",       /* SADB_X_EXT_ADDRESS_DST2       20 */
  "X-source-flow-address",        /* SADB_X_EXT_ADDRESS_SRC_FLOW   21 */
  "X-dest-flow-address",          /* SADB_X_EXT_ADDRESS_DST_FLOW   22 */
  "X-source-mask",                /* SADB_X_EXT_ADDRESS_SRC_MASK   23 */
  "X-dest-mask",                  /* SADB_X_EXT_ADDRESS_DST_MASK   24 */
  "X-set-debug",                  /* SADB_X_EXT_DEBUG              25 */
  "X-NAT-T-type",                 /* SADB_X_EXT_NAT_T_TYPE         26 */
  "X-NAT-T-sport",                /* SADB_X_EXT_NAT_T_SPORT        27 */
  "X-NAT-T-dport",                /* SADB_X_EXT_NAT_T_DPORT        28 */
  "X-NAT-T-OA",                   /* SADB_X_EXT_NAT_T_OA           29 */
};

const char *
pfkey_v2_sadb_ext_string(int ext)
{
  if(ext <= SADB_EXT_MAX) {
    return pfkey_sadb_ext_strings[ext];
  } else {
    return "unknown-ext";
  }
}


static char *pfkey_sadb_type_strings[]={
	"reserved",                     /* SADB_RESERVED      */
	"getspi",                       /* SADB_GETSPI        */
	"update",                       /* SADB_UPDATE        */
	"add",                          /* SADB_ADD           */
	"delete",                       /* SADB_DELETE        */
	"get",                          /* SADB_GET           */
	"acquire",                      /* SADB_ACQUIRE       */
	"register",                     /* SADB_REGISTER      */
	"expire",                       /* SADB_EXPIRE        */
	"flush",                        /* SADB_FLUSH         */
	"dump",                         /* SADB_DUMP          */
	"x-promisc",                    /* SADB_X_PROMISC     */
	"x-pchange",                    /* SADB_X_PCHANGE     */
	"x-groupsa",                    /* SADB_X_GRPSA       */
	"x-addflow(eroute)",            /* SADB_X_ADDFLOW     */
	"x-delflow(eroute)",            /* SADB_X_DELFLOW     */
	"x-debug",                      /* SADB_X_DEBUG       */
};

const char *
pfkey_v2_sadb_type_string(int sadb_type)
{
  if(sadb_type <= SADB_MAX) {
    return pfkey_sadb_type_strings[sadb_type];
  } else {
    return "unknown-sadb-type";
  }
}




/*
 * $Log: pfkey_v2_debug.c,v $
 * Revision 1.2  2004/03/22 21:53:18  as
 * merged alg-0.8.1 branch with HEAD
 *
 * Revision 1.1.2.1  2004/03/15 22:30:06  as
 * nat-0.6c patch merged
 *
 * Revision 1.1  2004/03/15 20:35:26  as
 * added files from freeswan-2.04-x509-1.5.3
 *
 * Revision 1.7  2002/09/20 05:01:26  rgb
 * Fixed limit inclusion error in both type and ext string conversion.
 *
 * Revision 1.6  2002/04/24 07:55:32  mcr
 * 	#include patches and Makefiles for post-reorg compilation.
 *
 * Revision 1.5  2002/04/24 07:36:40  mcr
 * Moved from ./lib/pfkey_v2_debug.c,v
 *
 * Revision 1.4  2002/01/29 22:25:36  rgb
 * Re-add ipsec_kversion.h to keep MALLOC happy.
 *
 * Revision 1.3  2002/01/29 01:59:09  mcr
 * 	removal of kversions.h - sources that needed it now use ipsec_param.h.
 * 	updating of IPv6 structures to match latest in6.h version.
 * 	removed dead code from freeswan.h that also duplicated kversions.h
 * 	code.
 *
 * Revision 1.2  2002/01/20 20:34:50  mcr
 * 	added pfkey_v2_sadb_type_string to decode sadb_type to string.
 *
 * Revision 1.1  2001/11/27 05:30:06  mcr
 * 	initial set of debug strings for pfkey debugging.
 * 	this will eventually only be included for debug builds.
 *
 * Revision 1.1  2001/09/21 04:12:03  mcr
 * 	first compilable version.
 *
 *
 * Local variables:
 * c-file-style: "linux"
 * End:
 *
 */
