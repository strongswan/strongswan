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
 */

# include <sys/types.h>
# include <errno.h>

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
