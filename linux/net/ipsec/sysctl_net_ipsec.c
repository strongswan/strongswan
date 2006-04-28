/*
 * sysctl interface to net IPSEC subsystem.
 * Copyright (C) 1998, 1999, 2000, 2001	  Richard Guy Briggs.
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
 * RCSID $Id: sysctl_net_ipsec.c,v 1.1 2004/03/15 20:35:27 as Exp $
 */

/* -*- linux-c -*-
 *
 * Initiated April 3, 1998, Richard Guy Briggs <rgb@conscoop.ottawa.on.ca>
 */

#include <linux/mm.h>
#include <linux/sysctl.h>

#include "freeswan/ipsec_param.h"

#ifdef CONFIG_SYSCTL

#define NET_IPSEC 2112 /* Random number */                                        
#ifdef CONFIG_IPSEC_DEBUG
extern int       debug_ah;
extern int       debug_esp;
extern int       debug_tunnel;
extern int       debug_eroute;
extern int       debug_spi;
extern int       debug_radij;
extern int       debug_netlink;
extern int       debug_xform;
extern int       debug_rcv;
extern int       debug_pfkey;
extern int sysctl_ipsec_debug_verbose;
#ifdef CONFIG_IPSEC_IPCOMP
extern int sysctl_ipsec_debug_ipcomp;
#endif /* CONFIG_IPSEC_IPCOMP */
#endif /* CONFIG_IPSEC_DEBUG */

extern int sysctl_ipsec_icmp;
extern int sysctl_ipsec_inbound_policy_check;
extern int sysctl_ipsec_tos;
int sysctl_ipsec_regress_pfkey_lossage;

enum {
#ifdef CONFIG_IPSEC_DEBUG
	NET_IPSEC_DEBUG_AH=1,
	NET_IPSEC_DEBUG_ESP=2,
	NET_IPSEC_DEBUG_TUNNEL=3,
	NET_IPSEC_DEBUG_EROUTE=4,
	NET_IPSEC_DEBUG_SPI=5,
	NET_IPSEC_DEBUG_RADIJ=6,
	NET_IPSEC_DEBUG_NETLINK=7,
	NET_IPSEC_DEBUG_XFORM=8,
	NET_IPSEC_DEBUG_RCV=9,
	NET_IPSEC_DEBUG_PFKEY=10,
	NET_IPSEC_DEBUG_VERBOSE=11,
	NET_IPSEC_DEBUG_IPCOMP=12,
#endif /* CONFIG_IPSEC_DEBUG */
	NET_IPSEC_ICMP=13,
	NET_IPSEC_INBOUND_POLICY_CHECK=14,
	NET_IPSEC_TOS=15,
	NET_IPSEC_REGRESS_PFKEY_LOSSAGE=16,
};

static ctl_table ipsec_table[] = {
#ifdef CONFIG_IPSEC_DEBUG
	{ NET_IPSEC_DEBUG_AH, "debug_ah", &debug_ah,
	  sizeof(int), 0644, NULL, &proc_dointvec},    
	{ NET_IPSEC_DEBUG_ESP, "debug_esp", &debug_esp,
	  sizeof(int), 0644, NULL, &proc_dointvec},    
	{ NET_IPSEC_DEBUG_TUNNEL, "debug_tunnel", &debug_tunnel,
	  sizeof(int), 0644, NULL, &proc_dointvec},    
	{ NET_IPSEC_DEBUG_EROUTE, "debug_eroute", &debug_eroute,
	  sizeof(int), 0644, NULL, &proc_dointvec},    
	{ NET_IPSEC_DEBUG_SPI, "debug_spi", &debug_spi,
	  sizeof(int), 0644, NULL, &proc_dointvec},    
	{ NET_IPSEC_DEBUG_RADIJ, "debug_radij", &debug_radij,
	  sizeof(int), 0644, NULL, &proc_dointvec},    
	{ NET_IPSEC_DEBUG_NETLINK, "debug_netlink", &debug_netlink,
	  sizeof(int), 0644, NULL, &proc_dointvec},    
	{ NET_IPSEC_DEBUG_XFORM, "debug_xform", &debug_xform,
	  sizeof(int), 0644, NULL, &proc_dointvec},    
	{ NET_IPSEC_DEBUG_RCV, "debug_rcv", &debug_rcv,
	  sizeof(int), 0644, NULL, &proc_dointvec},    
	{ NET_IPSEC_DEBUG_PFKEY, "debug_pfkey", &debug_pfkey,
	  sizeof(int), 0644, NULL, &proc_dointvec},    
	{ NET_IPSEC_DEBUG_VERBOSE, "debug_verbose",&sysctl_ipsec_debug_verbose,
	  sizeof(int), 0644, NULL, &proc_dointvec},    
#ifdef CONFIG_IPSEC_IPCOMP
	{ NET_IPSEC_DEBUG_IPCOMP, "debug_ipcomp", &sysctl_ipsec_debug_ipcomp,
	  sizeof(int), 0644, NULL, &proc_dointvec},    
#endif /* CONFIG_IPSEC_IPCOMP */

#ifdef CONFIG_IPSEC_REGRESS
	{ NET_IPSEC_REGRESS_PFKEY_LOSSAGE, "pfkey_lossage",
	  &sysctl_ipsec_regress_pfkey_lossage,
	  sizeof(int), 0644, NULL, &proc_dointvec},
#endif /* CONFIG_IPSEC_REGRESS */

#endif /* CONFIG_IPSEC_DEBUG */
	{ NET_IPSEC_ICMP, "icmp", &sysctl_ipsec_icmp,
	  sizeof(int), 0644, NULL, &proc_dointvec},    
	{ NET_IPSEC_INBOUND_POLICY_CHECK, "inbound_policy_check", &sysctl_ipsec_inbound_policy_check,
	  sizeof(int), 0644, NULL, &proc_dointvec},    
	{ NET_IPSEC_TOS, "tos", &sysctl_ipsec_tos,
	  sizeof(int), 0644, NULL, &proc_dointvec},    
	{0}
};

static ctl_table ipsec_net_table[] = {
        { NET_IPSEC, "ipsec", NULL, 0, 0555, ipsec_table },
        { 0 }
};
 
static ctl_table ipsec_root_table[] = {
        { CTL_NET, "net", NULL, 0, 0555, ipsec_net_table },
        { 0 }
};
 
static struct ctl_table_header *ipsec_table_header;

int ipsec_sysctl_register(void)
{
        ipsec_table_header = register_sysctl_table(ipsec_root_table, 0);
        if (!ipsec_table_header) {
                return -ENOMEM;
	}
        return 0;
}
 
void ipsec_sysctl_unregister(void)
{
        unregister_sysctl_table(ipsec_table_header);
}

#endif /* CONFIG_SYSCTL */

/*
 * $Log: sysctl_net_ipsec.c,v $
 * Revision 1.1  2004/03/15 20:35:27  as
 * added files from freeswan-2.04-x509-1.5.3
 *
 * Revision 1.15  2002/04/24 07:55:32  mcr
 * 	#include patches and Makefiles for post-reorg compilation.
 *
 * Revision 1.14  2002/04/24 07:36:35  mcr
 * Moved from ./klips/net/ipsec/sysctl_net_ipsec.c,v
 *
 * Revision 1.13  2002/01/12 02:58:32  mcr
 * 	first regression test causes acquire messages to be lost
 * 	100% of the time. This is to help testing of pluto.
 *
 * Revision 1.12  2001/06/14 19:35:13  rgb
 * Update copyright date.
 *
 * Revision 1.11  2001/02/26 19:58:13  rgb
 * Drop sysctl_ipsec_{no_eroute_pass,opportunistic}, replaced by magic SAs.
 *
 * Revision 1.10  2000/09/16 01:50:15  rgb
 * Protect sysctl_ipsec_debug_ipcomp with compiler defines too so that the
 * linker won't blame rj_delete() for missing symbols.  ;->  Damn statics...
 *
 * Revision 1.9  2000/09/15 23:17:51  rgb
 * Moved stuff around to compile with debug off.
 *
 * Revision 1.8  2000/09/15 11:37:02  rgb
 * Merge in heavily modified Svenning Soerensen's <svenning@post5.tele.dk>
 * IPCOMP zlib deflate code.
 *
 * Revision 1.7  2000/09/15 07:37:15  rgb
 * Munged silly log comment that was causing a warning.
 *
 * Revision 1.6  2000/09/15 04:58:23  rgb
 * Added tos runtime switch.
 * Removed 'sysctl_ipsec_' prefix from /proc/sys/net/ipsec/ filenames.
 *
 * Revision 1.5  2000/09/12 03:25:28  rgb
 * Filled in and implemented sysctl.
 *
 * Revision 1.4  1999/04/11 00:29:03  henry
 * GPL boilerplate
 *
 * Revision 1.3  1999/04/06 04:54:29  rgb
 * Fix/Add RCSID Id: and Log: bits to make PHMDs happy.  This includes
 * patch shell fixes.
 *
 */
