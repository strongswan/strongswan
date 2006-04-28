/*
 * @(#) /proc file system interface code.
 *
 * Copyright (C) 1996, 1997  John Ioannidis.
 * Copyright (C) 1998, 1999, 2000, 2001  Richard Guy Briggs <rgb@freeswan.org>
 *                                 2001  Michael Richardson <mcr@freeswan.org>
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
 * Split out from ipsec_init.c version 1.70.
 */

char ipsec_proc_c_version[] = "RCSID $Id: ipsec_proc.c,v 1.8 2004/04/28 08:06:22 as Exp $";

#include <linux/config.h>
#include <linux/version.h>
#define __NO_VERSION__
#include <linux/module.h>
#include <linux/kernel.h> /* printk() */

#include "freeswan/ipsec_param.h"

#ifdef MALLOC_SLAB
# include <linux/slab.h> /* kmalloc() */
#else /* MALLOC_SLAB */
# include <linux/malloc.h> /* kmalloc() */
#endif /* MALLOC_SLAB */
#include <linux/errno.h>  /* error codes */
#include <linux/types.h>  /* size_t */
#include <linux/interrupt.h> /* mark_bh */

#include <linux/netdevice.h>   /* struct device, and other headers */
#include <linux/etherdevice.h> /* eth_type_trans */
#include <linux/ip.h>          /* struct iphdr */
#include <linux/in.h>          /* struct sockaddr_in */
#include <linux/skbuff.h>
#include <freeswan.h>
#ifdef SPINLOCK
#ifdef SPINLOCK_23
#include <linux/spinlock.h> /* *lock* */
#else /* SPINLOCK_23 */
#include <asm/spinlock.h> /* *lock* */
#endif /* SPINLOCK_23 */
#endif /* SPINLOCK */
#ifdef NET_21
#include <asm/uaccess.h>
#include <linux/in6.h>
#endif /* NET_21 */
#include <asm/checksum.h>
#include <net/ip.h>
#ifdef CONFIG_PROC_FS
#include <linux/proc_fs.h>
#endif /* CONFIG_PROC_FS */
#ifdef NETLINK_SOCK
#include <linux/netlink.h>
#else
#include <net/netlink.h>
#endif

#include "freeswan/radij.h"

#include "freeswan/ipsec_life.h"
#include "freeswan/ipsec_stats.h"
#include "freeswan/ipsec_sa.h"

#include "freeswan/ipsec_encap.h"
#include "freeswan/ipsec_radij.h"
#include "freeswan/ipsec_xform.h"
#include "freeswan/ipsec_tunnel.h"
#include "freeswan/ipsec_xmit.h"

#include "freeswan/ipsec_rcv.h"
#include "freeswan/ipsec_ah.h"
#include "freeswan/ipsec_esp.h"

#ifdef CONFIG_IPSEC_IPCOMP
#include "freeswan/ipcomp.h"
#endif /* CONFIG_IPSEC_IPCOMP */

#include "freeswan/ipsec_proto.h"

#include <pfkeyv2.h>
#include <pfkey.h>

#ifdef CONFIG_PROC_FS

#ifdef IPSEC_PROC_SUBDIRS
static struct proc_dir_entry *proc_net_ipsec_dir = NULL;
static struct proc_dir_entry *proc_eroute_dir    = NULL;
static struct proc_dir_entry *proc_spi_dir       = NULL;
static struct proc_dir_entry *proc_spigrp_dir    = NULL;
static struct proc_dir_entry *proc_birth_dir     = NULL;
static struct proc_dir_entry *proc_stats_dir     = NULL;
#endif

struct ipsec_birth_reply ipsec_ipv4_birth_packet;
struct ipsec_birth_reply ipsec_ipv6_birth_packet;

extern int ipsec_xform_get_info(char *buffer, char **start,
				off_t offset, int length IPSEC_PROC_LAST_ARG);


/* ipsec_snprintf: like snprintf except
 * - size is signed and a negative value is treated as if it were 0
 * - the returned result is never negative --
 *   an error generates a "?" or null output (depending on space).
 *   (Our callers are too lazy to check for an error return.)
 *
 * @param buf String buffer
 * @param size Size of the string
 * @param fmt printf string
 * @param ... Variables to be displayed in fmt
 * @return int Return code
 */
int ipsec_snprintf(char *buf, ssize_t size, const char *fmt, ...)
{
       va_list args;
       int i;
       size_t possize = size < 0? 0 : size;
       va_start(args, fmt);
       i = vsnprintf(buf,possize,fmt,args);
       va_end(args);
       if (i < 0) {
           /* create empty output in place of error */
           i = 0;
           if (size > 0) {
               *buf = '\0';
           }
       }
       return i;
}


IPSEC_PROCFS_DEBUG_NO_STATIC
int
ipsec_eroute_get_info(char *buffer, 
		      char **start, 
		      off_t offset, 
		      int length        IPSEC_PROC_LAST_ARG)
{
	struct wsbuf w = {buffer, length, offset, 0, 0};

#ifdef CONFIG_IPSEC_DEBUG
	if (debug_radij & DB_RJ_DUMPTREES)
	  rj_dumptrees();			/* XXXXXXXXX */
#endif /* CONFIG_IPSEC_DEBUG */

	KLIPS_PRINT(debug_tunnel & DB_TN_PROCFS,
		    "klips_debug:ipsec_eroute_get_info: "
		    "buffer=0p%p, *start=0p%p, offset=%d, length=%d\n",
		    buffer,
		    *start,
		    (int)offset,
		    length);

	spin_lock_bh(&eroute_lock);

	rj_walktree(rnh, ipsec_rj_walker_procprint, &w);
/*	rj_walktree(mask_rjhead, ipsec_rj_walker_procprint, &w); */

	spin_unlock_bh(&eroute_lock);

	*start = buffer + (offset - w.begin);	/* Start of wanted data */
	return w.len - (offset - w.begin);
}

IPSEC_PROCFS_DEBUG_NO_STATIC
int
ipsec_spi_get_info(char *buffer,
		   char **start,
		   off_t offset,
		   int length    IPSEC_PROC_LAST_ARG)
{
	/* Limit of useful snprintf output */
	const int max_content = length > 0? length-1 : 0;

	int len = 0;
	off_t begin = 0;
	int i;
	struct ipsec_sa *sa_p;
	char sa[SATOA_BUF];
	char buf_s[SUBNETTOA_BUF];
	char buf_d[SUBNETTOA_BUF];
	size_t sa_len;

	KLIPS_PRINT(debug_tunnel & DB_TN_PROCFS,
		    "klips_debug:ipsec_spi_get_info: "
		    "buffer=0p%p, *start=0p%p, offset=%d, length=%d\n",
		    buffer,
		    *start,
		    (int)offset,
		    length);
	
	spin_lock_bh(&tdb_lock);


	
	for (i = 0; i < SADB_HASHMOD; i++) {
		for (sa_p = ipsec_sadb_hash[i];
		     sa_p;
		     sa_p = sa_p->ips_hnext) {
			atomic_inc(&sa_p->ips_refcount);
			sa_len = satoa(sa_p->ips_said, 0, sa, SATOA_BUF);
			len += ipsec_snprintf(buffer+len, length-len, "%s ",
				       sa_len ? sa : " (error)");

			len += ipsec_snprintf(buffer+len, length-len, "%s%s%s",
				       IPS_XFORM_NAME(sa_p));

			len += ipsec_snprintf(buffer+len, length-len, ": dir=%s",
				       (sa_p->ips_flags & EMT_INBOUND) ?
				       "in " : "out");

			if(sa_p->ips_addr_s) {
				addrtoa(((struct sockaddr_in*)(sa_p->ips_addr_s))->sin_addr,
					0, buf_s, sizeof(buf_s));
				len += ipsec_snprintf(buffer+len, length-len, " src=%s",
					       buf_s);
			}

			if((sa_p->ips_said.proto == IPPROTO_IPIP)
			   && (sa_p->ips_flags & SADB_X_SAFLAGS_INFLOW)) {
				subnettoa(sa_p->ips_flow_s.u.v4.sin_addr,
					  sa_p->ips_mask_s.u.v4.sin_addr,
					  0,
					  buf_s,
					  sizeof(buf_s));

				subnettoa(sa_p->ips_flow_d.u.v4.sin_addr,
					  sa_p->ips_mask_d.u.v4.sin_addr,
					  0,
					  buf_d,
					  sizeof(buf_d));

				len += ipsec_snprintf(buffer+len, length-len, " policy=%s->%s",
					       buf_s, buf_d);
			}
			
			if(sa_p->ips_iv_bits) {
				int j;
				len += ipsec_snprintf(buffer+len, length-len, " iv_bits=%dbits iv=0x",
					       sa_p->ips_iv_bits);

				for(j = 0; j < sa_p->ips_iv_bits / 8; j++) {
					len += ipsec_snprintf(buffer+len, length-len, "%02x",
						       (__u32)((__u8*)(sa_p->ips_iv))[j]);
				}
			}

			if(sa_p->ips_encalg || sa_p->ips_authalg) {
				if(sa_p->ips_replaywin) {
					len += ipsec_snprintf(buffer+len, length-len, " ooowin=%d",
						       sa_p->ips_replaywin);
				}
				if(sa_p->ips_errs.ips_replaywin_errs) {
					len += ipsec_snprintf(buffer+len, length-len, " ooo_errs=%d",
						       sa_p->ips_errs.ips_replaywin_errs);
				}
				if(sa_p->ips_replaywin_lastseq) {
                                       len += ipsec_snprintf(buffer+len, length-len, " seq=%d",
						      sa_p->ips_replaywin_lastseq);
				}
				if(sa_p->ips_replaywin_bitmap) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,0)
					len += ipsec_snprintf(buffer+len, length-len, " bit=0x%Lx",
						       sa_p->ips_replaywin_bitmap);
#else
					len += ipsec_snprintf(buffer+len, length-len, " bit=0x%x%08x",
						       (__u32)(sa_p->ips_replaywin_bitmap >> 32),
						       (__u32)sa_p->ips_replaywin_bitmap);
#endif
				}
				if(sa_p->ips_replaywin_maxdiff) {
					len += ipsec_snprintf(buffer+len, length-len, " max_seq_diff=%d",
						       sa_p->ips_replaywin_maxdiff);
				}
			}
			if(sa_p->ips_flags & ~EMT_INBOUND) {
				len += ipsec_snprintf(buffer+len, length-len, " flags=0x%x",
					       sa_p->ips_flags & ~EMT_INBOUND);
				len += ipsec_snprintf(buffer+len, length-len, "<");
				/* flag printing goes here */
				len += ipsec_snprintf(buffer+len, length-len, ">");
			}
			if(sa_p->ips_auth_bits) {
				len += ipsec_snprintf(buffer+len, length-len, " alen=%d",
					       sa_p->ips_auth_bits);
			}
			if(sa_p->ips_key_bits_a) {
				len += ipsec_snprintf(buffer+len, length-len, " aklen=%d",
					       sa_p->ips_key_bits_a);
			}
			if(sa_p->ips_errs.ips_auth_errs) {
				len += ipsec_snprintf(buffer+len, length-len, " auth_errs=%d",
					       sa_p->ips_errs.ips_auth_errs);
			}
			if(sa_p->ips_key_bits_e) {
				len += ipsec_snprintf(buffer+len, length-len, " eklen=%d",
					       sa_p->ips_key_bits_e);
			}
			if(sa_p->ips_errs.ips_encsize_errs) {
				len += ipsec_snprintf(buffer+len, length-len, " encr_size_errs=%d",
					       sa_p->ips_errs.ips_encsize_errs);
			}
			if(sa_p->ips_errs.ips_encpad_errs) {
				len += ipsec_snprintf(buffer+len, length-len, " encr_pad_errs=%d",
					       sa_p->ips_errs.ips_encpad_errs);
			}
			
			len += ipsec_snprintf(buffer+len, length-len, " life(c,s,h)=");

			len += ipsec_lifetime_format(buffer + len,
						     length - len,
						     "alloc", 
						     ipsec_life_countbased,
						     &sa_p->ips_life.ipl_allocations);

			len += ipsec_lifetime_format(buffer + len,
						     length - len,
						     "bytes",
						     ipsec_life_countbased,
						     &sa_p->ips_life.ipl_bytes);

			len += ipsec_lifetime_format(buffer + len,
						     length - len,
						     "addtime",
						     ipsec_life_timebased,
						     &sa_p->ips_life.ipl_addtime);

			len += ipsec_lifetime_format(buffer + len,
						     length - len,
						     "usetime",
						     ipsec_life_timebased,
						     &sa_p->ips_life.ipl_usetime);
			
			len += ipsec_lifetime_format(buffer + len,
						     length - len,
						     "packets",
						     ipsec_life_countbased,
						     &sa_p->ips_life.ipl_packets);
			
			if(sa_p->ips_life.ipl_usetime.ipl_last) { /* XXX-MCR should be last? */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,0)
				len += ipsec_snprintf(buffer+len, length-len, " idle=%Ld",
					       jiffies / HZ - sa_p->ips_life.ipl_usetime.ipl_last);
#else
				len += ipsec_snprintf(buffer+len, length-len, " idle=%lu",
					       jiffies / HZ - (unsigned long)sa_p->ips_life.ipl_usetime.ipl_last);
#endif
			}

#ifdef CONFIG_IPSEC_IPCOMP
			if(sa_p->ips_said.proto == IPPROTO_COMP &&
			   (sa_p->ips_comp_ratio_dbytes ||
			    sa_p->ips_comp_ratio_cbytes)) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,0)
				len += ipsec_snprintf(buffer+len, length-len, " ratio=%Ld:%Ld",
					       sa_p->ips_comp_ratio_dbytes,
					       sa_p->ips_comp_ratio_cbytes);
#else
				len += ipsec_snprintf(buffer+len, length-len, " ratio=%lu:%lu",
					       (unsigned long)sa_p->ips_comp_ratio_dbytes,
					       (unsigned long)sa_p->ips_comp_ratio_cbytes);
#endif
			}
#endif /* CONFIG_IPSEC_IPCOMP */

#ifdef CONFIG_IPSEC_NAT_TRAVERSAL
			if(sa_p->ips_natt_type != 0) {
				char *natttype_name;

				switch(sa_p->ips_natt_type)
				{
				case ESPINUDP_WITH_NON_IKE:
					natttype_name="nonike";
					break;
				case ESPINUDP_WITH_NON_ESP:
					natttype_name="nonesp";
					break;
				default:
					natttype_name="unknown";
					break;
				}

				len += ipsec_snprintf(buffer+len, length-len, " natencap=%s",
					       natttype_name);

				len += ipsec_snprintf(buffer+len, length-len, " natsport=%d",
					       sa_p->ips_natt_sport);

				len += ipsec_snprintf(buffer+len, length-len, " natdport=%d",
					       sa_p->ips_natt_dport);
			}
#endif /* CONFIG_IPSEC_NAT_TRAVERSAL */

			len += ipsec_snprintf(buffer+len, length-len, " refcount=%d",
				       atomic_read(&sa_p->ips_refcount));

			len += ipsec_snprintf(buffer+len, length-len, " ref=%d",
				       sa_p->ips_ref);
#ifdef CONFIG_IPSEC_DEBUG
			if(debug_xform) {
			len += ipsec_snprintf(buffer+len, length-len, " reftable=%lu refentry=%lu",
				       (unsigned long)IPsecSAref2table(sa_p->ips_ref),
				       (unsigned long)IPsecSAref2entry(sa_p->ips_ref));
			}
#endif /* CONFIG_IPSEC_DEBUG */

			len += ipsec_snprintf(buffer+len, length-len, "\n");

			atomic_dec(&sa_p->ips_refcount);
                                        
			if (len >= max_content) {
				/* we've done all that can fit -- stop loops */
				len = max_content;      /* truncate crap */
				goto done_spi_i;
			} else {
				const off_t pos = begin + len;

				if (pos <= offset) {
					/* all is before first interesting character:
					* discard, but note where we are.
					*/
					len = 0;
					begin = pos;
				}
			}
		}
	}

done_spi_i:
	spin_unlock_bh(&tdb_lock);

	*start = buffer + (offset - begin);	/* Start of wanted data */
	return len - (offset - begin);
}

IPSEC_PROCFS_DEBUG_NO_STATIC
int
ipsec_spigrp_get_info(char *buffer,
		      char **start,
		      off_t offset,
		      int length     IPSEC_PROC_LAST_ARG)
{
	/* limit of useful snprintf output */
	const int max_content = length > 0? length-1 : 0;

	int len = 0;
	off_t begin = 0;
	int i;
	struct ipsec_sa *sa_p, *sa_p2;
	char sa[SATOA_BUF];
	size_t sa_len;

	KLIPS_PRINT(debug_tunnel & DB_TN_PROCFS,
		    "klips_debug:ipsec_spigrp_get_info: "
		    "buffer=0p%p, *start=0p%p, offset=%d, length=%d\n",
		    buffer,
		    *start,
		    (int)offset,
		    length);

	spin_lock_bh(&tdb_lock);
	
	for (i = 0; i < SADB_HASHMOD; i++) {
		for (sa_p = ipsec_sadb_hash[i];
		     sa_p != NULL;
		     sa_p = sa_p->ips_hnext)
		{
			atomic_inc(&sa_p->ips_refcount);
			if(sa_p->ips_inext == NULL) {
				sa_p2 = sa_p;
				while(sa_p2 != NULL) {
					atomic_inc(&sa_p2->ips_refcount);
					sa_len = satoa(sa_p2->ips_said,
						       0, sa, SATOA_BUF);
					
					len += ipsec_snprintf(buffer+len, length-len, "%s ",
						       sa_len ? sa : " (error)");
					atomic_dec(&sa_p2->ips_refcount);
					sa_p2 = sa_p2->ips_onext;
				}
				len += ipsec_snprintf(buffer+len, length-len, "\n");
			}

			atomic_dec(&sa_p->ips_refcount);

			if (len >= max_content) {
				/* we've done all that can fit -- stop loops */
				len = max_content;      /* truncate crap */
				goto done_spigrp_i;
			} else {
				const off_t pos = begin + len;

				if (pos <= offset) {
					/* all is before first interesting character:
					* discard, but note where we are.
					*/
					len = 0;
					begin = pos;
				}
			}
		}
	}

 done_spigrp_i:	
	spin_unlock_bh(&tdb_lock);

	*start = buffer + (offset - begin);	/* Start of wanted data */
	return len - (offset - begin);
}

IPSEC_PROCFS_DEBUG_NO_STATIC
int
ipsec_tncfg_get_info(char *buffer,
		     char **start,
		     off_t offset,
		     int length     IPSEC_PROC_LAST_ARG)
{
	/* limit of useful snprintf output */
	const int max_content = length > 0? length-1 : 0;

	int len = 0;
	off_t begin = 0;
	int i;
	char name[9];
	struct device *dev, *privdev;
	struct ipsecpriv *priv;

	KLIPS_PRINT(debug_tunnel & DB_TN_PROCFS,
		    "klips_debug:ipsec_tncfg_get_info: "
		    "buffer=0p%p, *start=0p%p, offset=%d, length=%d\n",
		    buffer,
		    *start,
		    (int)offset,
		    length);

	for(i = 0; i < IPSEC_NUM_IF; i++) {
		ipsec_snprintf(name, (ssize_t) sizeof(name), IPSEC_DEV_FORMAT, i);
		dev = __ipsec_dev_get(name);
		if(dev) {
			priv = (struct ipsecpriv *)(dev->priv);
			len += ipsec_snprintf(buffer+len, length-len, "%s",
				       dev->name);
			if(priv) {
				privdev = (struct device *)(priv->dev);
				len += ipsec_snprintf(buffer+len, length-len, " -> %s",
					       privdev ? privdev->name : "NULL");
				len += ipsec_snprintf(buffer+len, length-len, " mtu=%d(%d) -> %d",
					       dev->mtu,
					       priv->mtu,
					       privdev ? privdev->mtu : 0);
			} else {
				KLIPS_PRINT(debug_tunnel & DB_TN_PROCFS,
					    "klips_debug:ipsec_tncfg_get_info: device '%s' has no private data space!\n",
					    dev->name);
			}
			len += ipsec_snprintf(buffer+len, length-len, "\n");

			if (len >= max_content) {
				/* we've done all that can fit -- stop loop */
				len = max_content;      /* truncate crap */
				break;
			} else {
				const off_t pos = begin + len;
				if (pos <= offset) {
					len = 0;
					begin = pos;
				}
			}
		}
	}
	*start = buffer + (offset - begin);	/* Start of wanted data */
	len -= (offset - begin);			/* Start slop */
	if (len > length)
		len = length;
	return len;
}

IPSEC_PROCFS_DEBUG_NO_STATIC
int
ipsec_version_get_info(char *buffer,
		       char **start,
		       off_t offset,
		       int length  IPSEC_PROC_LAST_ARG)
{
	int len = 0;
	off_t begin = 0;

	KLIPS_PRINT(debug_tunnel & DB_TN_PROCFS,
		    "klips_debug:ipsec_version_get_info: "
		    "buffer=0p%p, *start=0p%p, offset=%d, length=%d\n",
		    buffer,
		    *start,
		    (int)offset,
		    length);

	len += ipsec_snprintf(buffer+len, length-len, "strongSwan version: %s\n",
		       ipsec_version_code());
#if 0
	KLIPS_PRINT(debug_tunnel & DB_TN_PROCFS,
		    "klips_debug:ipsec_version_get_info: "
		    "ipsec_init version: %s\n",
		    ipsec_init_c_version);
	KLIPS_PRINT(debug_tunnel & DB_TN_PROCFS,
		    "klips_debug:ipsec_version_get_info: "
		    "ipsec_tunnel version: %s\n",
		    ipsec_tunnel_c_version);
	KLIPS_PRINT(debug_tunnel & DB_TN_PROCFS,
		    "klips_debug:ipsec_version_get_info: "
		    "ipsec_netlink version: %s\n",
		    ipsec_netlink_c_version);
	KLIPS_PRINT(debug_tunnel & DB_TN_PROCFS,
		    "klips_debug:ipsec_version_get_info: "
		    "radij_c_version: %s\n",
		    radij_c_version);
#endif

	*start = buffer + (offset - begin);	/* Start of wanted data */
	len -= (offset - begin);			/* Start slop */
	if (len > length)
		len = length;
	return len;
}

IPSEC_PROCFS_DEBUG_NO_STATIC
int
ipsec_birth_info(char *page,
		 char **start,
		 off_t offset,
		 int count,
		 int *eof,
		 void *data)
{
	struct ipsec_birth_reply *ibr = (struct ipsec_birth_reply *)data;
	int len;

	if(offset >= ibr->packet_template_len) {
		if(eof) {
			*eof=1;
		}
		return 0;
	}

	len = ibr->packet_template_len;
	len -= offset;
	if (len > count)
		len = count;

	memcpy(page + offset, ibr->packet_template+offset, len);

	return len;
}

IPSEC_PROCFS_DEBUG_NO_STATIC
int
ipsec_birth_set(struct file *file, const char *buffer,
		unsigned long count, void *data)
{
	struct ipsec_birth_reply *ibr = (struct ipsec_birth_reply *)data;
	int len;

	MOD_INC_USE_COUNT;
        if(count > IPSEC_BIRTH_TEMPLATE_MAXLEN) {
                len = IPSEC_BIRTH_TEMPLATE_MAXLEN;
	} else {
                len = count;
	}

        if(copy_from_user(ibr->packet_template, buffer, len)) {
                MOD_DEC_USE_COUNT;
                return -EFAULT;
        }
	ibr->packet_template_len = len;

        MOD_DEC_USE_COUNT;

        return len;
}


#ifdef CONFIG_IPSEC_DEBUG
IPSEC_PROCFS_DEBUG_NO_STATIC
int
ipsec_klipsdebug_get_info(char *buffer,
			  char **start,
			  off_t offset,
			  int length      IPSEC_PROC_LAST_ARG)
{
	int len = 0;
	off_t begin = 0;

	KLIPS_PRINT(debug_tunnel & DB_TN_PROCFS,
		    "klips_debug:ipsec_klipsdebug_get_info: "
		    "buffer=0p%p, *start=0p%p, offset=%d, length=%d\n",
		    buffer,
		    *start,
		    (int)offset,
		    length);

	len += ipsec_snprintf(buffer+len, length-len, "debug_tunnel=%08x.\n", debug_tunnel);
	len += ipsec_snprintf(buffer+len, length-len, "debug_xform=%08x.\n", debug_xform);
	len += ipsec_snprintf(buffer+len, length-len, "debug_eroute=%08x.\n", debug_eroute);
	len += ipsec_snprintf(buffer+len, length-len, "debug_spi=%08x.\n", debug_spi);
	len += ipsec_snprintf(buffer+len, length-len, "debug_radij=%08x.\n", debug_radij);
	len += ipsec_snprintf(buffer+len, length-len, "debug_esp=%08x.\n", debug_esp);
	len += ipsec_snprintf(buffer+len, length-len, "debug_ah=%08x.\n", debug_ah);
	len += ipsec_snprintf(buffer+len, length-len, "debug_rcv=%08x.\n", debug_rcv);
	len += ipsec_snprintf(buffer+len, length-len, "debug_pfkey=%08x.\n", debug_pfkey);

	*start = buffer + (offset - begin);	/* Start of wanted data */
	len -= (offset - begin);			/* Start slop */
	if (len > length)
		len = length;
	return len;
}
#endif /* CONFIG_IPSEC_DEBUG */

IPSEC_PROCFS_DEBUG_NO_STATIC
int
ipsec_stats_get_int_info(char *buffer,
			 char **start,
			 off_t offset,
			 int length,
			 int *eof,
			 void *data)
{
	/* Limit of useful snprintf output */
	const int max_content = length > 0? length-1 : 0;
	
	int len = 0;
	int *thing;

	thing = (int *)data;
	
	len = ipsec_snprintf(buffer+len, length-len, "%08x\n", *thing);

	if (len >= max_content)
               len = max_content;      /* truncate crap */

        *start = buffer + offset;       /* Start of wanted data */
        return len > offset? len - offset : 0;
}

#ifndef PROC_FS_2325
struct proc_dir_entry ipsec_eroute =
{
	0,
	12, "ipsec_eroute",
	S_IFREG | S_IRUGO, 1, 0, 0, 0,
	&proc_net_inode_operations,
	ipsec_eroute_get_info,
	NULL, NULL, NULL, NULL, NULL
};

struct proc_dir_entry ipsec_spi =
{
	0,
	9, "ipsec_spi",
	S_IFREG | S_IRUGO, 1, 0, 0, 0,
	&proc_net_inode_operations,
	ipsec_spi_get_info,
	NULL, NULL, NULL, NULL, NULL
};

struct proc_dir_entry ipsec_spigrp =
{
	0,
	12, "ipsec_spigrp",
	S_IFREG | S_IRUGO, 1, 0, 0, 0,
	&proc_net_inode_operations,
	ipsec_spigrp_get_info,
	NULL, NULL, NULL, NULL, NULL
};

struct proc_dir_entry ipsec_tncfg =
{
	0,
	11, "ipsec_tncfg",
	S_IFREG | S_IRUGO, 1, 0, 0, 0,
	&proc_net_inode_operations,
	ipsec_tncfg_get_info,
	NULL, NULL, NULL, NULL, NULL
};

struct proc_dir_entry ipsec_version =
{
	0,
	13, "ipsec_version",
	S_IFREG | S_IRUGO, 1, 0, 0, 0,
	&proc_net_inode_operations,
	ipsec_version_get_info,
	NULL, NULL, NULL, NULL, NULL
};

#ifdef CONFIG_IPSEC_DEBUG
struct proc_dir_entry ipsec_klipsdebug =
{
	0,
	16, "ipsec_klipsdebug",
	S_IFREG | S_IRUGO, 1, 0, 0, 0,
	&proc_net_inode_operations,
	ipsec_klipsdebug_get_info,
	NULL, NULL, NULL, NULL, NULL
};
#endif /* CONFIG_IPSEC_DEBUG */
#endif /* !PROC_FS_2325 */
#endif /* CONFIG_PROC_FS */

#if defined(PROC_FS_2325) 
struct ipsec_proc_list {
	char                   *name;
	struct proc_dir_entry **parent;
	struct proc_dir_entry **dir;
	read_proc_t            *readthing;
	write_proc_t           *writething;
	void                   *data;
};
static struct ipsec_proc_list proc_items[]={
#ifdef CONFIG_IPSEC_DEBUG
	{"klipsdebug", &proc_net_ipsec_dir, NULL,             ipsec_klipsdebug_get_info, NULL, NULL},
#endif
	{"eroute",     &proc_net_ipsec_dir, &proc_eroute_dir, NULL, NULL, NULL},
	{"all",        &proc_eroute_dir,    NULL,             ipsec_eroute_get_info,     NULL, NULL},
	{"spi",        &proc_net_ipsec_dir, &proc_spi_dir,    NULL, NULL, NULL},
	{"all",        &proc_spi_dir,       NULL,             ipsec_spi_get_info,        NULL, NULL},
	{"spigrp",     &proc_net_ipsec_dir, &proc_spigrp_dir, NULL, NULL, NULL},
	{"all",        &proc_spigrp_dir,    NULL,             ipsec_spigrp_get_info,     NULL, NULL},
	{"birth",      &proc_net_ipsec_dir, &proc_birth_dir,  NULL,      NULL, NULL},
	{"ipv4",       &proc_birth_dir,     NULL,             ipsec_birth_info, ipsec_birth_set, (void *)&ipsec_ipv4_birth_packet},
	{"ipv6",       &proc_birth_dir,     NULL,             ipsec_birth_info, ipsec_birth_set, (void *)&ipsec_ipv6_birth_packet},
	{"xforms",     &proc_net_ipsec_dir, NULL,             ipsec_xform_get_info,      NULL, NULL},
	{"tncfg",      &proc_net_ipsec_dir, NULL,             ipsec_tncfg_get_info,      NULL, NULL},
	{"stats",      &proc_net_ipsec_dir, &proc_stats_dir,  NULL,      NULL, NULL},
	{"trap_count", &proc_stats_dir,     NULL,             ipsec_stats_get_int_info, NULL, &ipsec_xmit_trap_count},
	{"trap_sendcount", &proc_stats_dir, NULL,             ipsec_stats_get_int_info, NULL, &ipsec_xmit_trap_sendcount},
	{"version",    &proc_net_ipsec_dir, NULL,             ipsec_version_get_info,    NULL, NULL},
	{NULL,         NULL,                NULL,             NULL,      NULL, NULL}
};
#endif
		
int
ipsec_proc_init()
{
	int error = 0;
#ifdef IPSEC_PROC_SUBDIRS
	struct proc_dir_entry *item;
#endif

	/*
	 * just complain because pluto won't run without /proc!
	 */
#ifndef CONFIG_PROC_FS 
#error You must have PROC_FS built in to use KLIPS
#endif

        /* for 2.0 kernels */
#if !defined(PROC_FS_2325) && !defined(PROC_FS_21)
	error |= proc_register_dynamic(&proc_net, &ipsec_eroute);
	error |= proc_register_dynamic(&proc_net, &ipsec_spi);
	error |= proc_register_dynamic(&proc_net, &ipsec_spigrp);
	error |= proc_register_dynamic(&proc_net, &ipsec_tncfg);
	error |= proc_register_dynamic(&proc_net, &ipsec_version);
#ifdef CONFIG_IPSEC_DEBUG
	error |= proc_register_dynamic(&proc_net, &ipsec_klipsdebug);
#endif /* CONFIG_IPSEC_DEBUG */
#endif

	/* for 2.2 kernels */
#if !defined(PROC_FS_2325) && defined(PROC_FS_21)
	error |= proc_register(proc_net, &ipsec_eroute);
	error |= proc_register(proc_net, &ipsec_spi);
	error |= proc_register(proc_net, &ipsec_spigrp);
	error |= proc_register(proc_net, &ipsec_tncfg);
	error |= proc_register(proc_net, &ipsec_version);
#ifdef CONFIG_IPSEC_DEBUG
	error |= proc_register(proc_net, &ipsec_klipsdebug);
#endif /* CONFIG_IPSEC_DEBUG */
#endif

	/* for 2.4 kernels */
#if defined(PROC_FS_2325)
	/* create /proc/net/ipsec */

	/* zero these out before we initialize /proc/net/ipsec/birth/stuff */
	memset(&ipsec_ipv4_birth_packet, 0, sizeof(struct ipsec_birth_reply));
	memset(&ipsec_ipv6_birth_packet, 0, sizeof(struct ipsec_birth_reply));

	proc_net_ipsec_dir = proc_mkdir("ipsec", proc_net);
	if(proc_net_ipsec_dir == NULL) {
		/* no point in continuing */
		return 1;
	} 	

	{
		struct ipsec_proc_list *it;

		it=proc_items;
		while(it->name!=NULL) {
			if(it->dir) {
				/* make a dir instead */
				item = proc_mkdir(it->name, *it->parent);
				*it->dir = item;
			} else {
				item = create_proc_entry(it->name, 0400, *it->parent);
			}
			if(item) {
				item->read_proc  = it->readthing;
				item->write_proc = it->writething;
				item->data       = it->data;
#ifdef MODULE
				item->owner = THIS_MODULE;
#endif
			} else {
				error |= 1;
			}
			it++;
		}
	}
	
	/* now create some symlinks to provide compatibility */
	proc_symlink("ipsec_eroute", proc_net, "ipsec/eroute/all");
	proc_symlink("ipsec_spi",    proc_net, "ipsec/spi/all");
	proc_symlink("ipsec_spigrp", proc_net, "ipsec/spigrp/all");
	proc_symlink("ipsec_tncfg",  proc_net, "ipsec/tncfg");
	proc_symlink("ipsec_version",proc_net, "ipsec/version");
	proc_symlink("ipsec_klipsdebug",proc_net,"ipsec/klipsdebug");

#endif /* !PROC_FS_2325 */

	return error;
}

void
ipsec_proc_cleanup()
{

	/* for 2.0 and 2.2 kernels */
#if !defined(PROC_FS_2325) 

#ifdef CONFIG_IPSEC_DEBUG
	if (proc_net_unregister(ipsec_klipsdebug.low_ino) != 0)
		printk("klips_debug:ipsec_cleanup: "
		       "cannot unregister /proc/net/ipsec_klipsdebug\n");
#endif /* CONFIG_IPSEC_DEBUG */

	if (proc_net_unregister(ipsec_version.low_ino) != 0)
		printk("klips_debug:ipsec_cleanup: "
		       "cannot unregister /proc/net/ipsec_version\n");
	if (proc_net_unregister(ipsec_eroute.low_ino) != 0)
		printk("klips_debug:ipsec_cleanup: "
		       "cannot unregister /proc/net/ipsec_eroute\n");
	if (proc_net_unregister(ipsec_spi.low_ino) != 0)
		printk("klips_debug:ipsec_cleanup: "
		       "cannot unregister /proc/net/ipsec_spi\n");
	if (proc_net_unregister(ipsec_spigrp.low_ino) != 0)
		printk("klips_debug:ipsec_cleanup: "
		       "cannot unregister /proc/net/ipsec_spigrp\n");
	if (proc_net_unregister(ipsec_tncfg.low_ino) != 0)
		printk("klips_debug:ipsec_cleanup: "
		       "cannot unregister /proc/net/ipsec_tncfg\n");
#endif

	/* for 2.4 kernels */
#if defined(PROC_FS_2325)
	{
		struct ipsec_proc_list *it;

		/* find end of list */
		it=proc_items;
		while(it->name!=NULL) {
			it++;
		}
		it--;

		do {
			remove_proc_entry(it->name, *it->parent);
			it--;
		} while(it > proc_items);
	}


#ifdef CONFIG_IPSEC_DEBUG
	remove_proc_entry("ipsec_klipsdebug", proc_net);
#endif /* CONFIG_IPSEC_DEBUG */
	remove_proc_entry("ipsec_eroute",     proc_net);
	remove_proc_entry("ipsec_spi",        proc_net);
	remove_proc_entry("ipsec_spigrp",     proc_net);
	remove_proc_entry("ipsec_tncfg",      proc_net);
	remove_proc_entry("ipsec_version",    proc_net);
	remove_proc_entry("ipsec",            proc_net);
#endif /* 2.4 kernel */
}


