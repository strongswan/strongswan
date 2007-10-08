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
 *
 * RCSID $Id$
 *
 */

/* 
 * This file provides a set of #define's which may be tuned by various
 * people/configurations. It keeps all compile-time tunables in one place.
 *
 * This file should be included before all other IPsec kernel-only files.
 *
 */

#ifndef _IPSEC_PARAM_H_

#ifdef __KERNEL__
#include "ipsec_kversion.h"

/* Set number of ipsecX virtual devices here. */
/* This must be < exp(field width of IPSEC_DEV_FORMAT) */
/* It must also be reasonable so as not to overload the memory and CPU */
/* constraints of the host. */
#define IPSEC_NUM_IF	4
/* The field width must be < IF_NAM_SIZ - strlen("ipsec") - 1. */
/* With "ipsec" being 5 characters, that means 10 is the max field width */
/* but machine memory and CPU constraints are not likely to tollerate */
/* more than 3 digits.  The default is one digit. */
/* Update: userland scripts get upset if they can't find "ipsec0", so */
/* for now, no "0"-padding should be used (which would have been helpful */
/* to make text-searches work */
#define IPSEC_DEV_FORMAT "ipsec%d"
/* For, say, 500 virtual ipsec devices, I would recommend: */
/* #define IPSEC_NUM_IF	500 */
/* #define IPSEC_DEV_FORMAT "ipsec%03d" */
/* Note that the "interfaces=" line in /etc/ipsec.conf would be, um, challenging. */

/* use dynamic ipsecX device allocation */
#ifndef CONFIG_IPSEC_DYNDEV
#define CONFIG_IPSEC_DYNDEV 1
#endif /* CONFIG_IPSEC_DYNDEV */


#ifdef CONFIG_IPSEC_BIGGATE
# define SADB_HASHMOD   8069
#else /* CONFIG_IPSEC_BIGGATE */
# define SADB_HASHMOD	257
#endif /* CONFIG_IPSEC_BIGGATE */
#endif /* __KERNEL__ */

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

#ifdef __KERNEL__
/* This is defined for 2.4, but not 2.2.... */
#ifndef ARPHRD_VOID
# define ARPHRD_VOID 0xFFFF
#endif

/*
 * Worry about PROC_FS stuff
 */
#if defined(PROC_FS_2325)
/* kernel 2.4 */
# define IPSEC_PROC_LAST_ARG ,int *eof,void *data
# define IPSEC_PROCFS_DEBUG_NO_STATIC
# define IPSEC_PROC_SUBDIRS
#else
/* kernel <2.4 */
# define IPSEC_PROCFS_DEBUG_NO_STATIC DEBUG_NO_STATIC

# ifndef PROC_NO_DUMMY
#  define IPSEC_PROC_LAST_ARG , int dummy
# else
#  define IPSEC_PROC_LAST_ARG
# endif /* !PROC_NO_DUMMY */
#endif /* PROC_FS_2325 */

#if !defined(LINUX_KERNEL_HAS_SNPRINTF)
/* GNU CPP specific! */
# define snprintf(buf, len, fmt...) sprintf(buf, ##fmt)
#endif /* !LINUX_KERNEL_HAS_SNPRINTF */

#ifdef SPINLOCK
# ifdef SPINLOCK_23
#  include <linux/spinlock.h> /* *lock* */
# else /* SPINLOCK_23 */
#  include <asm/spinlock.h> /* *lock* */
# endif /* SPINLOCK_23 */
#endif /* SPINLOCK */

#ifndef KLIPS_FIXES_DES_PARITY
# define KLIPS_FIXES_DES_PARITY 1
#endif /* !KLIPS_FIXES_DES_PARITY */

/* we don't really want to print these unless there are really big problems */
#ifndef KLIPS_DIVULGE_CYPHER_KEY
# define KLIPS_DIVULGE_CYPHER_KEY 0
#endif /* !KLIPS_DIVULGE_CYPHER_KEY */

#ifndef KLIPS_DIVULGE_HMAC_KEY
# define KLIPS_DIVULGE_HMAC_KEY 0
#endif /* !KLIPS_DIVULGE_HMAC_KEY */

#ifndef IPSEC_DISALLOW_IPOPTIONS
# define IPSEC_DISALLOW_IPOPTIONS 1
#endif /* !KLIPS_DIVULGE_HMAC_KEY */

/* extra toggles for regression testing */
#ifdef CONFIG_IPSEC_REGRESS

/* 
 * should pfkey_acquire() become 100% lossy?
 *
 */
extern int sysctl_ipsec_regress_pfkey_lossage;
#ifndef KLIPS_PFKEY_ACQUIRE_LOSSAGE
# ifdef CONFIG_IPSEC_PFKEY_ACQUIRE_LOSSAGE
#  define KLIPS_PFKEY_ACQUIRE_LOSSAGE 100
# else /* CONFIG_IPSEC_PFKEY_ACQUIRE_LOSSAGE */
/* not by default! */
#  define KLIPS_PFKEY_ACQUIRE_LOSSAGE 0
# endif /* CONFIG_IPSEC_PFKEY_ACQUIRE_LOSSAGE */
#endif /* KLIPS_PFKEY_ACQUIRE_LOSSAGE */

#endif /* CONFIG_IPSEC_REGRESS */

/*
 * debugging routines.
 */
#ifdef CONFIG_IPSEC_DEBUG
extern void ipsec_print_ip(struct iphdr *ip);

	#define KLIPS_PRINT(flag, format, args...) \
		((flag) ? printk(KERN_INFO format , ## args) : 0)
	#define KLIPS_PRINTMORE(flag, format, args...) \
		((flag) ? printk(format , ## args) : 0)
	#define KLIPS_IP_PRINT(flag, ip) \
		((flag) ? ipsec_print_ip(ip) : 0)
#else /* CONFIG_IPSEC_DEBUG */
	#define KLIPS_PRINT(flag, format, args...) do ; while(0)
	#define KLIPS_PRINTMORE(flag, format, args...) do ; while(0)
	#define KLIPS_IP_PRINT(flag, ip) do ; while(0)
#endif /* CONFIG_IPSEC_DEBUG */


/* 
 * Stupid kernel API differences in APIs. Not only do some
 * kernels not have ip_select_ident, but some have differing APIs,
 * and SuSE has one with one parameter, but no way of checking to
 * see what is really what.
 */

#ifdef SUSE_LINUX_2_4_19_IS_STUPID
#define KLIPS_IP_SELECT_IDENT(iph, skb) ip_select_ident(iph)
#else

/* simplest case, nothing */
#if !defined(IP_SELECT_IDENT)
#define KLIPS_IP_SELECT_IDENT(iph, skb)  do { iph->id = htons(ip_id_count++); } while(0)
#endif

/* kernels > 2.3.37-ish */
#if defined(IP_SELECT_IDENT) && !defined(IP_SELECT_IDENT_NEW)
#define KLIPS_IP_SELECT_IDENT(iph, skb) ip_select_ident(iph, skb->dst)
#endif

/* kernels > 2.4.2 */
#if defined(IP_SELECT_IDENT) && defined(IP_SELECT_IDENT_NEW)
#define KLIPS_IP_SELECT_IDENT(iph, skb) ip_select_ident(iph, skb->dst, NULL)
#endif

#endif /* SUSE_LINUX_2_4_19_IS_STUPID */

/*
 * make klips fail test:east-espiv-01.
 * exploit is at testing/attacks/espiv
 *
 */
#define KLIPS_IMPAIRMENT_ESPIV_CBC_ATTACK 0


/* IP_FRAGMENT_LINEARIZE is set in freeswan.h if Kernel > 2.4.4 */
#ifndef IP_FRAGMENT_LINEARIZE
# define IP_FRAGMENT_LINEARIZE 0
#endif /* IP_FRAGMENT_LINEARIZE */
#endif /* __KERNEL__ */

#define _IPSEC_PARAM_H_
#endif /* _IPSEC_PARAM_H_ */
