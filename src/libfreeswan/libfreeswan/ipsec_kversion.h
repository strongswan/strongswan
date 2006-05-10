#ifndef _FREESWAN_KVERSIONS_H
/*
 * header file for FreeS/WAN library functions
 * Copyright (C) 1998, 1999, 2000  Henry Spencer.
 * Copyright (C) 1999, 2000, 2001  Richard Guy Briggs
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/lgpl.txt>.
 * 
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Library General Public
 * License for more details.
 *
 * RCSID $Id: ipsec_kversion.h,v 1.1 2004/03/15 20:35:25 as Exp $
 */
#define	_FREESWAN_KVERSIONS_H	/* seen it, no need to see it again */

/*
 * this file contains a series of atomic defines that depend upon
 * kernel version numbers. The kernel versions are arranged
 * in version-order number (which is often not chronological)
 * and each clause enables or disables a feature.
 */

/*
 * First, assorted kernel-version-dependent trickery.
 */
#include <linux/version.h>
#ifndef KERNEL_VERSION
#define KERNEL_VERSION(x,y,z) (((x)<<16)+((y)<<8)+(z))
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,1,0)
#define HEADER_CACHE_BIND_21
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,1,0)
#define SPINLOCK
#define PROC_FS_21
#define NETLINK_SOCK
#define NET_21
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,1,19)
#define net_device_stats enet_statistics
#endif                                                                         

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,0)
#define SPINLOCK_23
#define NETDEV_23
#  ifndef CONFIG_IP_ALIAS
#  define CONFIG_IP_ALIAS
#  endif
#include <linux/socket.h>
#include <linux/skbuff.h>
#include <linux/netlink.h>
#  ifdef NETLINK_XFRM
#  define NETDEV_25
#  endif
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,25)
#define PROC_FS_2325
#undef  PROC_FS_21
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,30)
#define PROC_NO_DUMMY
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,35)
#define SKB_COPY_EXPAND
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,37)
#define IP_SELECT_IDENT
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,50)) && defined(CONFIG_NETFILTER)
#define SKB_RESET_NFCT
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,2)
#define IP_SELECT_IDENT_NEW
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,4)
#define IPH_is_SKB_PULLED
#define SKB_COW_NEW
#define PROTO_HANDLER_SINGLE_PARM
#define IP_FRAGMENT_LINEARIZE 1
#else /* LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,4) */
#  ifdef REDHAT_BOGOSITY
#  define IP_SELECT_IDENT_NEW
#  define IPH_is_SKB_PULLED
#  define SKB_COW_NEW
#  define PROTO_HANDLER_SINGLE_PARM
#  endif /* REDHAT_BOGOSITY */
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,4) */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,9)
#define MALLOC_SLAB
#define LINUX_KERNEL_HAS_SNPRINTF
#endif                                                                         

#ifdef NET_21
#  include <linux/in6.h>
#else
     /* old kernel in.h has some IPv6 stuff, but not quite enough */
#  define	s6_addr16	s6_addr
#  define	AF_INET6	10
#  define uint8_t __u8
#  define uint16_t __u16 
#  define uint32_t __u32 
#  define uint64_t __u64 
#endif

#ifdef NET_21
# define ipsec_kfree_skb(a) kfree_skb(a)
#else /* NET_21 */
# define ipsec_kfree_skb(a) kfree_skb(a, FREE_WRITE)
#endif /* NET_21 */

#ifdef NETDEV_23
# define device net_device
# define ipsec_dev_get dev_get_by_name
# define __ipsec_dev_get __dev_get_by_name
# define ipsec_dev_put(x) dev_put(x)
# define __ipsec_dev_put(x) __dev_put(x)
# define ipsec_dev_hold(x) dev_hold(x)
#else /* NETDEV_23 */
# define ipsec_dev_get dev_get
# define __ipsec_dev_put(x) 
# define ipsec_dev_put(x)
# define ipsec_dev_hold(x) 
#endif /* NETDEV_23 */

#ifndef SPINLOCK
#  include <linux/bios32.h>
     /* simulate spin locks and read/write locks */
     typedef struct {
       volatile char lock;
     } spinlock_t;

     typedef struct {
       volatile unsigned int lock;
     } rwlock_t;                                                                     

#  define spin_lock_init(x) { (x)->lock = 0;}
#  define rw_lock_init(x) { (x)->lock = 0; }

#  define spin_lock(x) { while ((x)->lock) barrier(); (x)->lock=1;}
#  define spin_lock_irq(x) { cli(); spin_lock(x);}
#  define spin_lock_irqsave(x,flags) { save_flags(flags); spin_lock_irq(x);}

#  define spin_unlock(x) { (x)->lock=0;}
#  define spin_unlock_irq(x) { spin_unlock(x); sti();}
#  define spin_unlock_irqrestore(x,flags) { spin_unlock(x); restore_flags(flags);}

#  define read_lock(x) spin_lock(x)
#  define read_lock_irq(x) spin_lock_irq(x)
#  define read_lock_irqsave(x,flags) spin_lock_irqsave(x,flags)

#  define read_unlock(x) spin_unlock(x)
#  define read_unlock_irq(x) spin_unlock_irq(x)
#  define read_unlock_irqrestore(x,flags) spin_unlock_irqrestore(x,flags)

#  define write_lock(x) spin_lock(x)
#  define write_lock_irq(x) spin_lock_irq(x)
#  define write_lock_irqsave(x,flags) spin_lock_irqsave(x,flags)

#  define write_unlock(x) spin_unlock(x)
#  define write_unlock_irq(x) spin_unlock_irq(x)
#  define write_unlock_irqrestore(x,flags) spin_unlock_irqrestore(x,flags)
#endif /* !SPINLOCK */

#ifndef SPINLOCK_23
#  define spin_lock_bh(x)  spin_lock_irq(x)
#  define spin_unlock_bh(x)  spin_unlock_irq(x)

#  define read_lock_bh(x)  read_lock_irq(x)
#  define read_unlock_bh(x)  read_unlock_irq(x)

#  define write_lock_bh(x)  write_lock_irq(x)
#  define write_unlock_bh(x)  write_unlock_irq(x)
#endif /* !SPINLOCK_23 */

#endif /* _FREESWAN_KVERSIONS_H */

/*
 * $Log: ipsec_kversion.h,v $
 * Revision 1.1  2004/03/15 20:35:25  as
 * added files from freeswan-2.04-x509-1.5.3
 *
 * Revision 1.7  2003/07/31 22:48:08  mcr
 * 	derive NET25-ness from presence of NETLINK_XFRM macro.
 *
 * Revision 1.6  2003/06/24 20:22:32  mcr
 * 	added new global: ipsecdevices[] so that we can keep track of
 * 	the ipsecX devices. They will be referenced with dev_hold(),
 * 	so 2.2 may need this as well.
 *
 * Revision 1.5  2003/04/03 17:38:09  rgb
 * Centralised ipsec_kfree_skb and ipsec_dev_{get,put}.
 *
 * Revision 1.4  2002/04/24 07:36:46  mcr
 * Moved from ./klips/net/ipsec/ipsec_kversion.h,v
 *
 * Revision 1.3  2002/04/12 03:21:17  mcr
 * 	three parameter version of ip_select_ident appears first
 * 	in 2.4.2 (RH7.1) not 2.4.4.
 *
 * Revision 1.2  2002/03/08 21:35:22  rgb
 * Defined LINUX_KERNEL_HAS_SNPRINTF to shut up compiler warnings after
 * 2.4.9.  (Andreas Piesk).
 *
 * Revision 1.1  2002/01/29 02:11:42  mcr
 * 	removal of kversions.h - sources that needed it now use ipsec_param.h.
 * 	updating of IPv6 structures to match latest in6.h version.
 * 	removed dead code from freeswan.h that also duplicated kversions.h
 * 	code.
 *
 *
 */
