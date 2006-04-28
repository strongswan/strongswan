/*
 * Common routines for IPsec SA maintenance routines.
 *
 * Copyright (C) 1996, 1997  John Ioannidis.
 * Copyright (C) 1998, 1999, 2000, 2001, 2002  Richard Guy Briggs.
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
 * RCSID $Id: ipsec_sa.c,v 1.3 2004/06/13 19:57:50 as Exp $
 *
 * This is the file formerly known as "ipsec_xform.h"
 *
 */

#include <linux/config.h>
#include <linux/version.h>
#include <linux/kernel.h> /* printk() */

#include "freeswan/ipsec_param.h"

#ifdef MALLOC_SLAB
# include <linux/slab.h> /* kmalloc() */
#else /* MALLOC_SLAB */
# include <linux/malloc.h> /* kmalloc() */
#endif /* MALLOC_SLAB */
#include <linux/vmalloc.h> /* vmalloc() */
#include <linux/errno.h>  /* error codes */
#include <linux/types.h>  /* size_t */
#include <linux/interrupt.h> /* mark_bh */

#include <linux/netdevice.h>   /* struct device, and other headers */
#include <linux/etherdevice.h> /* eth_type_trans */
#include <linux/ip.h>          /* struct iphdr */
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
#endif
#include <asm/checksum.h>
#include <net/ip.h>

#include "freeswan/radij.h"

#include "freeswan/ipsec_stats.h"
#include "freeswan/ipsec_life.h"
#include "freeswan/ipsec_sa.h"
#include "freeswan/ipsec_xform.h"

#include "freeswan/ipsec_encap.h"
#include "freeswan/ipsec_radij.h"
#include "freeswan/ipsec_xform.h"
#include "freeswan/ipsec_ipe4.h"
#include "freeswan/ipsec_ah.h"
#include "freeswan/ipsec_esp.h"

#include <pfkeyv2.h>
#include <pfkey.h>

#include "freeswan/ipsec_proto.h"
#include "freeswan/ipsec_alg.h"


#ifdef CONFIG_IPSEC_DEBUG
int debug_xform = 0;
#endif /* CONFIG_IPSEC_DEBUG */

#define SENDERR(_x) do { error = -(_x); goto errlab; } while (0)

struct ipsec_sa *ipsec_sadb_hash[SADB_HASHMOD];
#ifdef SPINLOCK
spinlock_t tdb_lock = SPIN_LOCK_UNLOCKED;
#else /* SPINLOCK */
spinlock_t tdb_lock;
#endif /* SPINLOCK */

struct ipsec_sadb ipsec_sadb;

#if IPSEC_SA_REF_CODE

/* the sub table must be narrower (or equal) in bits than the variable type
   in the main table to count the number of unused entries in it. */
typedef struct {
	int testSizeOf_refSubTable :
		((sizeof(IPsecRefTableUnusedCount) * 8) < IPSEC_SA_REF_SUBTABLE_IDX_WIDTH ? -1 : 1);
} dummy;


/* The field where the saref will be hosted in the skb must be wide enough to
   accomodate the information it needs to store. */
typedef struct {
	int testSizeOf_refField : 
		(IPSEC_SA_REF_HOST_FIELD_WIDTH < IPSEC_SA_REF_TABLE_IDX_WIDTH ? -1 : 1 );
} dummy2;


void
ipsec_SAtest(void)
{
	IPsecSAref_t SAref = 258;
	struct ipsec_sa ips;
	ips.ips_ref = 772;

	printk("klips_debug:ipsec_SAtest: "
	       "IPSEC_SA_REF_SUBTABLE_IDX_WIDTH=%u\n"
	       "IPSEC_SA_REF_MAINTABLE_NUM_ENTRIES=%u\n"
	       "IPSEC_SA_REF_SUBTABLE_NUM_ENTRIES=%u\n"
	       "IPSEC_SA_REF_HOST_FIELD_WIDTH=%lu\n"
	       "IPSEC_SA_REF_TABLE_MASK=%x\n"
	       "IPSEC_SA_REF_ENTRY_MASK=%x\n"
	       "IPsecSAref2table(%d)=%u\n"
	       "IPsecSAref2entry(%d)=%u\n"
	       "IPsecSAref2NFmark(%d)=%u\n"
	       "IPsecSAref2SA(%d)=%p\n"
	       "IPsecSA2SAref(%p)=%d\n"
	       ,
	       IPSEC_SA_REF_SUBTABLE_IDX_WIDTH,
	       IPSEC_SA_REF_MAINTABLE_NUM_ENTRIES,
	       IPSEC_SA_REF_SUBTABLE_NUM_ENTRIES,
	       (unsigned long) IPSEC_SA_REF_HOST_FIELD_WIDTH,
	       IPSEC_SA_REF_TABLE_MASK,
	       IPSEC_SA_REF_ENTRY_MASK,
	       SAref, IPsecSAref2table(SAref),
	       SAref, IPsecSAref2entry(SAref),
	       SAref, IPsecSAref2NFmark(SAref),
	       SAref, IPsecSAref2SA(SAref),
	       (&ips), IPsecSA2SAref((&ips))
		);
	return;
}

int
ipsec_SAref_recycle(void)
{
	int table;
	int entry;
	int error = 0;

	ipsec_sadb.refFreeListHead = -1;
	ipsec_sadb.refFreeListTail = -1;

	if(ipsec_sadb.refFreeListCont == IPSEC_SA_REF_MAINTABLE_NUM_ENTRIES * IPSEC_SA_REF_SUBTABLE_NUM_ENTRIES) {
		KLIPS_PRINT(debug_xform,
			    "klips_debug:ipsec_SAref_recycle: "
			    "end of table reached, continuing at start..\n");
		ipsec_sadb.refFreeListCont = 0;
	}

	KLIPS_PRINT(debug_xform,
		    "klips_debug:ipsec_SAref_recycle: "
		    "recycling, continuing from SAref=%d (0p%p), table=%d, entry=%d.\n",
		    ipsec_sadb.refFreeListCont,
		    (ipsec_sadb.refTable[IPsecSAref2table(ipsec_sadb.refFreeListCont)] != NULL) ? IPsecSAref2SA(ipsec_sadb.refFreeListCont) : NULL,
		    IPsecSAref2table(ipsec_sadb.refFreeListCont),
		    IPsecSAref2entry(ipsec_sadb.refFreeListCont));

	for(table = IPsecSAref2table(ipsec_sadb.refFreeListCont);
	    table < IPSEC_SA_REF_MAINTABLE_NUM_ENTRIES;
	    table++) {
		if(ipsec_sadb.refTable[table] == NULL) {
			error = ipsec_SArefSubTable_alloc(table);
			if(error) {
				return error;
			}
		}
		for(entry = IPsecSAref2entry(ipsec_sadb.refFreeListCont);
		    entry < IPSEC_SA_REF_SUBTABLE_NUM_ENTRIES;
		    entry++) {
			if(ipsec_sadb.refTable[table]->entry[entry] == NULL) {
				ipsec_sadb.refFreeList[++ipsec_sadb.refFreeListTail] = IPsecSArefBuild(table, entry);
				if(ipsec_sadb.refFreeListTail == (IPSEC_SA_REF_FREELIST_NUM_ENTRIES - 1)) {
					ipsec_sadb.refFreeListHead = 0;
					ipsec_sadb.refFreeListCont = ipsec_sadb.refFreeList[ipsec_sadb.refFreeListTail] + 1;
					KLIPS_PRINT(debug_xform,
						    "klips_debug:ipsec_SAref_recycle: "
						    "SArefFreeList refilled.\n");
					return 0;
				}
			}
		}
	}

	if(ipsec_sadb.refFreeListTail == -1) {
		KLIPS_PRINT(debug_xform,
			    "klips_debug:ipsec_SAref_recycle: "
			    "out of room in the SArefTable.\n");

		return(-ENOSPC);
	}

	ipsec_sadb.refFreeListHead = 0;
	ipsec_sadb.refFreeListCont = ipsec_sadb.refFreeList[ipsec_sadb.refFreeListTail] + 1;
	KLIPS_PRINT(debug_xform,
		    "klips_debug:ipsec_SAref_recycle: "
		    "SArefFreeList partly refilled to %d of %d.\n",
		    ipsec_sadb.refFreeListTail,
		    IPSEC_SA_REF_FREELIST_NUM_ENTRIES);
	return 0;
}

int
ipsec_SArefSubTable_alloc(unsigned table)
{
	unsigned entry;
	struct IPsecSArefSubTable* SArefsub;

	KLIPS_PRINT(debug_xform,
		    "klips_debug:ipsec_SArefSubTable_alloc: "
		    "allocating %lu bytes for table %u of %u.\n",
		    (unsigned long) (IPSEC_SA_REF_SUBTABLE_NUM_ENTRIES * sizeof(struct ipsec_sa *)),
		    table,
		    IPSEC_SA_REF_MAINTABLE_NUM_ENTRIES);

	/* allocate another sub-table */
	SArefsub = vmalloc(IPSEC_SA_REF_SUBTABLE_NUM_ENTRIES * sizeof(struct ipsec_sa *));
	if(SArefsub == NULL) {
		KLIPS_PRINT(debug_xform,
			    "klips_debug:ipsec_SArefSubTable_alloc: "
			    "error allocating memory for table %u of %u!\n",
			    table,
			    IPSEC_SA_REF_MAINTABLE_NUM_ENTRIES);
		return -ENOMEM;
	}

	/* add this sub-table to the main table */
	ipsec_sadb.refTable[table] = SArefsub;

	/* initialise each element to NULL */
	KLIPS_PRINT(debug_xform,
		    "klips_debug:ipsec_SArefSubTable_alloc: "
		    "initialising %u elements (2 ^ %u) of table %u.\n",
		    IPSEC_SA_REF_SUBTABLE_NUM_ENTRIES,
		    IPSEC_SA_REF_SUBTABLE_IDX_WIDTH,
		    table);
	for(entry = 0; entry < IPSEC_SA_REF_SUBTABLE_NUM_ENTRIES; entry++) {
		SArefsub->entry[entry] = NULL;
	}

	return 0;
}
#endif /* IPSEC_SA_REF_CODE */

int
ipsec_saref_freelist_init(void)
{
	int i;

	KLIPS_PRINT(debug_xform,
		    "klips_debug:ipsec_saref_freelist_init: "
		    "initialising %u elements of FreeList.\n",
		    IPSEC_SA_REF_FREELIST_NUM_ENTRIES);

	for(i = 0; i < IPSEC_SA_REF_FREELIST_NUM_ENTRIES; i++) {
		ipsec_sadb.refFreeList[i] = IPSEC_SAREF_NULL;
	}
	ipsec_sadb.refFreeListHead = -1;
	ipsec_sadb.refFreeListCont = 0;
	ipsec_sadb.refFreeListTail = -1;
       
	return 0;
}

int
ipsec_sadb_init(void)
{
	int error = 0;
	unsigned i;

	for(i = 0; i < SADB_HASHMOD; i++) {
		ipsec_sadb_hash[i] = NULL;
	}
	/* parts above are for the old style SADB hash table */
	

#if IPSEC_SA_REF_CODE
	/* initialise SA reference table */

	/* initialise the main table */
	KLIPS_PRINT(debug_xform,
		    "klips_debug:ipsec_sadb_init: "
		    "initialising main table of size %u (2 ^ %u).\n",
		    IPSEC_SA_REF_MAINTABLE_NUM_ENTRIES,
		    IPSEC_SA_REF_MAINTABLE_IDX_WIDTH);
	{
		unsigned table;
		for(table = 0; table < IPSEC_SA_REF_MAINTABLE_NUM_ENTRIES; table++) {
			ipsec_sadb.refTable[table] = NULL;
		}
	}

	/* allocate the first sub-table */
	error = ipsec_SArefSubTable_alloc(0);
	if(error) {
		return error;
	}

	error = ipsec_saref_freelist_init();
#endif /* IPSEC_SA_REF_CODE */
	return error;
}

#if IPSEC_SA_REF_CODE
IPsecSAref_t
ipsec_SAref_alloc(int*error) /* pass in error var by pointer */
{
	IPsecSAref_t SAref;

	KLIPS_PRINT(debug_xform,
		    "klips_debug:ipsec_SAref_alloc: "
		    "SAref requested... head=%d, cont=%d, tail=%d, listsize=%d.\n",
		    ipsec_sadb.refFreeListHead,
		    ipsec_sadb.refFreeListCont,
		    ipsec_sadb.refFreeListTail,
		    IPSEC_SA_REF_FREELIST_NUM_ENTRIES);

	if(ipsec_sadb.refFreeListHead == -1) {
		KLIPS_PRINT(debug_xform,
			    "klips_debug:ipsec_SAref_alloc: "
			    "FreeList empty, recycling...\n");
		*error = ipsec_SAref_recycle();
		if(*error) {
			return IPSEC_SAREF_NULL;
		}
	}

	SAref = ipsec_sadb.refFreeList[ipsec_sadb.refFreeListHead];
	if(SAref == IPSEC_SAREF_NULL) {
		KLIPS_PRINT(debug_xform,
			    "klips_debug:ipsec_SAref_alloc: "
			    "unexpected error, refFreeListHead = %d points to invalid entry.\n",
			    ipsec_sadb.refFreeListHead);
			*error = -ESPIPE;
			return IPSEC_SAREF_NULL;
	}

	KLIPS_PRINT(debug_xform,
		    "klips_debug:ipsec_SAref_alloc: "
		    "allocating SAref=%d, table=%u, entry=%u of %u.\n",
		    SAref,
		    IPsecSAref2table(SAref),
		    IPsecSAref2entry(SAref),
		    IPSEC_SA_REF_MAINTABLE_NUM_ENTRIES * IPSEC_SA_REF_SUBTABLE_NUM_ENTRIES);
	
	ipsec_sadb.refFreeList[ipsec_sadb.refFreeListHead] = IPSEC_SAREF_NULL;
	ipsec_sadb.refFreeListHead++;
	if(ipsec_sadb.refFreeListHead > ipsec_sadb.refFreeListTail) {
		KLIPS_PRINT(debug_xform,
			    "klips_debug:ipsec_SAref_alloc: "
			    "last FreeList entry allocated, resetting list head to empty.\n");
		ipsec_sadb.refFreeListHead = -1;
	}

	return SAref;
}
#endif /* IPSEC_SA_REF_CODE */

int
ipsec_sa_print(struct ipsec_sa *ips)
{
        char sa[SATOA_BUF];
	size_t sa_len;

	printk(KERN_INFO "klips_debug:   SA:");
	if(ips == NULL) {
		printk("NULL\n");
		return -ENOENT;
	}
	printk(" ref=%d", ips->ips_ref);
	printk(" refcount=%d", atomic_read(&ips->ips_refcount));
	if(ips->ips_hnext != NULL) {
		printk(" hnext=0p%p", ips->ips_hnext);
	}
	if(ips->ips_inext != NULL) {
		printk(" inext=0p%p", ips->ips_inext);
	}
	if(ips->ips_onext != NULL) {
		printk(" onext=0p%p", ips->ips_onext);
	}
	sa_len = satoa(ips->ips_said, 0, sa, SATOA_BUF);
	printk(" said=%s", sa_len ? sa : " (error)");
	if(ips->ips_seq) {
		printk(" seq=%u", ips->ips_seq);
	}
	if(ips->ips_pid) {
		printk(" pid=%u", ips->ips_pid);
	}
	if(ips->ips_authalg) {
		printk(" authalg=%u", ips->ips_authalg);
	}
	if(ips->ips_encalg) {
		printk(" encalg=%u", ips->ips_encalg);
	}
	printk(" XFORM=%s%s%s", IPS_XFORM_NAME(ips));
	if(ips->ips_replaywin) {
		printk(" ooowin=%u", ips->ips_replaywin);
	}
	if(ips->ips_flags) {
		printk(" flags=%u", ips->ips_flags);
	}
	if(ips->ips_addr_s) {
		char buf[SUBNETTOA_BUF];
		addrtoa(((struct sockaddr_in*)(ips->ips_addr_s))->sin_addr,
			0, buf, sizeof(buf));
		printk(" src=%s", buf);
	}
	if(ips->ips_addr_d) {
		char buf[SUBNETTOA_BUF];
		addrtoa(((struct sockaddr_in*)(ips->ips_addr_s))->sin_addr,
			0, buf, sizeof(buf));
		printk(" dst=%s", buf);
	}
	if(ips->ips_addr_p) {
		char buf[SUBNETTOA_BUF];
		addrtoa(((struct sockaddr_in*)(ips->ips_addr_p))->sin_addr,
			0, buf, sizeof(buf));
		printk(" proxy=%s", buf);
	}
	if(ips->ips_key_bits_a) {
		printk(" key_bits_a=%u", ips->ips_key_bits_a);
	}
	if(ips->ips_key_bits_e) {
		printk(" key_bits_e=%u", ips->ips_key_bits_e);
	}

	printk("\n");
	return 0;
}

struct ipsec_sa*
ipsec_sa_alloc(int*error) /* pass in error var by pointer */
{
	struct ipsec_sa* ips;

	if((ips = kmalloc(sizeof(*ips), GFP_ATOMIC) ) == NULL) {
		KLIPS_PRINT(debug_xform,
			    "klips_debug:ipsec_sa_alloc: "
			    "memory allocation error\n");
		*error = -ENOMEM;
		return NULL;
	}
	memset((caddr_t)ips, 0, sizeof(*ips));
#if IPSEC_SA_REF_CODE
	ips->ips_ref = ipsec_SAref_alloc(error); /* pass in error return by pointer */
	KLIPS_PRINT(debug_xform,
		    "klips_debug:ipsec_sa_alloc: "
		    "allocated %lu bytes for ipsec_sa struct=0p%p ref=%d.\n",
		    (unsigned long) sizeof(*ips),
		    ips,
		    ips->ips_ref);
	if(ips->ips_ref == IPSEC_SAREF_NULL) {
		kfree(ips);
		KLIPS_PRINT(debug_xform,
			    "klips_debug:ipsec_sa_alloc: "
			    "SAref allocation error\n");
		return NULL;
	}

	atomic_inc(&ips->ips_refcount);
	IPsecSAref2SA(ips->ips_ref) = ips;
#endif /* IPSEC_SA_REF_CODE */

	*error = 0;
	return(ips);
}

int
ipsec_sa_free(struct ipsec_sa* ips)
{
	return ipsec_sa_wipe(ips);
}

struct ipsec_sa *
ipsec_sa_getbyid(struct sa_id *said)
{
	int hashval;
	struct ipsec_sa *ips;
        char sa[SATOA_BUF];
	size_t sa_len;

	if(said == NULL) {
		KLIPS_PRINT(debug_xform,
			    "klips_error:ipsec_sa_getbyid: "
			    "null pointer passed in!\n");
		return NULL;
	}

	sa_len = satoa(*said, 0, sa, SATOA_BUF);

	hashval = (said->spi+said->dst.s_addr+said->proto) % SADB_HASHMOD;
	
	KLIPS_PRINT(debug_xform,
		    "klips_debug:ipsec_sa_getbyid: "
		    "linked entry in ipsec_sa table for hash=%d of SA:%s requested.\n",
		    hashval,
		    sa_len ? sa : " (error)");

	if((ips = ipsec_sadb_hash[hashval]) == NULL) {
		KLIPS_PRINT(debug_xform,
			    "klips_debug:ipsec_sa_getbyid: "
			    "no entries in ipsec_sa table for hash=%d of SA:%s.\n",
			    hashval,
			    sa_len ? sa : " (error)");
		return NULL;
	}

	for (; ips; ips = ips->ips_hnext) {
		if ((ips->ips_said.spi == said->spi) &&
		    (ips->ips_said.dst.s_addr == said->dst.s_addr) &&
		    (ips->ips_said.proto == said->proto)) {
			atomic_inc(&ips->ips_refcount);
			return ips;
		}
	}
	
	KLIPS_PRINT(debug_xform,
		    "klips_debug:ipsec_sa_getbyid: "
		    "no entry in linked list for hash=%d of SA:%s.\n",
		    hashval,
		    sa_len ? sa : " (error)");
	return NULL;
}

int
ipsec_sa_put(struct ipsec_sa *ips)
{
        char sa[SATOA_BUF];
	size_t sa_len;

	if(ips == NULL) {
		KLIPS_PRINT(debug_xform,
			    "klips_error:ipsec_sa_put: "
			    "null pointer passed in!\n");
		return -1;
	}

	sa_len = satoa(ips->ips_said, 0, sa, SATOA_BUF);

	KLIPS_PRINT(debug_xform,
		    "klips_debug:ipsec_sa_put: "
		    "ipsec_sa SA:%s, ref:%d reference count decremented.\n",
		    sa_len ? sa : " (error)",
		    ips->ips_ref);

	atomic_dec(&ips->ips_refcount);

	return 0;
}

/*
  The ipsec_sa table better *NOT* be locked before it is handed in, or SMP locks will happen
*/
int
ipsec_sa_add(struct ipsec_sa *ips)
{
	int error = 0;
	unsigned int hashval;

	if(ips == NULL) {
		KLIPS_PRINT(debug_xform,
			    "klips_error:ipsec_sa_add: "
			    "null pointer passed in!\n");
		return -ENODATA;
	}
	hashval = ((ips->ips_said.spi + ips->ips_said.dst.s_addr + ips->ips_said.proto) % SADB_HASHMOD);

	atomic_inc(&ips->ips_refcount);
	spin_lock_bh(&tdb_lock);
	
	ips->ips_hnext = ipsec_sadb_hash[hashval];
	ipsec_sadb_hash[hashval] = ips;
	
	spin_unlock_bh(&tdb_lock);

	return error;
}

/*
  The ipsec_sa table better be locked before it is handed in, or races might happen
*/
int
ipsec_sa_del(struct ipsec_sa *ips)
{
	unsigned int hashval;
	struct ipsec_sa *ipstp;
        char sa[SATOA_BUF];
	size_t sa_len;

	if(ips == NULL) {
		KLIPS_PRINT(debug_xform,
			    "klips_error:ipsec_sa_del: "
			    "null pointer passed in!\n");
		return -ENODATA;
	}
	
	sa_len = satoa(ips->ips_said, 0, sa, SATOA_BUF);
	if(ips->ips_inext || ips->ips_onext) {
		KLIPS_PRINT(debug_xform,
			    "klips_error:ipsec_sa_del: "
			    "SA:%s still linked!\n",
			    sa_len ? sa : " (error)");
		return -EMLINK;
	}
	
	hashval = ((ips->ips_said.spi + ips->ips_said.dst.s_addr + ips->ips_said.proto) % SADB_HASHMOD);
	
	KLIPS_PRINT(debug_xform,
		    "klips_debug:ipsec_sa_del: "
		    "deleting SA:%s, hashval=%d.\n",
		    sa_len ? sa : " (error)",
		    hashval);
	if(ipsec_sadb_hash[hashval] == NULL) {
		KLIPS_PRINT(debug_xform,
			    "klips_debug:ipsec_sa_del: "
			    "no entries in ipsec_sa table for hash=%d of SA:%s.\n",
			    hashval,
			    sa_len ? sa : " (error)");
		return -ENOENT;
	}
	
	if (ips == ipsec_sadb_hash[hashval]) {
		ipsec_sadb_hash[hashval] = ipsec_sadb_hash[hashval]->ips_hnext;
		ips->ips_hnext = NULL;
		atomic_dec(&ips->ips_refcount);
		KLIPS_PRINT(debug_xform,
			    "klips_debug:ipsec_sa_del: "
			    "successfully deleted first ipsec_sa in chain.\n");
		return 0;
	} else {
		for (ipstp = ipsec_sadb_hash[hashval];
		     ipstp;
		     ipstp = ipstp->ips_hnext) {
			if (ipstp->ips_hnext == ips) {
				ipstp->ips_hnext = ips->ips_hnext;
				ips->ips_hnext = NULL;
				atomic_dec(&ips->ips_refcount);
				KLIPS_PRINT(debug_xform,
					    "klips_debug:ipsec_sa_del: "
					    "successfully deleted link in ipsec_sa chain.\n");
				return 0;
			}
		}
	}
	
	KLIPS_PRINT(debug_xform,
		    "klips_debug:ipsec_sa_del: "
		    "no entries in linked list for hash=%d of SA:%s.\n",
		    hashval,
		    sa_len ? sa : " (error)");
	return -ENOENT;
}

/*
  The ipsec_sa table better be locked before it is handed in, or races
  might happen
*/
int
ipsec_sa_delchain(struct ipsec_sa *ips)
{
	struct ipsec_sa *ipsdel;
	int error = 0;
        char sa[SATOA_BUF];
	size_t sa_len;

	if(ips == NULL) {
		KLIPS_PRINT(debug_xform,
			    "klips_error:ipsec_sa_delchain: "
			    "null pointer passed in!\n");
		return -ENODATA;
	}

	sa_len = satoa(ips->ips_said, 0, sa, SATOA_BUF);
	KLIPS_PRINT(debug_xform,
		    "klips_debug:ipsec_sa_delchain: "
		    "passed SA:%s\n",
		    sa_len ? sa : " (error)");
	while(ips->ips_onext != NULL) {
		ips = ips->ips_onext;
	}

	while(ips) {
		/* XXX send a pfkey message up to advise of deleted ipsec_sa */
		sa_len = satoa(ips->ips_said, 0, sa, SATOA_BUF);
		KLIPS_PRINT(debug_xform,
			    "klips_debug:ipsec_sa_delchain: "
			    "unlinking and delting SA:%s",
			    sa_len ? sa : " (error)");
		ipsdel = ips;
		ips = ips->ips_inext;
		if(ips != NULL) {
			sa_len = satoa(ips->ips_said, 0, sa, SATOA_BUF);
			KLIPS_PRINT(debug_xform,
				    ", inext=%s",
				    sa_len ? sa : " (error)");
			atomic_dec(&ipsdel->ips_refcount);
			ipsdel->ips_inext = NULL;
			atomic_dec(&ips->ips_refcount);
			ips->ips_onext = NULL;
		}
		KLIPS_PRINT(debug_xform,
			    ".\n");
		if((error = ipsec_sa_del(ipsdel))) {
			KLIPS_PRINT(debug_xform,
				    "klips_debug:ipsec_sa_delchain: "
				    "ipsec_sa_del returned error %d.\n", -error);
			return error;
		}
		if((error = ipsec_sa_wipe(ipsdel))) {
			KLIPS_PRINT(debug_xform,
				    "klips_debug:ipsec_sa_delchain: "
				    "ipsec_sa_wipe returned error %d.\n", -error);
			return error;
		}
	}
	return error;
}

int 
ipsec_sadb_cleanup(__u8 proto)
{
	unsigned i;
	int error = 0;
	struct ipsec_sa *ips, **ipsprev, *ipsdel;
        char sa[SATOA_BUF];
	size_t sa_len;

	KLIPS_PRINT(debug_xform,
		    "klips_debug:ipsec_sadb_cleanup: "
		    "cleaning up proto=%d.\n",
		    proto);

	spin_lock_bh(&tdb_lock);

	for (i = 0; i < SADB_HASHMOD; i++) {
		ipsprev = &(ipsec_sadb_hash[i]);
		ips = ipsec_sadb_hash[i];
		if(ips != NULL) {
			atomic_inc(&ips->ips_refcount);
		}
		for(; ips != NULL;) {
			sa_len = satoa(ips->ips_said, 0, sa, SATOA_BUF);
			KLIPS_PRINT(debug_xform,
				    "klips_debug:ipsec_sadb_cleanup: "
				    "checking SA:%s, hash=%d, ref=%d",
				    sa_len ? sa : " (error)",
				    i,
				    ips->ips_ref);
			ipsdel = ips;
			ips = ipsdel->ips_hnext;
			if(ips != NULL) {
				atomic_inc(&ips->ips_refcount);
				sa_len = satoa(ips->ips_said, 0, sa, SATOA_BUF);
				KLIPS_PRINT(debug_xform,
					    ", hnext=%s",
					    sa_len ? sa : " (error)");
			}
			if(*ipsprev != NULL) {
				sa_len = satoa((*ipsprev)->ips_said, 0, sa, SATOA_BUF);
				KLIPS_PRINT(debug_xform,
					    ", *ipsprev=%s",
					    sa_len ? sa : " (error)");
				if((*ipsprev)->ips_hnext) {
					sa_len = satoa((*ipsprev)->ips_hnext->ips_said, 0, sa, SATOA_BUF);
					KLIPS_PRINT(debug_xform,
						    ", *ipsprev->ips_hnext=%s",
						    sa_len ? sa : " (error)");
				}
			}
			KLIPS_PRINT(debug_xform,
				    ".\n");
			if(proto == 0 || (proto == ipsdel->ips_said.proto)) {
				sa_len = satoa(ipsdel->ips_said, 0, sa, SATOA_BUF);
				KLIPS_PRINT(debug_xform,
					    "klips_debug:ipsec_sadb_cleanup: "
					    "deleting SA chain:%s.\n",
					    sa_len ? sa : " (error)");
				if((error = ipsec_sa_delchain(ipsdel))) {
					SENDERR(-error);
				}
				ipsprev = &(ipsec_sadb_hash[i]);
				ips = ipsec_sadb_hash[i];

				KLIPS_PRINT(debug_xform,
					    "klips_debug:ipsec_sadb_cleanup: "
					    "deleted SA chain:%s",
					    sa_len ? sa : " (error)");
				if(ips != NULL) {
					sa_len = satoa(ips->ips_said, 0, sa, SATOA_BUF);
					KLIPS_PRINT(debug_xform,
						    ", ipsec_sadb_hash[%d]=%s",
						    i,
						    sa_len ? sa : " (error)");
				}
				if(*ipsprev != NULL) {
					sa_len = satoa((*ipsprev)->ips_said, 0, sa, SATOA_BUF);
					KLIPS_PRINT(debug_xform,
						    ", *ipsprev=%s",
						    sa_len ? sa : " (error)");
					if((*ipsprev)->ips_hnext != NULL) {
						sa_len = satoa((*ipsprev)->ips_hnext->ips_said, 0, sa, SATOA_BUF);
						KLIPS_PRINT(debug_xform,
							    ", *ipsprev->ips_hnext=%s",
							    sa_len ? sa : " (error)");
					}
				}
				KLIPS_PRINT(debug_xform,
					    ".\n");
			} else {
				ipsprev = &ipsdel;
			}
			if(ipsdel != NULL) {
				ipsec_sa_put(ipsdel);
			}
		}
	}
 errlab:

	spin_unlock_bh(&tdb_lock);


#if IPSEC_SA_REF_CODE
	/* clean up SA reference table */

	/* go through the ref table and clean out all the SAs */
	KLIPS_PRINT(debug_xform,
		    "klips_debug:ipsec_sadb_cleanup: "
		    "removing SAref entries and tables.");
	{
		unsigned table, entry;
		for(table = 0; table < IPSEC_SA_REF_MAINTABLE_NUM_ENTRIES; table++) {
			KLIPS_PRINT(debug_xform,
				    "klips_debug:ipsec_sadb_cleanup: "
				    "cleaning SAref table=%u.\n",
				    table);
			if(ipsec_sadb.refTable[table] == NULL) {
				printk("\n");
				KLIPS_PRINT(debug_xform,
					    "klips_debug:ipsec_sadb_cleanup: "
					    "cleaned %u used refTables.\n",
					    table);
				break;
			}
			for(entry = 0; entry < IPSEC_SA_REF_SUBTABLE_NUM_ENTRIES; entry++) {
				if(ipsec_sadb.refTable[table]->entry[entry] != NULL) {
					ipsec_sa_delchain(ipsec_sadb.refTable[table]->entry[entry]);
					ipsec_sadb.refTable[table]->entry[entry] = NULL;
				}
			}
		}
	}
#endif /* IPSEC_SA_REF_CODE */

	return(error);
}

int 
ipsec_sadb_free(void)
{
	int error = 0;

	KLIPS_PRINT(debug_xform,
		    "klips_debug:ipsec_sadb_free: "
		    "freeing SArefTable memory.\n");

	/* clean up SA reference table */

	/* go through the ref table and clean out all the SAs if any are
	   left and free table memory */
	KLIPS_PRINT(debug_xform,
		    "klips_debug:ipsec_sadb_free: "
		    "removing SAref entries and tables.\n");
	{
		unsigned table, entry;
		for(table = 0; table < IPSEC_SA_REF_MAINTABLE_NUM_ENTRIES; table++) {
			KLIPS_PRINT(debug_xform,
				    "klips_debug:ipsec_sadb_free: "
				    "removing SAref table=%u.\n",
				    table);
			if(ipsec_sadb.refTable[table] == NULL) {
				KLIPS_PRINT(debug_xform,
					    "klips_debug:ipsec_sadb_free: "
					    "removed %u used refTables.\n",
					    table);
				break;
			}
			for(entry = 0; entry < IPSEC_SA_REF_SUBTABLE_NUM_ENTRIES; entry++) {
				if(ipsec_sadb.refTable[table]->entry[entry] != NULL) {
					ipsec_sa_delchain(ipsec_sadb.refTable[table]->entry[entry]);
					ipsec_sadb.refTable[table]->entry[entry] = NULL;
				}
			}
			vfree(ipsec_sadb.refTable[table]);
			ipsec_sadb.refTable[table] = NULL;
		}
	}

	return(error);
}

int
ipsec_sa_wipe(struct ipsec_sa *ips)
{
	if(ips == NULL) {
		return -ENODATA;
	}

	/* if(atomic_dec_and_test(ips)) {
	}; */

#if IPSEC_SA_REF_CODE
	/* remove me from the SArefTable */
	{
		char sa[SATOA_BUF];
		size_t sa_len;
		sa_len = satoa(ips->ips_said, 0, sa, SATOA_BUF);
		KLIPS_PRINT(debug_xform,
			    "klips_debug:ipsec_sa_wipe: "
			    "removing SA=%s(0p%p), SAref=%d, table=%d(0p%p), entry=%d from the refTable.\n",
			    sa_len ? sa : " (error)",
			    ips,
			    ips->ips_ref,
			    IPsecSAref2table(IPsecSA2SAref(ips)),
			    ipsec_sadb.refTable[IPsecSAref2table(IPsecSA2SAref(ips))],
			    IPsecSAref2entry(IPsecSA2SAref(ips)));
	}
	if(ips->ips_ref == IPSEC_SAREF_NULL) {
		KLIPS_PRINT(debug_xform,
			    "klips_debug:ipsec_sa_wipe: "
			    "why does this SA not have a valid SAref?.\n");
	}
	ipsec_sadb.refTable[IPsecSAref2table(IPsecSA2SAref(ips))]->entry[IPsecSAref2entry(IPsecSA2SAref(ips))] = NULL;
	ips->ips_ref = IPSEC_SAREF_NULL;
	ipsec_sa_put(ips);
#endif /* IPSEC_SA_REF_CODE */

	/* paranoid clean up */
	if(ips->ips_addr_s != NULL) {
		memset((caddr_t)(ips->ips_addr_s), 0, ips->ips_addr_s_size);
		kfree(ips->ips_addr_s);
	}
	ips->ips_addr_s = NULL;

	if(ips->ips_addr_d != NULL) {
		memset((caddr_t)(ips->ips_addr_d), 0, ips->ips_addr_d_size);
		kfree(ips->ips_addr_d);
	}
	ips->ips_addr_d = NULL;

	if(ips->ips_addr_p != NULL) {
		memset((caddr_t)(ips->ips_addr_p), 0, ips->ips_addr_p_size);
		kfree(ips->ips_addr_p);
	}
	ips->ips_addr_p = NULL;

#ifdef CONFIG_IPSEC_NAT_TRAVERSAL
	if(ips->ips_natt_oa) {
		memset((caddr_t)(ips->ips_natt_oa), 0, ips->ips_natt_oa_size);
		kfree(ips->ips_natt_oa);
	}
	ips->ips_natt_oa = NULL;
#endif

	if(ips->ips_key_a != NULL) {
		memset((caddr_t)(ips->ips_key_a), 0, ips->ips_key_a_size);
		kfree(ips->ips_key_a);
	}
	ips->ips_key_a = NULL;

	if(ips->ips_key_e != NULL) {
#ifdef CONFIG_IPSEC_ALG
		if (ips->ips_alg_enc&&ips->ips_alg_enc->ixt_e_destroy_key) {
			ips->ips_alg_enc->ixt_e_destroy_key(ips->ips_alg_enc, 
					ips->ips_key_e);
		} else {
#endif /* CONFIG_IPSEC_ALG */
		memset((caddr_t)(ips->ips_key_e), 0, ips->ips_key_e_size);
		kfree(ips->ips_key_e);
#ifdef CONFIG_IPSEC_ALG
		}
#endif /* CONFIG_IPSEC_ALG */
	}
	ips->ips_key_e = NULL;

	if(ips->ips_iv != NULL) {
		memset((caddr_t)(ips->ips_iv), 0, ips->ips_iv_size);
		kfree(ips->ips_iv);
	}
	ips->ips_iv = NULL;

	if(ips->ips_ident_s.data != NULL) {
		memset((caddr_t)(ips->ips_ident_s.data),
                       0,
		       ips->ips_ident_s.len * IPSEC_PFKEYv2_ALIGN - sizeof(struct sadb_ident));
		kfree(ips->ips_ident_s.data);
        }
	ips->ips_ident_s.data = NULL;
	
	if(ips->ips_ident_d.data != NULL) {
		memset((caddr_t)(ips->ips_ident_d.data),
                       0,
		       ips->ips_ident_d.len * IPSEC_PFKEYv2_ALIGN - sizeof(struct sadb_ident));
		kfree(ips->ips_ident_d.data);
        }
	ips->ips_ident_d.data = NULL;

#ifdef CONFIG_IPSEC_ALG
	if (ips->ips_alg_enc||ips->ips_alg_auth) {
		ipsec_alg_sa_wipe(ips);
	}
#endif /* CONFIG_IPSEC_ALG */
	
	memset((caddr_t)ips, 0, sizeof(*ips));
	kfree(ips);
	ips = NULL;

	return 0;
}
