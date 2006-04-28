/*
 * FreeS/WAN specific PF_KEY headers
 * Copyright (C) 1999, 2000, 2001  Richard Guy Briggs.
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
 * RCSID $Id: pfkey.h,v 1.2 2004/03/22 21:53:18 as Exp $
 */

#ifndef __NET_IPSEC_PF_KEY_H
#define __NET_IPSEC_PF_KEY_H
#ifdef __KERNEL__
extern struct proto_ops pfkey_proto_ops;
typedef struct sock pfkey_sock;
extern int debug_pfkey;

extern /* void */ int pfkey_init(void);
extern /* void */ int pfkey_cleanup(void);

extern struct sock *pfkey_sock_list;
struct socket_list
{
	struct socket *socketp;
	struct socket_list *next;
};
extern int pfkey_list_insert_socket(struct socket*, struct socket_list**);
extern int pfkey_list_remove_socket(struct socket*, struct socket_list**);
extern struct socket_list *pfkey_open_sockets;
extern struct socket_list *pfkey_registered_sockets[SADB_SATYPE_MAX+1];

/* 
 *	There is a field-by-field copy in klips/net/ipsec/ipsec_alg.h
 *	please keep in sync until we migrate all support stuff
 *	to ipsec_alg objects
 */
struct supported
{
	uint16_t supported_alg_exttype;
	uint8_t supported_alg_id;
	uint8_t supported_alg_ivlen;
	uint16_t supported_alg_minbits;
	uint16_t supported_alg_maxbits;
};
extern struct supported_list *pfkey_supported_list[SADB_SATYPE_MAX+1];
struct supported_list
{
	struct supported *supportedp;
	struct supported_list *next;
};
extern int pfkey_list_insert_supported(struct supported*, struct supported_list**);
extern int pfkey_list_remove_supported(struct supported*, struct supported_list**);

struct sockaddr_key
{
	uint16_t	key_family;	/* PF_KEY */
	uint16_t	key_pad;	/* not used */
	uint32_t	key_pid;	/* process ID */
};

struct pfkey_extracted_data
{
	struct ipsec_sa* ips;
	struct ipsec_sa* ips2;
	struct eroute *eroute;
};

extern int
pfkey_alloc_eroute(struct eroute** eroute);

extern int
pfkey_sa_process(struct sadb_ext *pfkey_ext,
		 struct pfkey_extracted_data* extr);

extern int
pfkey_lifetime_process(struct sadb_ext *pfkey_ext,
		       struct pfkey_extracted_data* extr);

extern int
pfkey_address_process(struct sadb_ext *pfkey_ext,
		      struct pfkey_extracted_data* extr);

extern int
pfkey_key_process(struct sadb_ext *pfkey_ext,
		  struct pfkey_extracted_data* extr);

extern int
pfkey_ident_process(struct sadb_ext *pfkey_ext,
		    struct pfkey_extracted_data* extr);

extern int
pfkey_sens_process(struct sadb_ext *pfkey_ext,
		   struct pfkey_extracted_data* extr);

extern int
pfkey_prop_process(struct sadb_ext *pfkey_ext,
		   struct pfkey_extracted_data* extr);

extern int
pfkey_supported_process(struct sadb_ext *pfkey_ext,
			struct pfkey_extracted_data* extr);

extern int
pfkey_spirange_process(struct sadb_ext *pfkey_ext,
		       struct pfkey_extracted_data* extr);

extern int
pfkey_x_kmprivate_process(struct sadb_ext *pfkey_ext,
			  struct pfkey_extracted_data* extr);

extern int
pfkey_x_satype_process(struct sadb_ext *pfkey_ext,
		       struct pfkey_extracted_data* extr);

extern int
pfkey_x_debug_process(struct sadb_ext *pfkey_ext,
		      struct pfkey_extracted_data* extr);

extern int pfkey_register_reply(int satype, struct sadb_msg *);
extern int pfkey_upmsg(struct socket *, struct sadb_msg *);
extern int pfkey_expire(struct ipsec_sa *, int);
extern int pfkey_acquire(struct ipsec_sa *);
#else /* ! __KERNEL__ */

extern void (*pfkey_debug_func)(const char *message, ...);

#endif /* __KERNEL__ */

extern uint8_t satype2proto(uint8_t satype);
extern uint8_t proto2satype(uint8_t proto);
extern char* satype2name(uint8_t satype);
extern char* proto2name(uint8_t proto);

struct key_opt
{
	uint32_t	key_pid;	/* process ID */
	struct sock	*sk;
};

#define key_pid(sk) ((struct key_opt*)&((sk)->protinfo))->key_pid

#define IPSEC_PFKEYv2_ALIGN (sizeof(uint64_t)/sizeof(uint8_t))
#define BITS_PER_OCTET 8
#define OCTETBITS 8
#define PFKEYBITS 64
#define DIVUP(x,y) ((x + y -1) / y) /* divide, rounding upwards */
#define ALIGN_N(x,y) (DIVUP(x,y) * y) /* align on y boundary */

#define PFKEYv2_MAX_MSGSIZE 4096

/*
 * PF_KEYv2 permitted and required extensions in and out bitmaps
 */
struct pf_key_ext_parsers_def {
	int  (*parser)(struct sadb_ext*);
	char  *parser_name;
};


extern unsigned int extensions_bitmaps[2/*in/out*/][2/*perm/req*/][SADB_MAX + 1/*ext*/];
#define EXT_BITS_IN 0
#define EXT_BITS_OUT 1
#define EXT_BITS_PERM 0
#define EXT_BITS_REQ 1

extern void pfkey_extensions_init(struct sadb_ext *extensions[SADB_EXT_MAX + 1]);
extern void pfkey_extensions_free(struct sadb_ext *extensions[SADB_EXT_MAX + 1]);
extern void pfkey_msg_free(struct sadb_msg **pfkey_msg);

extern int pfkey_msg_parse(struct sadb_msg *pfkey_msg,
			   struct pf_key_ext_parsers_def *ext_parsers[],
			   struct sadb_ext **extensions,
			   int dir);

/*
 * PF_KEYv2 build function prototypes
 */

int
pfkey_msg_hdr_build(struct sadb_ext**	pfkey_ext,
		    uint8_t		msg_type,
		    uint8_t		satype,
		    uint8_t		msg_errno,
		    uint32_t		seq,
		    uint32_t		pid);

int
pfkey_sa_ref_build(struct sadb_ext **	pfkey_ext,
	       uint16_t			exttype,
	       uint32_t			spi, /* in network order */
	       uint8_t			replay_window,
	       uint8_t			sa_state,
	       uint8_t			auth,
	       uint8_t			encrypt,
	       uint32_t			flags,
	       uint32_t/*IPsecSAref_t*/	ref);

int
pfkey_sa_build(struct sadb_ext **	pfkey_ext,
	       uint16_t			exttype,
	       uint32_t			spi, /* in network order */
	       uint8_t			replay_window,
	       uint8_t			sa_state,
	       uint8_t			auth,
	       uint8_t			encrypt,
	       uint32_t			flags);

int
pfkey_lifetime_build(struct sadb_ext **	pfkey_ext,
		     uint16_t		exttype,
		     uint32_t		allocations,
		     uint64_t		bytes,
		     uint64_t		addtime,
		     uint64_t		usetime,
		     uint32_t		packets);

int
pfkey_address_build(struct sadb_ext**	pfkey_ext,
		    uint16_t		exttype,
		    uint8_t		proto,
		    uint8_t		prefixlen,
		    struct sockaddr*	address);

int
pfkey_key_build(struct sadb_ext**	pfkey_ext,
		uint16_t		exttype,
		uint16_t		key_bits,
		char*			key);

int
pfkey_ident_build(struct sadb_ext**	pfkey_ext,
		  uint16_t		exttype,
		  uint16_t		ident_type,
		  uint64_t		ident_id,
		  uint8_t               ident_len,
		  char*			ident_string);

#ifdef NAT_TRAVERSAL
#ifdef __KERNEL__
extern int pfkey_nat_t_new_mapping(struct ipsec_sa *, struct sockaddr *, __u16);
extern int pfkey_x_nat_t_type_process(struct sadb_ext *pfkey_ext, struct pfkey_extracted_data* extr);
extern int pfkey_x_nat_t_port_process(struct sadb_ext *pfkey_ext, struct pfkey_extracted_data* extr);
#endif /* __KERNEL__ */
int
pfkey_x_nat_t_type_build(struct sadb_ext**  pfkey_ext,
            uint8_t         type);
int
pfkey_x_nat_t_port_build(struct sadb_ext**  pfkey_ext,
            uint16_t         exttype,
            uint16_t         port);
#endif

int
pfkey_sens_build(struct sadb_ext**	pfkey_ext,
		 uint32_t		dpd,
		 uint8_t		sens_level,
		 uint8_t		sens_len,
		 uint64_t*		sens_bitmap,
		 uint8_t		integ_level,
		 uint8_t		integ_len,
		 uint64_t*		integ_bitmap);

int pfkey_x_protocol_build(struct sadb_ext **, uint8_t);


int
pfkey_prop_build(struct sadb_ext**	pfkey_ext,
		 uint8_t		replay,
		 unsigned int		comb_num,
		 struct sadb_comb*	comb);

int
pfkey_supported_build(struct sadb_ext**	pfkey_ext,
		      uint16_t		exttype,
		      unsigned int	alg_num,
		      struct sadb_alg*	alg);

int
pfkey_spirange_build(struct sadb_ext**	pfkey_ext,
		     uint16_t		exttype,
		     uint32_t		min,
		     uint32_t		max);

int
pfkey_x_kmprivate_build(struct sadb_ext**	pfkey_ext);

int
pfkey_x_satype_build(struct sadb_ext**	pfkey_ext,
		     uint8_t		satype);

int
pfkey_x_debug_build(struct sadb_ext**	pfkey_ext,
		    uint32_t            tunnel,
		    uint32_t		netlink,
		    uint32_t		xform,
		    uint32_t		eroute,
		    uint32_t		spi,
		    uint32_t		radij,
		    uint32_t		esp,
		    uint32_t		ah,
		    uint32_t		rcv,
		    uint32_t            pfkey,
		    uint32_t            ipcomp,
		    uint32_t            verbose);

int
pfkey_msg_build(struct sadb_msg**	pfkey_msg,
		struct sadb_ext*	extensions[],
		int			dir);

/* in pfkey_v2_debug.c - routines to decode numbers -> strings */
const char *
pfkey_v2_sadb_ext_string(int extnum);

const char *
pfkey_v2_sadb_type_string(int sadb_type);


#endif /* __NET_IPSEC_PF_KEY_H */

/*
 * $Log: pfkey.h,v $
 * Revision 1.2  2004/03/22 21:53:18  as
 * merged alg-0.8.1 branch with HEAD
 *
 * Revision 1.1.2.1.2.1  2004/03/16 09:48:18  as
 * alg-0.8.1rc12 patch merged
 *
 * Revision 1.1.2.1  2004/03/15 22:30:06  as
 * nat-0.6c patch merged
 *
 * Revision 1.1  2004/03/15 20:35:25  as
 * added files from freeswan-2.04-x509-1.5.3
 *
 * Revision 1.42  2003/08/25 22:08:19  mcr
 * 	removed pfkey_proto_init() from pfkey.h for 2.6 support.
 *
 * Revision 1.41  2003/05/07 17:28:57  mcr
 * 	new function pfkey_debug_func added for us in debugging from
 * 	pfkey library.
 *
 * Revision 1.40  2003/01/30 02:31:34  rgb
 *
 * Convert IPsecSAref_t from signed to unsigned to fix apparent SAref exhaustion bug.
 *
 * Revision 1.39  2002/09/20 15:40:21  rgb
 * Switch from pfkey_alloc_ipsec_sa() to ipsec_sa_alloc().
 * Added ref parameter to pfkey_sa_build().
 * Cleaned out unused cruft.
 *
 * Revision 1.38  2002/05/14 02:37:24  rgb
 * Change all references to tdb, TDB or Tunnel Descriptor Block to ips,
 * ipsec_sa or ipsec_sa.
 * Added function prototypes for the functions moved to
 * pfkey_v2_ext_process.c.
 *
 * Revision 1.37  2002/04/24 07:36:49  mcr
 * Moved from ./lib/pfkey.h,v
 *
 * Revision 1.36  2002/01/20 20:34:49  mcr
 * 	added pfkey_v2_sadb_type_string to decode sadb_type to string.
 *
 * Revision 1.35  2001/11/27 05:27:47  mcr
 * 	pfkey parses are now maintained by a structure
 * 	that includes their name for debug purposes.
 *
 * Revision 1.34  2001/11/26 09:23:53  rgb
 * Merge MCR's ipsec_sa, eroute, proc and struct lifetime changes.
 *
 * Revision 1.33  2001/11/06 19:47:47  rgb
 * Added packet parameter to lifetime and comb structures.
 *
 * Revision 1.32  2001/09/08 21:13:34  rgb
 * Added pfkey ident extension support for ISAKMPd. (NetCelo)
 *
 * Revision 1.31  2001/06/14 19:35:16  rgb
 * Update copyright date.
 *
 * Revision 1.30  2001/02/27 07:04:52  rgb
 * Added satype2name prototype.
 *
 * Revision 1.29  2001/02/26 19:59:33  rgb
 * Ditch unused sadb_satype2proto[], replaced by satype2proto().
 *
 * Revision 1.28  2000/10/10 20:10:19  rgb
 * Added support for debug_ipcomp and debug_verbose to klipsdebug.
 *
 * Revision 1.27  2000/09/21 04:20:45  rgb
 * Fixed array size off-by-one error.  (Thanks Svenning!)
 *
 * Revision 1.26  2000/09/12 03:26:05  rgb
 * Added pfkey_acquire prototype.
 *
 * Revision 1.25  2000/09/08 19:21:28  rgb
 * Fix pfkey_prop_build() parameter to be only single indirection.
 *
 * Revision 1.24  2000/09/01 18:46:42  rgb
 * Added a supported algorithms array lists, one per satype and registered
 * existing algorithms.
 * Fixed pfkey_list_{insert,remove}_{socket,support}() to allow change to
 * list.
 *
 * Revision 1.23  2000/08/27 01:55:26  rgb
 * Define OCTETBITS and PFKEYBITS to avoid using 'magic' numbers in code.
 *
 * Revision 1.22  2000/08/20 21:39:23  rgb
 * Added kernel prototypes for kernel funcitions pfkey_upmsg() and
 * pfkey_expire().
 *
 * Revision 1.21  2000/08/15 17:29:23  rgb
 * Fixes from SZI to untested pfkey_prop_build().
 *
 * Revision 1.20  2000/05/10 20:14:19  rgb
 * Fleshed out sensitivity, proposal and supported extensions.
 *
 * Revision 1.19  2000/03/16 14:07:23  rgb
 * Renamed ALIGN macro to avoid fighting with others in kernel.
 *
 * Revision 1.18  2000/01/22 23:24:06  rgb
 * Added prototypes for proto2satype(), satype2proto() and proto2name().
 *
 * Revision 1.17  2000/01/21 06:26:59  rgb
 * Converted from double tdb arguments to one structure (extr)
 * containing pointers to all temporary information structures.
 * Added klipsdebug switching capability.
 * Dropped unused argument to pfkey_x_satype_build().
 *
 * Revision 1.16  1999/12/29 21:17:41  rgb
 * Changed pfkey_msg_build() I/F to include a struct sadb_msg**
 * parameter for cleaner manipulation of extensions[] and to guard
 * against potential memory leaks.
 * Changed the I/F to pfkey_msg_free() for the same reason.
 *
 * Revision 1.15  1999/12/09 23:12:54  rgb
 * Added macro for BITS_PER_OCTET.
 * Added argument to pfkey_sa_build() to do eroutes.
 *
 * Revision 1.14  1999/12/08 20:33:25  rgb
 * Changed sa_family_t to uint16_t for 2.0.xx compatibility.
 *
 * Revision 1.13  1999/12/07 19:53:40  rgb
 * Removed unused first argument from extension parsers.
 * Changed __u* types to uint* to avoid use of asm/types.h and
 * sys/types.h in userspace code.
 * Added function prototypes for pfkey message and extensions
 * initialisation and cleanup.
 *
 * Revision 1.12  1999/12/01 22:19:38  rgb
 * Change pfkey_sa_build to accept an SPI in network byte order.
 *
 * Revision 1.11  1999/11/27 11:55:26  rgb
 * Added extern sadb_satype2proto to enable moving protocol lookup table
 * to lib/pfkey_v2_parse.c.
 * Delete unused, moved typedefs.
 * Add argument to pfkey_msg_parse() for direction.
 * Consolidated the 4 1-d extension bitmap arrays into one 4-d array.
 *
 * Revision 1.10  1999/11/23 22:29:21  rgb
 * This file has been moved in the distribution from klips/net/ipsec to
 * lib.
 * Add macros for dealing with alignment and rounding up more opaquely.
 * The uint<n>_t type defines have been moved to freeswan.h to avoid
 * chicken-and-egg problems.
 * Add macros for dealing with alignment and rounding up more opaque.
 * Added prototypes for using extention header bitmaps.
 * Added prototypes of all the build functions.
 *
 * Revision 1.9  1999/11/20 21:59:48  rgb
 * Moved socketlist type declarations and prototypes for shared use.
 * Slightly modified scope of sockaddr_key declaration.
 *
 * Revision 1.8  1999/11/17 14:34:25  rgb
 * Protect sa_family_t from being used in userspace with GLIBC<2.
 *
 * Revision 1.7  1999/10/27 19:40:35  rgb
 * Add a maximum PFKEY packet size macro.
 *
 * Revision 1.6  1999/10/26 16:58:58  rgb
 * Created a sockaddr_key and key_opt socket extension structures.
 *
 * Revision 1.5  1999/06/10 05:24:41  rgb
 * Renamed variables to reduce confusion.
 *
 * Revision 1.4  1999/04/29 15:21:11  rgb
 * Add pfkey support to debugging.
 * Add return values to init and cleanup functions.
 *
 * Revision 1.3  1999/04/15 17:58:07  rgb
 * Add RCSID labels.
 *
 */
