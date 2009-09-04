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
 */

#ifndef __NET_IPSEC_PF_KEY_H
#define __NET_IPSEC_PF_KEY_H

extern void (*pfkey_debug_func)(const char *message, ...);

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

int
pfkey_x_nat_t_type_build(struct sadb_ext**  pfkey_ext,
            uint8_t         type);
int
pfkey_x_nat_t_port_build(struct sadb_ext**  pfkey_ext,
            uint16_t         exttype,
            uint16_t         port);

int
pfkey_sens_build(struct sadb_ext**	pfkey_ext,
		 uint32_t		dpd,
		 uint8_t		sens_level,
		 uint8_t		sens_len,
		 uint64_t*		sens_bitmap,
		 uint8_t		integ_level,
		 uint8_t		integ_len,
		 uint64_t*		integ_bitmap);

int
pfkey_x_protocol_build(struct sadb_ext **, uint8_t);


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
