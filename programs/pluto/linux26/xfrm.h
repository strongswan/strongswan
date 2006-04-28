#ifndef _LINUX_XFRM_H
#define _LINUX_XFRM_H

#include <stdint.h>

/* All of the structures in this file may not change size as they are
 * passed into the kernel from userspace via netlink sockets.
 */

/* Structure to encapsulate addresses. I do not want to use
 * "standard" structure. My apologies.
 */
typedef union
{
	uint32_t	a4;
	uint32_t	a6[4];
} xfrm_address_t;

/* Ident of a specific xfrm_state. It is used on input to lookup
 * the state by (spi,daddr,ah/esp) or to store information about
 * spi, protocol and tunnel address on output.
 */
struct xfrm_id
{
	xfrm_address_t	daddr;
	uint32_t	spi;
	uint8_t		proto;
};

/* Selector, used as selector both on policy rules (SPD) and SAs. */

struct xfrm_selector
{
	xfrm_address_t	daddr;
	xfrm_address_t	saddr;
	uint16_t	dport;
	uint16_t	dport_mask;
	uint16_t	sport;
	uint16_t	sport_mask;
	uint16_t	family;
	uint8_t		prefixlen_d;
	uint8_t		prefixlen_s;
	uint8_t		proto;
	int		ifindex;
	uid_t		user;
};

#define XFRM_INF (~(uint64_t)0)

struct xfrm_lifetime_cfg
{
	uint64_t	soft_byte_limit;
	uint64_t	hard_byte_limit;
	uint64_t	soft_packet_limit;
	uint64_t	hard_packet_limit;
	uint64_t	soft_add_expires_seconds;
	uint64_t	hard_add_expires_seconds;
	uint64_t	soft_use_expires_seconds;
	uint64_t	hard_use_expires_seconds;
};

struct xfrm_lifetime_cur
{
	uint64_t	bytes;
	uint64_t	packets;
	uint64_t	add_time;
	uint64_t	use_time;
};

struct xfrm_replay_state
{
	uint32_t	oseq;
	uint32_t	seq;
	uint32_t	bitmap;
};

struct xfrm_algo {
	char	alg_name[64];
	int	alg_key_len;    /* in bits */
	char	alg_key[0];
};

struct xfrm_stats {
	uint32_t	replay_window;
	uint32_t	replay;
	uint32_t	integrity_failed;
};

enum
{
	XFRM_POLICY_IN	= 0,
	XFRM_POLICY_OUT	= 1,
	XFRM_POLICY_FWD	= 2,
	XFRM_POLICY_MAX	= 3
};

enum
{
	XFRM_SHARE_ANY,		/* No limitations */
	XFRM_SHARE_SESSION,	/* For this session only */
	XFRM_SHARE_USER,	/* For this user only */
	XFRM_SHARE_UNIQUE	/* Use once */
};

/* Netlink configuration messages.  */
#define XFRM_MSG_BASE		0x10

#define XFRM_MSG_NEWSA		(XFRM_MSG_BASE + 0)
#define XFRM_MSG_DELSA		(XFRM_MSG_BASE + 1)
#define XFRM_MSG_GETSA		(XFRM_MSG_BASE + 2)

#define XFRM_MSG_NEWPOLICY	(XFRM_MSG_BASE + 3)
#define XFRM_MSG_DELPOLICY	(XFRM_MSG_BASE + 4)
#define XFRM_MSG_GETPOLICY	(XFRM_MSG_BASE + 5)

#define XFRM_MSG_ALLOCSPI	(XFRM_MSG_BASE + 6)
#define XFRM_MSG_ACQUIRE	(XFRM_MSG_BASE + 7)
#define XFRM_MSG_EXPIRE		(XFRM_MSG_BASE + 8)

#define XFRM_MSG_UPDPOLICY	(XFRM_MSG_BASE + 9)
#define XFRM_MSG_UPDSA		(XFRM_MSG_BASE + 10)

#define XFRM_MSG_POLEXPIRE	(XFRM_MSG_BASE + 11)

#define XFRM_MSG_MAX		(XFRM_MSG_POLEXPIRE+1)

struct xfrm_user_tmpl {
	struct xfrm_id		id;
	uint16_t		family;
	xfrm_address_t		saddr;
	uint32_t		reqid;
	uint8_t			mode;
	uint8_t			share;
	uint8_t			optional;
	uint32_t		aalgos;
	uint32_t		ealgos;
	uint32_t		calgos;
};

struct xfrm_encap_tmpl {
	uint16_t		encap_type;
	uint16_t		encap_sport;
	uint16_t		encap_dport;
	xfrm_address_t		encap_oa;
};

/* Netlink message attributes.  */
enum xfrm_attr_type_t {
	XFRMA_UNSPEC,
	XFRMA_ALG_AUTH,		/* struct xfrm_algo */
	XFRMA_ALG_CRYPT,	/* struct xfrm_algo */
	XFRMA_ALG_COMP,		/* struct xfrm_algo */
	XFRMA_ENCAP,		/* struct xfrm_algo + struct xfrm_encap_tmpl */
	XFRMA_TMPL,		/* 1 or more struct xfrm_user_tmpl */

#define XFRMA_MAX XFRMA_TMPL
};

struct xfrm_usersa_info {
	struct xfrm_selector		sel;
	struct xfrm_id			id;
	xfrm_address_t			saddr;
	struct xfrm_lifetime_cfg	lft;
	struct xfrm_lifetime_cur	curlft;
	struct xfrm_stats		stats;
	uint32_t			seq;
	uint32_t			reqid;
	uint16_t			family;
	uint8_t				mode; /* 0=transport,1=tunnel */
	uint8_t				replay_window;
	uint8_t				flags;
#define XFRM_STATE_NOECN	1
};

struct xfrm_usersa_id {
	xfrm_address_t			daddr;
	uint32_t			spi;
	uint16_t			family;
	uint8_t				proto;
};

struct xfrm_userspi_info {
	struct xfrm_usersa_info		info;
	uint32_t			min;
	uint32_t			max;
};

struct xfrm_userpolicy_info {
	struct xfrm_selector		sel;
	struct xfrm_lifetime_cfg	lft;
	struct xfrm_lifetime_cur	curlft;
	uint32_t			priority;
	uint32_t			index;
	uint8_t				dir;
	uint8_t				action;
#define XFRM_POLICY_ALLOW	0
#define XFRM_POLICY_BLOCK	1
	uint8_t				flags;
#define XFRM_POLICY_LOCALOK	1	/* Allow user to override global policy */
	uint8_t				share;
};

struct xfrm_userpolicy_id {
	struct xfrm_selector		sel;
	uint32_t			index;
	uint8_t				dir;
};

struct xfrm_user_acquire {
	struct xfrm_id			id;
	xfrm_address_t			saddr;
	struct xfrm_selector		sel;
	struct xfrm_userpolicy_info	policy;
	uint32_t			aalgos;
	uint32_t			ealgos;
	uint32_t			calgos;
	uint32_t			seq;
};

struct xfrm_user_expire {
	struct xfrm_usersa_info		state;
	uint8_t				hard;
};

struct xfrm_user_polexpire {
	struct xfrm_userpolicy_info	pol;
	uint8_t				hard;
};

#define XFRMGRP_ACQUIRE		1
#define XFRMGRP_EXPIRE		2

#endif /* _LINUX_XFRM_H */
