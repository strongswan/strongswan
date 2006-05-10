#ifndef _FREESWAN_H
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
 * RCSID $Id: freeswan.h,v 1.2 2004/03/22 21:53:17 as Exp $
 */
#define	_FREESWAN_H	/* seen it, no need to see it again */



/*
 * We've just got to have some datatypes defined...  And annoyingly, just
 * where we get them depends on whether we're in userland or not.
 */
#ifdef __KERNEL__

#  include <linux/types.h>
#  include <linux/in.h>

#else /* __KERNEL__ */

#  include <stdio.h>
#  include <netinet/in.h>

#  define uint8_t u_int8_t
#  define uint16_t u_int16_t 
#  define uint32_t u_int32_t 
#  define uint64_t u_int64_t 

#  define DEBUG_NO_STATIC static

#endif /* __KERNEL__ */

#include <freeswan/ipsec_param.h>


/*
 * Grab the kernel version to see if we have NET_21, and therefore 
 * IPv6. Some of this is repeated from ipsec_kversions.h. Of course, 
 * we aren't really testing if the kernel has IPv6, but rather if the
 * the include files do.
 */
#include <linux/version.h>
#ifndef KERNEL_VERSION
#define KERNEL_VERSION(x,y,z) (((x)<<16)+((y)<<8)+(z))
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,1,0)
#define NET_21
#endif

#ifndef IPPROTO_COMP
#  define IPPROTO_COMP 108
#endif /* !IPPROTO_COMP */

#ifndef IPPROTO_INT
#  define IPPROTO_INT 61
#endif /* !IPPROTO_INT */

#ifdef CONFIG_IPSEC_DEBUG
#  define DEBUG_NO_STATIC
#else /* CONFIG_IPSEC_DEBUG */
#  define DEBUG_NO_STATIC static
#endif /* CONFIG_IPSEC_DEBUG */

#ifdef CONFIG_IPSEC_NAT_TRAVERSAL /* KERNEL ifdef */
#ifndef NAT_TRAVERSAL
#define NAT_TRAVERSAL
#endif
#endif
#ifdef NAT_TRAVERSAL
#define ESPINUDP_WITH_NON_IKE   1  /* draft-ietf-ipsec-nat-t-ike-00/01 */
#define ESPINUDP_WITH_NON_ESP   2  /* draft-ietf-ipsec-nat-t-ike-02    */
#endif

/*
 * Basic data types for the address-handling functions.
 * ip_address and ip_subnet are supposed to be opaque types; do not
 * use their definitions directly, they are subject to change!
 */

/* first, some quick fakes in case we're on an old system with no IPv6 */
#ifndef s6_addr16
struct in6_addr {
	union 
	{
		__u8		u6_addr8[16];
		__u16		u6_addr16[8];
		__u32		u6_addr32[4];
	} in6_u;
#define s6_addr			in6_u.u6_addr8
#define s6_addr16		in6_u.u6_addr16
#define s6_addr32		in6_u.u6_addr32
};
struct sockaddr_in6 {
	unsigned short int	sin6_family;    /* AF_INET6 */
	__u16			sin6_port;      /* Transport layer port # */
	__u32			sin6_flowinfo;  /* IPv6 flow information */
	struct in6_addr		sin6_addr;      /* IPv6 address */
	__u32			sin6_scope_id;  /* scope id (new in RFC2553) */
};
#endif	/* !s6_addr16 */

/* then the main types */
typedef struct {
	union {
		struct sockaddr_in v4;
		struct sockaddr_in6 v6;
	} u;
} ip_address;
typedef struct {
	ip_address addr;
	int maskbits;
} ip_subnet;

/* and the SA ID stuff */
#ifdef __KERNEL__
typedef __u32 ipsec_spi_t;
#else
typedef u_int32_t ipsec_spi_t;
#endif
typedef struct {		/* to identify an SA, we need: */
        ip_address dst;		/* A. destination host */
        ipsec_spi_t spi;	/* B. 32-bit SPI, assigned by dest. host */
#		define	SPI_PASS	256	/* magic values... */
#		define	SPI_DROP	257	/* ...for use... */
#		define	SPI_REJECT	258	/* ...with SA_INT */
#		define	SPI_HOLD	259
#		define	SPI_TRAP	260
#		define  SPI_TRAPSUBNET  261
	int proto;		/* C. protocol */
#		define	SA_ESP	50	/* IPPROTO_ESP */
#		define	SA_AH	51	/* IPPROTO_AH */
#		define	SA_IPIP	4	/* IPPROTO_IPIP */
#		define	SA_COMP	108	/* IPPROTO_COMP */
#		define	SA_INT	61	/* IANA reserved for internal use */
} ip_said;
struct sa_id {			/* old v4-only version */
        struct in_addr dst;
        ipsec_spi_t spi;
	int proto;
};

/* misc */
typedef const char *err_t;	/* error message, or NULL for success */
struct prng {			/* pseudo-random-number-generator guts */
	unsigned char sbox[256];
	int i, j;
	unsigned long count;
};


/*
 * definitions for user space, taken from freeswan/ipsec_sa.h
 */
typedef uint32_t IPsecSAref_t;

#define IPSEC_SA_REF_FIELD_WIDTH (8 * sizeof(IPsecSAref_t))

#define IPsecSAref2NFmark(x) ((x) << (IPSEC_SA_REF_FIELD_WIDTH - IPSEC_SA_REF_TABLE_IDX_WIDTH))
#define NFmark2IPsecSAref(x) ((x) >> (IPSEC_SA_REF_FIELD_WIDTH - IPSEC_SA_REF_TABLE_IDX_WIDTH))

#define IPSEC_SAREF_NULL (~((IPsecSAref_t)0))

/* GCC magic for use in function definitions! */
#ifdef GCC_LINT
# define PRINTF_LIKE(n) __attribute__ ((format(printf, n, n+1)))
# define NEVER_RETURNS __attribute__ ((noreturn))
# define UNUSED __attribute__ ((unused))
# define BLANK_FORMAT " "	/* GCC_LINT whines about empty formats */
#else
# define PRINTF_LIKE(n)	/* ignore */
# define NEVER_RETURNS /* ignore */
# define UNUSED /* ignore */
# define BLANK_FORMAT ""
#endif





/*
 * new IPv6-compatible functions
 */

/* text conversions */
err_t ttoul(const char *src, size_t srclen, int format, unsigned long *dst);
size_t ultot(unsigned long src, int format, char *buf, size_t buflen);
#define	ULTOT_BUF	(22+1)	/* holds 64 bits in octal */
err_t ttoaddr(const char *src, size_t srclen, int af, ip_address *dst);
err_t tnatoaddr(const char *src, size_t srclen, int af, ip_address *dst);
size_t addrtot(const ip_address *src, int format, char *buf, size_t buflen);
/* RFC 1886 old IPv6 reverse-lookup format is the bulkiest */
#define	ADDRTOT_BUF	(32*2 + 3 + 1 + 3 + 1 + 1)
err_t ttosubnet(const char *src, size_t srclen, int af, ip_subnet *dst);
size_t subnettot(const ip_subnet *src, int format, char *buf, size_t buflen);
#define	SUBNETTOT_BUF	(ADDRTOT_BUF + 1 + 3)
err_t ttosa(const char *src, size_t srclen, ip_said *dst);
size_t satot(const ip_said *src, int format, char *bufptr, size_t buflen);
#define	SATOT_BUF	(5 + ULTOA_BUF + 1 + ADDRTOT_BUF)
err_t ttodata(const char *src, size_t srclen, int base, char *buf,
						size_t buflen, size_t *needed);
err_t ttodatav(const char *src, size_t srclen, int base,
	       char *buf,  size_t buflen, size_t *needed,
	       char *errp, size_t errlen, unsigned int flags);
#define	TTODATAV_BUF	40	/* ttodatav's largest non-literal message */
#define TTODATAV_IGNORESPACE  (1<<1)  /* ignore spaces in base64 encodings*/
#define TTODATAV_SPACECOUNTS  0       /* do not ignore spaces in base64   */

size_t datatot(const char *src, size_t srclen, int format, char *buf,
								size_t buflen);
size_t keyblobtoid(const unsigned char *src, size_t srclen, char *dst,
								size_t dstlen);
size_t splitkeytoid(const unsigned char *e, size_t elen, const unsigned char *m,
					size_t mlen, char *dst, size_t dstlen);
#define	KEYID_BUF		10	/* up to 9 text digits plus NUL */
err_t ttoprotoport(char *src, size_t src_len, u_int8_t *proto, u_int16_t *port,
							int *has_port_wildcard);

/* initializations */
void initsaid(const ip_address *addr, ipsec_spi_t spi, int proto, ip_said *dst);
err_t loopbackaddr(int af, ip_address *dst);
err_t unspecaddr(int af, ip_address *dst);
err_t anyaddr(int af, ip_address *dst);
err_t initaddr(const unsigned char *src, size_t srclen, int af, ip_address *dst);
err_t initsubnet(const ip_address *addr, int maskbits, int clash, ip_subnet *dst);
err_t addrtosubnet(const ip_address *addr, ip_subnet *dst);

/* misc. conversions and related */
err_t rangetosubnet(const ip_address *from, const ip_address *to, ip_subnet *dst);
int addrtypeof(const ip_address *src);
int subnettypeof(const ip_subnet *src);
size_t addrlenof(const ip_address *src);
size_t addrbytesptr(const ip_address *src, const unsigned char **dst);
size_t addrbytesof(const ip_address *src, unsigned char *dst, size_t dstlen);
int masktocount(const ip_address *src);
void networkof(const ip_subnet *src, ip_address *dst);
void maskof(const ip_subnet *src, ip_address *dst);

/* tests */
int sameaddr(const ip_address *a, const ip_address *b);
int addrcmp(const ip_address *a, const ip_address *b);
int samesubnet(const ip_subnet *a, const ip_subnet *b);
int addrinsubnet(const ip_address *a, const ip_subnet *s);
int subnetinsubnet(const ip_subnet *a, const ip_subnet *b);
int subnetishost(const ip_subnet *s);
int samesaid(const ip_said *a, const ip_said *b);
int sameaddrtype(const ip_address *a, const ip_address *b);
int samesubnettype(const ip_subnet *a, const ip_subnet *b);
int isanyaddr(const ip_address *src);
int isunspecaddr(const ip_address *src);
int isloopbackaddr(const ip_address *src);

/* low-level grot */
int portof(const ip_address *src);
void setportof(int port, ip_address *dst);
struct sockaddr *sockaddrof(ip_address *src);
size_t sockaddrlenof(const ip_address *src);

/* PRNG */
void prng_init(struct prng *prng, const unsigned char *key, size_t keylen);
void prng_bytes(struct prng *prng, unsigned char *dst, size_t dstlen);
unsigned long prng_count(struct prng *prng);
void prng_final(struct prng *prng);

/* odds and ends */
const char *ipsec_version_code(void);
const char *ipsec_version_string(void);
const char **ipsec_copyright_notice(void);

const char *dns_string_rr(int rr, char *buf, int bufsize);
const char *dns_string_datetime(time_t seconds,
				char *buf,
				int bufsize);


/*
 * old functions, to be deleted eventually
 */

/* unsigned long */
const char *			/* NULL for success, else string literal */
atoul(
	const char *src,
	size_t srclen,		/* 0 means strlen(src) */
	int base,		/* 0 means figure it out */
	unsigned long *resultp
);
size_t				/* space needed for full conversion */
ultoa(
	unsigned long n,
	int base,
	char *dst,
	size_t dstlen
);
#define	ULTOA_BUF	21	/* just large enough for largest result, */
				/* assuming 64-bit unsigned long! */

/* Internet addresses */
const char *			/* NULL for success, else string literal */
atoaddr(
	const char *src,
	size_t srclen,		/* 0 means strlen(src) */
	struct in_addr *addr
);
size_t				/* space needed for full conversion */
addrtoa(
	struct in_addr addr,
	int format,		/* character; 0 means default */
	char *dst,
	size_t dstlen
);
#define	ADDRTOA_BUF	16	/* just large enough for largest result */

/* subnets */
const char *			/* NULL for success, else string literal */
atosubnet(
	const char *src,
	size_t srclen,		/* 0 means strlen(src) */
	struct in_addr *addr,
	struct in_addr *mask
);
size_t				/* space needed for full conversion */
subnettoa(
	struct in_addr addr,
	struct in_addr mask,
	int format,		/* character; 0 means default */
	char *dst,
	size_t dstlen
);
#define	SUBNETTOA_BUF	32	/* large enough for worst case result */

/* ranges */
const char *			/* NULL for success, else string literal */
atoasr(
	const char *src,
	size_t srclen,		/* 0 means strlen(src) */
	char *type,		/* 'a', 's', 'r' */
	struct in_addr *addrs	/* two-element array */
);
size_t				/* space needed for full conversion */
rangetoa(
	struct in_addr *addrs,	/* two-element array */
	int format,		/* character; 0 means default */
	char *dst,
	size_t dstlen
);
#define	RANGETOA_BUF	34	/* large enough for worst case result */

/* data types for SA conversion functions */

/* SAs */
const char *			/* NULL for success, else string literal */
atosa(
	const char *src,
	size_t srclen,		/* 0 means strlen(src) */
	struct sa_id *sa
);
size_t				/* space needed for full conversion */
satoa(
	struct sa_id sa,
	int format,		/* character; 0 means default */
	char *dst,
	size_t dstlen
);
#define	SATOA_BUF	(3+ULTOA_BUF+ADDRTOA_BUF)

/* generic data, e.g. keys */
const char *			/* NULL for success, else string literal */
atobytes(
	const char *src,
	size_t srclen,		/* 0 means strlen(src) */
	char *dst,
	size_t dstlen,
	size_t *lenp		/* NULL means don't bother telling me */
);
size_t				/* 0 failure, else true size */
bytestoa(
	const char *src,
	size_t srclen,
	int format,		/* character; 0 means default */
	char *dst,
	size_t dstlen
);

/* old versions of generic-data functions; deprecated */
size_t				/* 0 failure, else true size */
atodata(
	const char *src,
	size_t srclen,		/* 0 means strlen(src) */
	char *dst,
	size_t dstlen
);
size_t				/* 0 failure, else true size */
datatoa(
	const char *src,
	size_t srclen,
	int format,		/* character; 0 means default */
	char *dst,
	size_t dstlen
);

/* part extraction and special addresses */
struct in_addr
subnetof(
	struct in_addr addr,
	struct in_addr mask
);
struct in_addr
hostof(
	struct in_addr addr,
	struct in_addr mask
);
struct in_addr
broadcastof(
	struct in_addr addr,
	struct in_addr mask
);

/* mask handling */
int
goodmask(
	struct in_addr mask
);
int
masktobits(
	struct in_addr mask
);
struct in_addr
bitstomask(
	int n
);



/*
 * general utilities
 */

#ifndef __KERNEL__
/* option pickup from files (userland only because of use of FILE) */
const char *optionsfrom(const char *filename, int *argcp, char ***argvp,
						int optind, FILE *errorreport);
#endif

/*
 * Debugging levels for pfkey_lib_debug
 */
#define PF_KEY_DEBUG_PARSE_NONE    0
#define PF_KEY_DEBUG_PARSE_PROBLEM 1
#define PF_KEY_DEBUG_PARSE_STRUCT  2
#define PF_KEY_DEBUG_PARSE_FLOW    4
#define PF_KEY_DEBUG_PARSE_MAX     7

extern unsigned int pfkey_lib_debug;  /* bits selecting what to report */

/*
 * pluto and lwdnsq need to know the maximum size of the commands to,
 * and replies from lwdnsq. 
 */

#define LWDNSQ_CMDBUF_LEN      1024
#define LWDNSQ_RESULT_LEN_MAX  4096

#endif /* _FREESWAN_H */
