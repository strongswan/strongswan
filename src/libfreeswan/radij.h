/*
 * RCSID $Id$
 */

/*
 * This file is defived from ${SRC}/sys/net/radix.h of BSD 4.4lite
 *
 * Variable and procedure names have been modified so that they don't
 * conflict with the original BSD code, as a small number of modifications
 * have been introduced and we may want to reuse this code in BSD.
 * 
 * The `j' in `radij' is pronounced as a voiceless guttural (like a Greek
 * chi or a German ch sound (as `doch', not as in `milch'), or even a 
 * spanish j as in Juan.  It is not as far back in the throat like
 * the corresponding Hebrew sound, nor is it a soft breath like the English h.
 * It has nothing to do with the Dutch ij sound.
 * 
 * Here is the appropriate copyright notice:
 */

/*
 * Copyright (c) 1988, 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)radix.h	8.1 (Berkeley) 6/10/93
 */

#ifndef _RADIJ_H_
#define	_RADIJ_H_

/* 
#define RJ_DEBUG
*/

#ifdef __KERNEL__

#ifndef __P
#ifdef __STDC__
#define __P(x)  x
#else
#define __P(x)  ()
#endif
#endif

/*
 * Radix search tree node layout.
 */

struct radij_node
{
	struct	radij_mask *rj_mklist;	/* list of masks contained in subtree */
	struct	radij_node *rj_p;	/* parent */
	short	rj_b;			/* bit offset; -1-index(netmask) */
	char	rj_bmask;		/* node: mask for bit test*/
	u_char	rj_flags;		/* enumerated next */
#define RJF_NORMAL	1		/* leaf contains normal route */
#define RJF_ROOT	2		/* leaf is root leaf for tree */
#define RJF_ACTIVE	4		/* This node is alive (for rtfree) */
	union {
		struct {			/* leaf only data: */
			caddr_t	rj_Key;	/* object of search */
			caddr_t	rj_Mask;	/* netmask, if present */
			struct	radij_node *rj_Dupedkey;
		} rj_leaf;
		struct {			/* node only data: */
			int	rj_Off;		/* where to start compare */
			struct	radij_node *rj_L;/* progeny */
			struct	radij_node *rj_R;/* progeny */
		}rj_node;
	}		rj_u;
#ifdef RJ_DEBUG
	int rj_info;
	struct radij_node *rj_twin;
	struct radij_node *rj_ybro;
#endif
};

#define rj_dupedkey rj_u.rj_leaf.rj_Dupedkey
#define rj_key rj_u.rj_leaf.rj_Key
#define rj_mask rj_u.rj_leaf.rj_Mask
#define rj_off rj_u.rj_node.rj_Off
#define rj_l rj_u.rj_node.rj_L
#define rj_r rj_u.rj_node.rj_R

/*
 * Annotations to tree concerning potential routes applying to subtrees.
 */

extern struct radij_mask {
	short	rm_b;			/* bit offset; -1-index(netmask) */
	char	rm_unused;		/* cf. rj_bmask */
	u_char	rm_flags;		/* cf. rj_flags */
	struct	radij_mask *rm_mklist;	/* more masks to try */
	caddr_t	rm_mask;		/* the mask */
	int	rm_refs;		/* # of references to this struct */
} *rj_mkfreelist;

#define MKGet(m) {\
	if (rj_mkfreelist) {\
		m = rj_mkfreelist; \
		rj_mkfreelist = (m)->rm_mklist; \
	} else \
		R_Malloc(m, struct radij_mask *, sizeof (*(m))); }\

#define MKFree(m) { (m)->rm_mklist = rj_mkfreelist; rj_mkfreelist = (m);}

struct radij_node_head {
	struct	radij_node *rnh_treetop;
	int	rnh_addrsize;		/* permit, but not require fixed keys */
	int	rnh_pktsize;		/* permit, but not require fixed keys */
#if 0
	struct	radij_node *(*rnh_addaddr)	/* add based on sockaddr */
		__P((void *v, void *mask,
		     struct radij_node_head *head, struct radij_node nodes[]));
#endif
	int (*rnh_addaddr)	/* add based on sockaddr */
		__P((void *v, void *mask,
		     struct radij_node_head *head, struct radij_node nodes[]));
	struct	radij_node *(*rnh_addpkt)	/* add based on packet hdr */
		__P((void *v, void *mask,
		     struct radij_node_head *head, struct radij_node nodes[]));
#if 0
	struct	radij_node *(*rnh_deladdr)	/* remove based on sockaddr */
		__P((void *v, void *mask, struct radij_node_head *head));
#endif
	int (*rnh_deladdr)	/* remove based on sockaddr */
		__P((void *v, void *mask, struct radij_node_head *head, struct radij_node **node));
	struct	radij_node *(*rnh_delpkt)	/* remove based on packet hdr */
		__P((void *v, void *mask, struct radij_node_head *head));
	struct	radij_node *(*rnh_matchaddr)	/* locate based on sockaddr */
		__P((void *v, struct radij_node_head *head));
	struct	radij_node *(*rnh_matchpkt)	/* locate based on packet hdr */
		__P((void *v, struct radij_node_head *head));
	int	(*rnh_walktree)			/* traverse tree */
		__P((struct radij_node_head *head, int (*f)(struct radij_node *rn, void *w), void *w));
	struct	radij_node rnh_nodes[3];	/* empty tree for common case */
};


#define Bcmp(a, b, n) memcmp(((caddr_t)(b)), ((caddr_t)(a)), (unsigned)(n))
#define Bcopy(a, b, n) memmove(((caddr_t)(b)), ((caddr_t)(a)), (unsigned)(n))
#define Bzero(p, n) memset((caddr_t)(p), 0, (unsigned)(n))
#define R_Malloc(p, t, n) ((p = (t) kmalloc((size_t)(n), GFP_ATOMIC)), Bzero((p),(n)))
#define Free(p) kfree((caddr_t)p);

void	 rj_init __P((void));
int	 rj_inithead __P((void **, int));
int	 rj_refines __P((void *, void *));
int	 rj_walktree __P((struct radij_node_head *head, int (*f)(struct radij_node *rn, void *w), void *w));
struct radij_node
	 *rj_addmask __P((void *, int, int)) /* , rgb */ ;
int /* * */ rj_addroute __P((void *, void *, struct radij_node_head *,
			struct radij_node [2])) /* , rgb */ ;
int /* * */ rj_delete __P((void *, void *, struct radij_node_head *, struct radij_node **)) /* , rgb */ ;
struct radij_node /* rgb */
	 *rj_insert __P((void *, struct radij_node_head *, int *,
			struct radij_node [2])),
	 *rj_match __P((void *, struct radij_node_head *)),
	 *rj_newpair __P((void *, int, struct radij_node[2])),
	 *rj_search __P((void *, struct radij_node *)),
	 *rj_search_m __P((void *, struct radij_node *, void *));

void rj_deltree(struct radij_node_head *);
void rj_delnodes(struct radij_node *);
void rj_free_mkfreelist(void);
int radijcleartree(void);
int radijcleanup(void);

extern struct radij_node_head *mask_rjhead;
extern int maj_keylen;
#endif /* __KERNEL__ */

#endif /* _RADIJ_H_ */
