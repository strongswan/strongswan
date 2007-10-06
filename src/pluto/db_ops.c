/* Dynamic db (proposal, transforms, attributes) handling.
 * Author: JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>
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
 */

/* 
 * The stratedy is to have (full contained) struct db_prop in db_context
 * pointing to ONE dynamically sizable transform vector (trans0).
 * Each transform stores attrib. in ONE dyn. sizable attribute vector (attrs0)
 * in a "serialized" way (attributes storage is used in linear sequence for 
 * subsecuent transforms).
 *
 * Resizing for both trans0 and attrs0 is supported:
 * - For trans0: quite simple, just allocate and copy trans. vector content
 *               also update trans_cur (by offset)
 * - For attrs0: after allocating and copying attrs, I must rewrite each
 *               trans->attrs present in trans0; to achieve this, calculate
 *               attrs pointer offset (new minus old) and iterate over 
 *               each transform "adding" this difference.
 *               also update attrs_cur (by offset)
 *
 * db_context structure:
 * 	+---------------------+
 *	|  prop               |
 *	|    .protoid         |
 *	|    .trans           | --+
 *	|    .trans_cnt       |   |
 *	+---------------------+ <-+
 *	|  trans0             | ----> { trans#1 | ... | trans#i | ...   }
 *	+---------------------+                       ^
 *	|  trans_cur          | ----------------------' current transf.
 *	+---------------------+
 *	|  attrs0             | ----> { attr#1 | ... | attr#j | ...  }
 *	+---------------------+                      ^
 *	|  attrs_cur          | ---------------------' current attr.
 *	+---------------------+
 *	| max_trans,max_attrs |  max_trans/attrs: number of elem. of each vector
 *	+---------------------+
 *
 * See testing examples at end for interface usage.
 */
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <malloc.h>
#include <sys/types.h>

#include <freeswan.h>

#include "constants.h"
#include "defs.h"
#include "state.h"
#include "packet.h"
#include "spdb.h"
#include "db_ops.h"
#include "log.h"
#include "whack.h"

#include <assert.h>

#ifndef NO_PLUTO
#else
#define passert(x) assert(x)
extern int debug;	/* eg: spi.c */
#define DBG(cond, action)   { if (debug) { action ; } }
#define DBG_log(x, args...) fprintf(stderr, x "\n" , ##args);
#define alloc_thing(thing, name) alloc_bytes(sizeof (thing), name)
void * alloc_bytes(size_t size, const char *name) {
	void *p=malloc(size);
        if (p == NULL)
		fprintf(stderr, "unable to malloc %lu bytes for %s",
			(unsigned long) size, name);
	memset(p, '\0', size);
	return p;
}
#define pfreeany(ptr) free(ptr)

#endif

#ifdef NOT_YET
/*
 * 	Allocator cache:
 * 	Because of the single-threaded nature of pluto/spdb.c, 
 * 	alloc()/free() is exercised many times with very small
 * 	lifetime objects.
 * 	Just caching last object (currently it will select the
 * 	largest) will avoid this allocation mas^Wperturbations
 *
 */
struct db_ops_alloc_cache {
	void *ptr;
	int size;
};
#endif

#ifndef NO_DB_OPS_STATS
/* 	
 * 	stats: do account for allocations 	
 * 	displayed in db_ops_show_status() 
 */
struct db_ops_stats {
	int st_curr_cnt;	/* current number of allocations */
	int st_total_cnt;	/* total allocations so far */
	size_t st_maxsz;	/* max. size requested */
};
#define DB_OPS_ZERO { 0, 0, 0};
#define DB_OPS_STATS_DESC   "{curr_cnt, total_cnt, maxsz}"
#define DB_OPS_STATS_STR(name)  name "={%d,%d,%d} "
#define DB_OPS_STATS_F(st) (st).st_curr_cnt, (st).st_total_cnt, (int)(st).st_maxsz
static struct db_ops_stats db_context_st = DB_OPS_ZERO;
static struct db_ops_stats db_trans_st = DB_OPS_ZERO;
static struct db_ops_stats db_attrs_st = DB_OPS_ZERO;
static __inline__ void * alloc_bytes_st (size_t size, const char *str, struct db_ops_stats *st) 
{
	void *ptr = alloc_bytes(size, str);
	if (ptr)  {
		st->st_curr_cnt++;
		st->st_total_cnt++;
		if (size > st->st_maxsz) st->st_maxsz=size;
	}	
	return ptr;
}
#define ALLOC_BYTES_ST(z,s,st) alloc_bytes_st(z, s, &st);
#define PFREE_ST(p,st)         do { st.st_curr_cnt--; pfree(p);  } while (0);

#else

#define ALLOC_BYTES_ST(z,s,n) alloc_bytes(z, s);
#define PFREE_ST(p,n)         pfree(p);

#endif /* NO_DB_OPS_STATS */
/*	Initialize db object
 *	max_trans and max_attrs can be 0, will be dynamically expanded
 *	as a result of "add" operations
 */
int
db_prop_init(struct db_context *ctx, u_int8_t protoid, int max_trans, int max_attrs) 
{
	int ret=-1;

	ctx->trans0 = NULL;
	ctx->attrs0 = NULL;

	if (max_trans > 0) { /* quite silly if not */
		ctx->trans0 = ALLOC_BYTES_ST ( sizeof (struct db_trans) * max_trans, 
			"db_context->trans", db_trans_st);
		if (!ctx->trans0) goto out;
	}

	if (max_attrs > 0) { /* quite silly if not */
		ctx->attrs0 = ALLOC_BYTES_ST (sizeof (struct db_attr) * max_attrs,
				"db_context->attrs", db_attrs_st);
		if (!ctx->attrs0) goto out;
	}
	ret = 0;
out:
	if (ret < 0 && ctx->trans0) {
		PFREE_ST(ctx->trans0, db_trans_st);
		ctx->trans0 = NULL;
	}
	ctx->max_trans = max_trans;
	ctx->max_attrs = max_attrs;
	ctx->trans_cur = ctx->trans0;
	ctx->attrs_cur = ctx->attrs0;
	ctx->prop.protoid = protoid;
	ctx->prop.trans = ctx->trans0;
	ctx->prop.trans_cnt = 0;
	return ret;
}

/*	Expand storage for transforms by number delta_trans */
static int
db_trans_expand(struct db_context *ctx, int delta_trans)
{
	int ret = -1;
	struct db_trans *new_trans, *old_trans;
	int max_trans = ctx->max_trans + delta_trans;
	int offset;

	old_trans = ctx->trans0;
	new_trans = ALLOC_BYTES_ST ( sizeof (struct db_trans) * max_trans, 
			"db_context->trans (expand)", db_trans_st);
	if (!new_trans)
		goto out;
	memcpy(new_trans, old_trans, ctx->max_trans * sizeof(struct db_trans));
	
	/* update trans0 (obviously) */
	ctx->trans0 = ctx->prop.trans = new_trans;
	/* update trans_cur (by offset) */
	offset = (char *)(new_trans) - (char *)(old_trans);

	{
	  char *cctx = (char *)(ctx->trans_cur);
	  
	  cctx += offset;
	  ctx->trans_cur = (struct db_trans *)cctx;
	}
	/* update elem count */
	ctx->max_trans = max_trans;
	PFREE_ST(old_trans, db_trans_st);
	ret = 0;
out:
	return ret;
}
/*	
 *	Expand storage for attributes by delta_attrs number AND
 *	rewrite trans->attr pointers
 */
static int
db_attrs_expand(struct db_context *ctx, int delta_attrs)
{
	int ret = -1;
	struct db_attr *new_attrs, *old_attrs;
	struct db_trans *t;
	int ti;
	int max_attrs = ctx->max_attrs + delta_attrs;
	int offset;

	old_attrs = ctx->attrs0;
	new_attrs = ALLOC_BYTES_ST ( sizeof (struct db_attr) * max_attrs, 
			"db_context->attrs (expand)", db_attrs_st);
	if (!new_attrs)
		goto out;

	memcpy(new_attrs, old_attrs, ctx->max_attrs * sizeof(struct db_attr));
	
	/* update attrs0 and attrs_cur (obviously) */
	offset = (char *)(new_attrs) - (char *)(old_attrs);
	
	{
	  char *actx = (char *)(ctx->attrs0);
	  
	  actx += offset;
	  ctx->attrs0 = (struct db_attr *)actx;
	  
	  actx = (char *)ctx->attrs_cur;
	  actx += offset;
	  ctx->attrs_cur = (struct db_attr *)actx;
	}

	/* for each transform, rewrite attrs pointer by offsetting it */
	for (t=ctx->prop.trans, ti=0; ti < ctx->prop.trans_cnt; t++, ti++) {
		char *actx = (char *)(t->attrs);
 
		actx += offset;
		t->attrs = (struct db_attr *)actx;
	}
	/* update elem count */
	ctx->max_attrs = max_attrs;
	PFREE_ST(old_attrs, db_attrs_st);
	ret = 0;
out:
	return ret;
}
/*	Allocate a new db object */
struct db_context * 
db_prop_new(u_int8_t protoid, int max_trans, int max_attrs) 
{
	struct db_context *ctx;
	ctx = ALLOC_BYTES_ST ( sizeof (struct db_context), "db_context", db_context_st);
	if (!ctx) goto out;
	
	if (db_prop_init(ctx, protoid, max_trans, max_attrs) < 0) {
		PFREE_ST(ctx, db_context_st);
		ctx=NULL;
	}
out:
	return ctx;
}
/*	Free a db object */
void
db_destroy(struct db_context *ctx)
{
	if (ctx->trans0) PFREE_ST(ctx->trans0, db_trans_st);
	if (ctx->attrs0) PFREE_ST(ctx->attrs0, db_attrs_st);
	PFREE_ST(ctx, db_context_st);
}
/*	Start a new transform, expand trans0 is needed */
int
db_trans_add(struct db_context *ctx, u_int8_t transid)
{
	/*	skip incrementing current trans pointer the 1st time*/
	if (ctx->trans_cur && ctx->trans_cur->attr_cnt)
		ctx->trans_cur++;
	/*	
	 *	Strategy: if more space is needed, expand by 
	 *	          <current_size>/2 + 1
	 *
	 *	This happens to produce a "reasonable" sequence
	 *	after few allocations, eg.:
	 *	0,1,2,4,8,13,20,31,47
	 */
	if ((ctx->trans_cur - ctx->trans0) >= ctx->max_trans) {
		/* XXX:jjo if fails should shout and flag it */
		if (db_trans_expand(ctx, ctx->max_trans/2 + 1)<0)
			return -1;
	}
	ctx->trans_cur->transid = transid;
	ctx->trans_cur->attrs=ctx->attrs_cur;
	ctx->trans_cur->attr_cnt = 0;
	ctx->prop.trans_cnt++;
	return 0;
}
/*	Add attr copy to current transform, expanding attrs0 if needed */
int
db_attr_add(struct db_context *ctx, const struct db_attr *a) 
{
	/*	
	 *	Strategy: if more space is needed, expand by 
	 *	          <current_size>/2 + 1
	 */
	if ((ctx->attrs_cur - ctx->attrs0) >= ctx->max_attrs) {
		/* XXX:jjo if fails should shout and flag it */
		if (db_attrs_expand(ctx, ctx->max_attrs/2 + 1) < 0)
			return -1;
	}
	*ctx->attrs_cur++=*a;
	ctx->trans_cur->attr_cnt++;
	return 0;
}
/*	Add attr copy (by value) to current transform, 
 *	expanding attrs0 if needed, just calls db_attr_add().
 */
int
db_attr_add_values(struct db_context *ctx,  u_int16_t type, u_int16_t val)
{
	struct db_attr attr;
	attr.type = type;
	attr.val = val;
	return db_attr_add (ctx, &attr);
}
#ifndef NO_DB_OPS_STATS
int
db_ops_show_status(void)
{
	whack_log(RC_COMMENT, "stats " __FILE__ ": " 
			DB_OPS_STATS_DESC " :"
			DB_OPS_STATS_STR("context")
			DB_OPS_STATS_STR("trans")
			DB_OPS_STATS_STR("attrs"),
			DB_OPS_STATS_F(db_context_st),
			DB_OPS_STATS_F(db_trans_st),
			DB_OPS_STATS_F(db_attrs_st)
			);
	return 0;
}
#endif /* NO_DB_OPS_STATS */
/* 
 * From below to end just testing stuff ....
 */
#ifdef TEST
static void db_prop_print(struct db_prop *p)
{
	struct db_trans *t;
	struct db_attr *a;
	int ti, ai;
	enum_names *n, *n_at, *n_av;
	printf("protoid=\"%s\"\n", enum_name(&protocol_names, p->protoid));
	for (ti=0, t=p->trans; ti< p->trans_cnt; ti++, t++) {
		switch( t->transid) {
			case PROTO_ISAKMP:
				n=&isakmp_transformid_names;break;
			case PROTO_IPSEC_ESP:
				n=&esp_transformid_names;break;
			default:
				continue;
		}
		printf("  transid=\"%s\"\n", 
			enum_name(n, t->transid));
		for (ai=0, a=t->attrs; ai < t->attr_cnt; ai++, a++) {
			int i;
			switch( t->transid) {
				case PROTO_ISAKMP:
					n_at=&oakley_attr_names;
					i=a->type|ISAKMP_ATTR_AF_TV;
					n_av=oakley_attr_val_descs[(i)&ISAKMP_ATTR_RTYPE_MASK];
					break;
				case PROTO_IPSEC_ESP:
					n_at=&ipsec_attr_names;
					i=a->type|ISAKMP_ATTR_AF_TV;
					n_av=ipsec_attr_val_descs[(i)&ISAKMP_ATTR_RTYPE_MASK];
					break;
				default:
					continue;
			}
			printf("    type=\"%s\" value=\"%s\"\n", 
				enum_name(n_at, i),
				enum_name(n_av, a->val));
		}
	}

}
static void db_print(struct db_context *ctx) 
{
	printf("trans_cur diff=%d, attrs_cur diff=%d\n", 
			ctx->trans_cur - ctx->trans0,
			ctx->attrs_cur - ctx->attrs0);
	db_prop_print(&ctx->prop);
}

void
passert_fail(const char *pred_str, const char *file_str, unsigned long line_no);
void abort(void);
void
passert_fail(const char *pred_str, const char *file_str, unsigned long line_no)
{
    fprintf(stderr, "ASSERTION FAILED at %s:%lu: %s", file_str, line_no, pred_str);
    abort();	/* exiting correctly doesn't always work */
}
int main(void) {
	struct db_context *ctx=db_prop_new(PROTO_ISAKMP, 0, 0);
	db_trans_add(ctx, KEY_IKE);
	db_attr_add_values(ctx, OAKLEY_ENCRYPTION_ALGORITHM, OAKLEY_3DES_CBC);
	db_attr_add_values(ctx, OAKLEY_HASH_ALGORITHM, OAKLEY_MD5);
	db_attr_add_values(ctx, OAKLEY_AUTHENTICATION_METHOD, OAKLEY_RSA_SIG);
	db_attr_add_values(ctx, OAKLEY_GROUP_DESCRIPTION, OAKLEY_GROUP_MODP1024);
	db_trans_add(ctx, KEY_IKE);
	db_attr_add_values(ctx, OAKLEY_ENCRYPTION_ALGORITHM, OAKLEY_AES_CBC);
	db_attr_add_values(ctx, OAKLEY_HASH_ALGORITHM, OAKLEY_MD5);
	db_attr_add_values(ctx, OAKLEY_AUTHENTICATION_METHOD, OAKLEY_PRESHARED_KEY);
	db_attr_add_values(ctx, OAKLEY_GROUP_DESCRIPTION, OAKLEY_GROUP_MODP1536);
	db_trans_add(ctx, ESP_3DES);
	db_attr_add_values(ctx, AUTH_ALGORITHM, AUTH_ALGORITHM_HMAC_SHA1);
	db_print(ctx);
	db_destroy(ctx);
	return 0;
}
#endif
