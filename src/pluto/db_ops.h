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

#ifndef _DB_OPS_H
#define _DB_OPS_H

/*
 * 	Main db object, (quite proposal "oriented")
 */
#ifndef NO_DB_CONTEXT
struct db_context {
	struct db_prop prop;		/* proposal buffer (not pointer) */
	struct db_trans *trans0;	/* transf. list, dynamically sized */
	struct db_trans *trans_cur;	/* current transform ptr */
	struct db_attr *attrs0;		/* attr. list, dynamically sized */
	struct db_attr *attrs_cur;	/* current attribute ptr */
	int max_trans;			/* size of trans list */
	int max_attrs;			/* size of attrs list */
};
/*
 * 	Allocate a new db object
 */
struct db_context * db_prop_new(u_int8_t protoid, int max_trans, int max_attrs);
/*	Initialize object for proposal building  */
int db_prop_init(struct db_context *ctx, u_int8_t protoid, int max_trans, int max_attrs);
/*	Free all resourses for this db */
void db_destroy(struct db_context *ctx);

/*	Start a new transform */
int db_trans_add(struct db_context *ctx, u_int8_t transid);
/*	Add a new attribute by copying db_attr content */
int db_attr_add(struct db_context *db_ctx, const struct db_attr *attr);
/*	Add a new attribute by value */
int db_attr_add_values(struct db_context *ctx,  u_int16_t type, u_int16_t val);

/*	Get proposal from db object */
static __inline__ struct db_prop *db_prop_get(struct db_context *ctx) {
	return &ctx->prop;
}
/*	Show stats (allocation, etc) */
#endif /* NO_DB_CONTEXT */
int db_ops_show_status(void);
#endif /* _DB_OPS_H */
