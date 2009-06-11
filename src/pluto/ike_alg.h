/* IKE modular algorithm handling interface
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
 */

#ifndef _IKE_ALG_H
#define _IKE_ALG_H

#include <freeswan.h>

#include "connections.h"

struct ike_alg {
	u_int16_t algo_type;
	u_int16_t algo_id;
	struct ike_alg *algo_next;
};

struct encrypt_desc {
	u_int16_t algo_type;
	u_int16_t algo_id;
	struct ike_alg *algo_next;

	size_t enc_blocksize;
	u_int keydeflen;
	u_int keymaxlen;
	u_int keyminlen;
};

struct hash_desc {
	u_int16_t algo_type;
	u_int16_t algo_id;
	struct ike_alg *algo_next;

	size_t hash_digest_size;
};

struct dh_desc {
	u_int16_t algo_type;
	u_int16_t algo_id;
	struct ike_alg *algo_next;

	size_t ke_size;
};

#define IKE_ALG_ENCRYPT         0
#define IKE_ALG_HASH            1
#define IKE_ALG_DH_GROUP		2
#define IKE_ALG_MAX             IKE_ALG_DH_GROUP

extern int ike_alg_add(struct ike_alg *a);
extern struct hash_desc *ike_alg_get_hasher(u_int alg);
extern struct encrypt_desc *ike_alg_get_crypter(u_int alg);
extern struct dh_desc *ike_alg_get_dh_group(u_int alg);
extern const struct dh_desc* ike_alg_pfsgroup(struct connection *c, lset_t policy);
extern struct db_context * ike_alg_db_new(struct alg_info_ike *ai, lset_t policy);
extern void ike_alg_list(void);
extern void ike_alg_show_connection(struct connection *c, const char *instance);
extern bool ike_alg_ok_final(u_int ealg, u_int key_len, u_int aalg, u_int group
	, struct alg_info_ike *alg_info_ike);
extern int ike_alg_init(void);

#endif /* _IKE_ALG_H */
