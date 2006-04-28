/* Kernel runtime algorithm handling interface definitions
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
 * RCSID $Id: kernel_alg.h,v 1.5 2005/08/17 16:31:24 as Exp $
 */

#ifndef _KERNEL_ALG_H
#define _KERNEL_ALG_H

#include "alg_info.h"
#include "spdb.h"

/* status info */
extern void kernel_alg_show_status(void);
void kernel_alg_show_connection(struct connection *c, const char *instance);

/* Registration messages from pluto */
extern void kernel_alg_register_pfkey(const struct sadb_msg *msg, int buflen);

/* ESP interface */
extern struct sadb_alg *kernel_alg_esp_sadb_alg(u_int alg_id);
extern u_int kernel_alg_esp_ivlen(u_int alg_id);
extern bool kernel_alg_esp_enc_ok(u_int alg_id, u_int key_len, struct alg_info_esp *nfo);
extern bool kernel_alg_esp_ok_final(u_int ealg, u_int key_len, u_int aalg, struct alg_info_esp *alg_info);
extern u_int kernel_alg_esp_enc_keylen(u_int alg_id);
extern bool kernel_alg_esp_auth_ok(u_int auth, struct alg_info_esp *nfo);
extern u_int kernel_alg_esp_auth_keylen(u_int auth);
extern int kernel_alg_proc_read(void);
extern void kernel_alg_list(void);

/* get sadb_alg for passed args */
extern const struct sadb_alg * kernel_alg_sadb_alg_get(int satype, int exttype, int alg_id);

extern struct db_context * kernel_alg_db_new(struct alg_info_esp *ai, lset_t policy);
struct esp_info * kernel_alg_esp_info(int esp_id, int auth_id);
#endif /* _KERNEL_ALG_H */
