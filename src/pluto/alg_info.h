/* Algorithm info parsing and creation functions
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

#ifndef ALG_INFO_H
#define ALG_INFO_H

struct esp_info {
		u_int8_t transid;       /* ESP transform */
		u_int16_t auth;         /* AUTH */
		size_t enckeylen;       /* keylength for ESP transform */
		size_t authkeylen;      /* keylength for AUTH */
		u_int8_t encryptalg;    /* normally  encryptalg=transid */
		u_int8_t authalg;       /* normally  authalg=auth+1 */
};

struct ike_info {
		u_int16_t ike_ealg;     /* high 16 bit nums for reserved */
		u_int8_t ike_halg;
		size_t ike_eklen;
		size_t ike_hklen;
		u_int16_t ike_modp;
};

#define ALG_INFO_COMMON \
		int alg_info_cnt;               \
		int ref_cnt;                    \
		unsigned alg_info_flags;        \
		unsigned alg_info_protoid

struct alg_info {
		ALG_INFO_COMMON;
};

struct alg_info_esp {
		ALG_INFO_COMMON;
		struct esp_info esp[64];
		int esp_pfsgroup;
};

struct alg_info_ike {
		ALG_INFO_COMMON;
		struct ike_info ike[64];
};
#define esp_ealg_id transid
#define esp_aalg_id auth
#define esp_ealg_keylen enckeylen       /* bits */
#define esp_aalg_keylen authkeylen      /* bits */

/*      alg_info_flags bits */
#define ALG_INFO_F_STRICT       0x01

extern int alg_info_esp_aa2sadb(int auth);
extern int alg_info_esp_sadb2aa(int sadb_aalg);
extern void alg_info_free(struct alg_info *alg_info);
extern void alg_info_addref(struct alg_info *alg_info);
extern void alg_info_delref(struct alg_info **alg_info);
extern struct alg_info_esp* alg_info_esp_create_from_str(char *alg_str);
extern struct alg_info_ike* alg_info_ike_create_from_str(char *alg_str);
extern int alg_info_parse(const char *str);
extern int alg_info_snprint(char *buf, int buflen, struct alg_info *alg_info);
extern int alg_info_snprint_esp(char *buf, int buflen
	, struct alg_info_esp *alg_info);
extern int alg_info_snprint_ike(char *buf, int buflen
	, struct alg_info_ike *alg_info);
#define ALG_INFO_ESP_FOREACH(ai, ai_esp, i) \
		for (i=(ai)->alg_info_cnt,ai_esp=(ai)->esp; i--; ai_esp++) 
#define ALG_INFO_IKE_FOREACH(ai, ai_ike, i) \
		for (i=(ai)->alg_info_cnt,ai_ike=(ai)->ike; i--; ai_ike++) 
#endif /* ALG_INFO_H */
