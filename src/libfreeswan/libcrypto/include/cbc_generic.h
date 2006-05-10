#ifndef _CBC_GENERIC_H
#define _CBC_GENERIC_H
/*
 * CBC macro helpers
 *
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
 */

/*
 * 	Heavily inspired in loop_AES
 */
#define CBC_IMPL_BLK16(name, ctx_type, addr_type, enc_func, dec_func) \
int name(ctx_type *ctx, const u_int8_t * in, u_int8_t * out, int ilen, const u_int8_t * iv, int encrypt) { \
	int ret=ilen, pos; \
	const u_int32_t *iv_i; \
	if ((ilen) % 16) return 0; \
	if (encrypt) { \
		pos=0; \
		while(pos<ilen) { \
			if (pos==0) \
				iv_i=(const u_int32_t*) iv; \
			else \
				iv_i=(const u_int32_t*) (out-16); \
			*((u_int32_t *)(&out[ 0])) = iv_i[0]^*((const u_int32_t *)(&in[ 0])); \
			*((u_int32_t *)(&out[ 4])) = iv_i[1]^*((const u_int32_t *)(&in[ 4])); \
			*((u_int32_t *)(&out[ 8])) = iv_i[2]^*((const u_int32_t *)(&in[ 8])); \
			*((u_int32_t *)(&out[12])) = iv_i[3]^*((const u_int32_t *)(&in[12])); \
			enc_func(ctx, (addr_type) out, (addr_type) out); \
			in+=16; \
			out+=16; \
			pos+=16; \
		} \
	} else { \
		pos=ilen-16; \
		in+=pos; \
		out+=pos; \
		while(pos>=0) { \
			dec_func(ctx, (const addr_type) in, (addr_type) out); \
			if (pos==0) \
				iv_i=(const u_int32_t*) (iv); \
			else \
				iv_i=(const u_int32_t*) (in-16); \
			*((u_int32_t *)(&out[ 0])) ^= iv_i[0]; \
			*((u_int32_t *)(&out[ 4])) ^= iv_i[1]; \
			*((u_int32_t *)(&out[ 8])) ^= iv_i[2]; \
			*((u_int32_t *)(&out[12])) ^= iv_i[3]; \
			in-=16; \
			out-=16; \
			pos-=16; \
		} \
	} \
	return ret; \
} 
#define CBC_IMPL_BLK8(name, ctx_type, addr_type,  enc_func, dec_func) \
int name(ctx_type *ctx, u_int8_t * in, u_int8_t * out, int ilen, const u_int8_t * iv, int encrypt) { \
	int ret=ilen, pos; \
	const u_int32_t *iv_i; \
	if ((ilen) % 8) return 0; \
	if (encrypt) { \
		pos=0; \
		while(pos<ilen) { \
			if (pos==0) \
				iv_i=(const u_int32_t*) iv; \
			else \
				iv_i=(const u_int32_t*) (out-8); \
			*((u_int32_t *)(&out[ 0])) = iv_i[0]^*((const u_int32_t *)(&in[ 0])); \
			*((u_int32_t *)(&out[ 4])) = iv_i[1]^*((const u_int32_t *)(&in[ 4])); \
			enc_func(ctx, (addr_type)out, (addr_type)out); \
			in+=8; \
			out+=8; \
			pos+=8; \
		} \
	} else { \
		pos=ilen-8; \
		in+=pos; \
		out+=pos; \
		while(pos>=0) { \
			dec_func(ctx, (const addr_type)in, (addr_type)out); \
			if (pos==0) \
				iv_i=(const u_int32_t*) (iv); \
			else \
				iv_i=(const u_int32_t*) (in-8); \
			*((u_int32_t *)(&out[ 0])) ^= iv_i[0]; \
			*((u_int32_t *)(&out[ 4])) ^= iv_i[1]; \
			in-=8; \
			out-=8; \
			pos-=8; \
		} \
	} \
	return ret; \
} 
#define CBC_DECL(name, ctx_type) \
int name(ctx_type *ctx, u_int8_t * in, u_int8_t * out, int ilen, const u_int8_t * iv, int encrypt)
/*
Eg.:
CBC_IMPL_BLK16(AES_cbc_encrypt, aes_context, u_int8_t *, aes_encrypt, aes_decrypt);
CBC_DECL(AES_cbc_encrypt, aes_context);
*/
#endif /* _CBC_GENERIC_H */
