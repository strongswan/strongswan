/*
 * MIT License
 *
 * Copyright (C) Microsoft Corporation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "frodo_utils.h"

/**
 * See header
 */
void frodo_pack(u_char *out, size_t outlen, uint16_t *in, size_t inlen,
				u_char lsb)
{
	size_t i = 0;      /* whole bytes already filled in    */
	size_t j = 0;      /* whole uint16_t already copied    */
	uint16_t w = 0;    /* the leftover, not yet copied     */
	u_char bits = 0;   /* the number of lsb in w           */

	memset(out, 0x00, outlen);

	while (i < outlen && (j < inlen || ((j == inlen) && (bits > 0))))
	{
		u_char b = 0;      /* bits in out[i] already filled in */

		/**
		 * in: |        |        |********|********|
		 *                       ^
		 *                       j
		 * w : |   ****|
		 *         ^
		 *        bits
		 * out:|**|**|**|**|**|**|**|**|* |
		 *                             ^^
		 *                             ib
		 */
		while (b < 8)
		{
			int nbits = min(8 - b, bits);
			uint16_t mask = (1 << nbits) - 1;
			u_char t = (w >> (bits - nbits)) & mask;  /* the bits to copy from w to out */

			out[i] = out[i] + (t << (8 - b - nbits));
			b += nbits;
			bits -= nbits;

			/* not strictly necessary; mostly for debugging */
			w &= ~(mask << bits);

			if (bits == 0)
			{
				if (j < inlen)
				{
					w = in[j];
					bits = lsb;
					j++;
				}
				else
				{
					break;  /* the input vector is exhausted */
				}
			}
		}
		if (b == 8)
		{
			i++;   /* out[i] is filled in */
		}
	}
}

/**
 * See header
 */
void frodo_unpack(uint16_t *out, size_t outlen, u_char *in, size_t inlen,
				  u_char lsb)
{
	size_t i = 0;      /* whole uint16_t already filled in */
	size_t j = 0;      /* whole bytes already copied       */
	u_char w = 0;      /* the leftover, not yet copied     */
	u_char bits = 0;   /* the number of lsb bits of w      */

	memset(out, 0, outlen * sizeof(uint16_t));

	while (i < outlen && (j < inlen || ((j == inlen) && (bits > 0))))
	{
		u_char b = 0;      /* bits in out[i] already filled in */

		/**
		 * in: |  |  |  |  |  |  |**|**|...
		 *                       ^
		 *                     j
		 * w : | *|
		 *       ^
		 *       bits
		 * out:|   *****|   *****|   ***  |        |...
		 *                       ^   ^
		 *                       i   b
		 */
		while (b < lsb)
		{
			int nbits = min(lsb - b, bits);
			uint16_t mask = (1 << nbits) - 1;
			u_char t = (w >> (bits - nbits)) & mask;  /* the bits to copy from w to out */

			out[i] = out[i] + (t << (lsb - b - nbits));
			b += nbits;
			bits -= nbits;

			/* not strictly necessary; mostly for debugging */
			w &= ~(mask << bits);

			if (bits == 0)
			{
				if (j < inlen)
				{
					w = in[j];
					bits = 8;
					j++;
				}
				else
				{
					break;  /* the input vector is exhausted */
				}
			}
		}
		if (b == lsb)
		{
			i++;  /* out[i] is filled in */
		}
	}
}

/**
 * See header
 */
void frodo_sample_n(const frodo_params_t *params, uint16_t *s, size_t n)
{
	int i, j;

	for (i = 0; i < n; i++)
	{
		uint8_t sample = 0;
		uint16_t prnd = s[i] >> 1;    /* Drop the least significant bit */
		uint8_t sign = s[i] & 0x1;    /* Pick the least significant bit */

		/* No need to compare with the last value */
		for (j = 0; j < params->cdf_table_len - 1; j++)
		{
			/**
			 * Constant time comparison: 1 if CDF_TABLE[j] < s, 0 otherwise.
			 * Uses the fact that CDF_TABLE[j] and s fit in 15 bits
			 */
			sample += (uint16_t)(params->cdf_table[j] - prnd) >> 15;
		}
		/* Assuming that sign is either 0 or 1, flips sample iff sign = 1 */
		s[i] = ((-sign) ^ sample) + sign;
	}
}

/**
 * Generate square matrix A by using SHAKE128
 */
static bool generate_matrix_by_shake(const frodo_params_t *params, uint16_t *A,
									 uint8_t *seed_A)
{
	const uint32_t seed_A_len = params->seed_A_len;
	const uint32_t n = params->n;

	uint8_t seed_A_separated[2 + seed_A_len];
	uint16_t *seed_A_origin = (uint16_t*)&seed_A_separated;
	int i;
	bool success = FALSE;
	xof_t *xof;

	memcpy(&seed_A_separated[2], seed_A, seed_A_len);

	/* Instantiate a SHAKE-128 eXtended Output Function */
	xof = lib->crypto->create_xof(lib->crypto, XOF_SHAKE_128);
	if (!xof)
	{
		DBG1(DBG_LIB, "could not instantiate %N", ext_out_function_names,
					   XOF_SHAKE_128);
		return FALSE;
	}
	for (i = 0; i < n; i++)
	{
		seed_A_origin[0] = i;

		if (!xof->set_seed(xof, chunk_create(seed_A_separated, 2 + seed_A_len)))
		{
			goto err;
		}
		if (!xof->get_bytes(xof, 2*n, (uint8_t*)(A + i*n)))
		{
			goto err;
		}
	}
	success = TRUE;

err:
	xof->destroy(xof);
	return success;
}

/**
 * Generate square matrix A by using AES128
 */
static bool generate_matrix_by_aes(const frodo_params_t *params, uint16_t *A,
								   uint8_t *seed_A)
{
	const uint32_t n = params->n;
	const uint32_t n_x_n = n * n;
	const uint32_t A_len = n_x_n * sizeof(uint16_t);

	crypter_t *crypter;
	chunk_t A_chunk;
	bool success = FALSE;
	uint32_t block_len, step, k;
	int i, j;

	memset((uint8_t*)A, 0x00, A_len);

	crypter = lib->crypto->create_crypter(lib->crypto, ENCR_AES_ECB, 16);
	if (!crypter)
	{
		DBG1(DBG_LIB, "could not instantiate AES_ECB-128");
		return FALSE;
	}
	block_len = crypter->get_block_size(crypter);
	step =  block_len / sizeof(uint16_t);

	if (!crypter->set_key(crypter, chunk_create(seed_A, params->seed_A_len)))
	{
		goto err;
	}

    /* ECB encryption */
	for (i = 0; i < n; i++)
	{
		for (j = 0; j < n; j += step)
		{
			k = i*n + j;
			A[k] = i;
			A[k + 1] = j;
		}
	}
	A_chunk = chunk_create((uint8_t*)A, A_len);

	if (!crypter->encrypt(crypter, A_chunk, chunk_empty, NULL))
	{
		goto err;
	}
	success = TRUE;

err:
	crypter->destroy(crypter);
	return success;
}

/**
 * See header
 */
bool frodo_mul_add_as_plus_e(const frodo_params_t *params, uint16_t *out,
							 uint16_t *s, uint16_t *e, uint8_t *seed_A,
							 bool use_aes)
{
	const uint32_t n  = params->n;
	const uint32_t nb = params->nb;
	const uint32_t n_x_n = n * n;
	const uint32_t n_x_nb = n * nb;

	int16_t A[n_x_n];
	int i, j, k;

	if (use_aes ? !generate_matrix_by_aes  (params, A, seed_A) :
				  !generate_matrix_by_shake(params, A, seed_A))
	{
		return FALSE;
	}
	memcpy(out, e, n_x_nb * sizeof(uint16_t));

	for (i = 0; i < n; i++)
	{
		/* Matrix multiplication-addition A*s + e */
		for (k = 0; k < nb; k++)
		{
			uint16_t sum = 0;

			for (j = 0; j < n; j++)
			{
				sum += A[i*n + j] * s[k*n + j];
			}

			/* Adding e. No need to reduce modulo 2^15,
			 * extra bits are taken care of during packing later on.
			 */
			out[i*nb + k] += sum;}
	}
	return TRUE;
}

/**
 * See header
 */
bool frodo_mul_add_sa_plus_e(const frodo_params_t *params, uint16_t *out,
							 uint16_t *s, uint16_t *e, uint8_t *seed_A,
							 bool use_aes)
{
	const uint32_t n  = params->n;
	const uint32_t nb = params->nb;
	const uint32_t n_x_n = n * n;
	const uint32_t n_x_nb = n * nb;

	int16_t A[n_x_n];
	int i, j, k;

	if (use_aes ? !generate_matrix_by_aes  (params, A, seed_A) :
				  !generate_matrix_by_shake(params, A, seed_A))
	{
		return FALSE;
	}
	memcpy(out, e, n_x_nb * sizeof(uint16_t));

	/* Matrix multiplication-addition A*s + e*/
	for (i = 0; i < n; i++)
	{
		for (k = 0; k < nb; k++)
		{
			uint16_t sum = 0;

			for (j = 0; j < n; j++)
			{
				sum += A[j*n + i] * s[k*n + j];
			}

			/* Adding e. No need to reduce modulo 2^15,
			 * extra bits are taken care of during packing later on.
			 */
			out[k*n + i] += sum;
		}
	}

	return TRUE;
}

/**
 * See header
 */
void frodo_mul_add_sb_plus_e(const frodo_params_t *params, uint16_t *out,
							 uint16_t *b, uint16_t *s, uint16_t *e)
{
	const uint32_t n  = params->n;
	const uint32_t nb = params->nb;
	const uint32_t log_q = params->log_q;

	int i, j, k;

	for (k = 0; k < nb; k++)
	{
		for (i = 0; i < nb; i++)
		{
			out[k*nb + i] = e[k*nb + i];
			for (j = 0; j < n; j++)
			{
				out[k*nb + i] += s[k*n + j] * b[j*nb + i];
			}
			out[k*nb + i] = (uint32_t)(out[k*nb + i]) & ((1 << log_q) - 1);
		}
	}
}

/**
 * See header
 */
void frodo_mul_bs(const frodo_params_t *params, uint16_t *out,
				  uint16_t *b, uint16_t *s)
{
	const uint32_t n  = params->n;
	const uint32_t nb = params->nb;
	const uint32_t log_q = params->log_q;

	int i, j, k;

	for (i = 0; i < nb; i++)
	{
        for (j = 0; j < nb; j++)
		{
 			out[i*nb + j] = 0;
			for (k = 0; k < n; k++)
			{
				out[i*nb + j] += b[i*n + k] * s[j*n + k];
			}
			out[i*nb + j] = (uint32_t)(out[i*nb + j]) & ((1 << log_q) - 1);
		}
	}
}

/**
 * See header
 */
void frodo_add(const frodo_params_t *params, uint16_t *out,
			   uint16_t *a, uint16_t *b)
{
	const uint32_t nb = params->nb;
	const uint32_t log_q = params->log_q;

	u_int i;

	for (i = 0; i < (nb * nb); i++)
	{
		out[i] = (a[i] + b[i]) & ((1 << log_q) - 1);
	}
}

void frodo_sub(const frodo_params_t *params, uint16_t *out,
			   uint16_t *a, uint16_t *b)
{
	const uint32_t nb = params->nb;
	const uint32_t log_q = params->log_q;

	u_int i;

	for (i = 0; i < (nb * nb); i++)
	{
		out[i] = (a[i] - b[i]) & ((1 << log_q) - 1);
	}
}

/**
 * See header
 */
void frodo_key_encode(const frodo_params_t *params, uint16_t *out, uint16_t *in)
{
	const uint32_t nb        = params->nb;
	const uint32_t log_q     = params->log_q;
	const uint32_t extr_bits = params->extr_bits;

	u_int i, j, npieces_word = 8;
	u_int nwords = (nb * nb)/8;
	uint64_t temp, mask = ((uint64_t)1 << extr_bits) - 1;
	uint16_t* pos = out;

	for (i = 0; i < nwords; i++)
	{
		temp = 0;
		for(j = 0; j < extr_bits; j++)
		{
			temp |= ((uint64_t)((uint8_t*)in)[i*extr_bits + j]) << (8*j);
		}
		for (j = 0; j < npieces_word; j++)
		{
			*pos = (uint16_t)((temp & mask) << (log_q - extr_bits));
			temp >>= extr_bits;
			pos++;
		}
	}
}

/**
 * See header
 */
void frodo_key_decode(const frodo_params_t *params, uint16_t *out, uint16_t *in)
{
	const uint32_t nb        = params->nb;
	const uint32_t log_q     = params->log_q;
	const uint32_t extr_bits = params->extr_bits;

	u_int i, j, index = 0, npieces_word = 8;
	u_int nwords = (nb * nb) / 8;
	uint16_t temp;
	u_int maskex = ((uint16_t)1 << extr_bits) - 1;
	u_int maskq  = ((uint16_t)1 << log_q) - 1;
	uint8_t *pos = (uint8_t*)out;
	uint64_t templong;

	for (i = 0; i < nwords; i++)
	{
		templong = 0;
		for (j = 0; j < npieces_word; j++)
		{
			/* temp = floor(in*2^{-11}+0.5) */
			temp = ((in[index] & maskq) +
				   (1 << (log_q - extr_bits - 1))) >> (log_q - extr_bits);
			templong |= ((uint64_t)(temp & maskex)) << (extr_bits * j);
			index++;
		}
		for(j = 0; j < extr_bits; j++)
		{
			pos[i*extr_bits + j] = (templong >> (8*j)) & 0xFF;
		}
	}
}