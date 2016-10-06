/*
 * Copyright (C) 2016 Andreas Steffen
 * HSR Hochschule fuer Technik Rapperswil
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

/**
 * @defgroup libtpmtss libtpmtss
 *
 * @addtogroup libtpmtss
 * @{
 */

#ifndef TPM_TSS_H_
#define TPM_TSS_H_

#include "tpm_tss_quote_info.h"

#include <library.h>
#include <crypto/hashers/hasher.h>

typedef enum tpm_version_t tpm_version_t;
typedef struct tpm_tss_t tpm_tss_t;

/**
 * TPM Versions
 */
enum tpm_version_t {
	TPM_VERSION_ANY,
	TPM_VERSION_1_2,
	TPM_VERSION_2_0,
};

/**
 * TPM access via TSS public interface
 */
struct tpm_tss_t {

	/**
	 * Get TPM version supported by TSS
	 *
	 * @return		TPM version
	 */
	tpm_version_t (*get_version)(tpm_tss_t *this);

	/**
	 * Get TPM version info (TPM 1.2 only)
	 *
	 * @return			TPM version info struct
	 */
	chunk_t (*get_version_info)(tpm_tss_t *this);

	/**
	 * Generate AIK key pair bound to TPM (TPM 1.2 only)
	 *
	 * @param ca_modulus	RSA modulus of CA public key
	 * @param aik_blob		AIK private key blob
	 * @param aik_pubkey	AIK public key
	 * @return				TRUE if AIK key generation succeeded
	 */
	bool (*generate_aik)(tpm_tss_t *this, chunk_t ca_modulus,
						 chunk_t *aik_blob, chunk_t *aik_pubkey,
						 chunk_t *identity_req);

	/**
	 * Get public key from TPM using its object handle (TPM 2.0 only)
	 *
	 * @param handle	key object handle
	 * @return			public key in PKCS#1 format
	 */
	chunk_t (*get_public)(tpm_tss_t *this, uint32_t handle);

	/**
	 * Retrieve the current value of a PCR register in a given PCR bank
	 *
	 * @param pcr_num		PCR number
	 * @param pcr_value		PCR value returned
	 * @param alg			hash algorithm, selects PCR bank (TPM 2.0 only)
	 * @return				TRUE if PCR value retrieval succeeded
	 */
	bool (*read_pcr)(tpm_tss_t *this, uint32_t pcr_num, chunk_t *pcr_value,
					 hash_algorithm_t alg);

	/**
	 * Extend a PCR register in a given PCR bank with a hash value
	 *
	 * @param pcr_num		PCR number
	 * @param pcr_value		extended PCR value returned
	 * @param hash			data to be extended into the PCR
	 * @param alg			hash algorithm, selects PCR bank (TPM 2.0 only)
	 * @return				TRUE if PCR extension succeeded
	 */
	bool (*extend_pcr)(tpm_tss_t *this, uint32_t pcr_num, chunk_t *pcr_value,
					   chunk_t data, hash_algorithm_t alg);

	/**
	 * Do a quote signature over a selection of PCR registers
	 *
	 * @param aik_handle	object handle of AIK to be used for quote signature
	 * @param pcr_sel		selection of PCR registers
	 * @param alg			hash algorithm to be used for quote signature
	 * @param data			additional data to be hashed into the quote
	 * @param quote_mode	define current and legacy TPM quote modes
	 * @param quote_info	returns various info covered by quote signature
	 * @param quote_sig		returns quote signature
	 * @return				TRUE if quote signature succeeded
	 */
	bool (*quote)(tpm_tss_t *this, uint32_t aik_handle, uint32_t pcr_sel,
				  hash_algorithm_t alg, chunk_t data,
				  tpm_quote_mode_t *quote_mode,
				  tpm_tss_quote_info_t **quote_info, chunk_t *quote_sig);

	/**
	 * Destroy a tpm_tss_t.
	 */
	void (*destroy)(tpm_tss_t *this);
};

/**
 * Create a tpm_tss instance.
 *
 * @param version	TPM version that must be supported by TSS
 */
tpm_tss_t *tpm_tss_probe(tpm_version_t version);

/**
 * Dummy libtpmtss initialization function needed for integrity test
 */
void libtpmtss_init(void);

#endif /** TPM_TSS_H_ @}*/
