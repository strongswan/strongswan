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
 * @defgroup tpm_tss tpm_tss
 * @{ @ingroup libtpmtss
 */

#ifndef TPM_TSS_H_
#define TPM_TSS_H_

#include <library.h>

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

#endif /** TPM_TSS_H_ @}*/
