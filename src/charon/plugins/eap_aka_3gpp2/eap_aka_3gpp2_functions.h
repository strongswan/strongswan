/*
 * Copyright (C) 2008-2009 Martin Willi
 * Hochschule fuer Technik Rapperswil
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
 * @defgroup eap_aka_3gpp2_functions eap_aka_3gpp2_functions
 * @{ @ingroup eap_aka_3gpp2
 */

#ifndef EAP_AKA_3GPP2_FUNCTIONS_H_
#define EAP_AKA_3GPP2_FUNCTIONS_H_

#include <utils/enumerator.h>
#include <utils/identification.h>

#define RAND_LENGTH		16
#define RES_LENGTH		16
#define SQN_LENGTH		 6
#define K_LENGTH		16
#define MAC_LENGTH 		 8
#define CK_LENGTH		16
#define IK_LENGTH		16
#define AK_LENGTH		 6
#define AMF_LENGTH		 2
#define FMK_LENGTH		 4
#define AUTN_LENGTH 	(SQN_LENGTH + AMF_LENGTH + MAC_LENGTH)
#define AUTS_LENGTH 	(SQN_LENGTH + MAC_LENGTH)

typedef struct eap_aka_3gpp2_functions_t eap_aka_3gpp2_functions_t;

/**
 * f1-f5(), f1*() and f5*() functions from the 3GPP2 (S.S0055) standard.
 */
struct eap_aka_3gpp2_functions_t {

	/**
	 * Calculate MAC from RAND, SQN, AMF using K.
	 *
	 * @param k		secret key K
	 * @param rand	random value rand
	 * @param sqn	sequence number
	 * @param amf	authentication management field
	 * @param mac	buffer receiving mac MAC
	 */
	void (*f1)(eap_aka_3gpp2_functions_t *this, u_char k[K_LENGTH],
				u_char rand[RAND_LENGTH], u_char sqn[SQN_LENGTH],
				u_char amf[AMF_LENGTH], u_char mac[MAC_LENGTH]);

	/**
	 * Calculate MACS from RAND, SQN, AMF using K
	 *
	 * @param k		secret key K
	 * @param rand	random value RAND
	 * @param sqn	sequence number
	 * @param amf	authentication management field
	 * @param macs	buffer receiving resynchronization mac MACS
	 */
	void (*f1star)(eap_aka_3gpp2_functions_t *this, u_char k[K_LENGTH],
				u_char rand[RAND_LENGTH], u_char sqn[SQN_LENGTH],
				u_char amf[AMF_LENGTH], u_char macs[MAC_LENGTH]);

	/**
	 * Calculate RES from RAND using K
	 *
	 * @param k		secret key K
	 * @param rand	random value RAND
	 * @param macs	buffer receiving result RES
	 */
	void (*f2)(eap_aka_3gpp2_functions_t *this, u_char k[K_LENGTH],
				u_char rand[RAND_LENGTH], u_char res[RES_LENGTH]);
	/**
	 * Calculate CK from RAND using K
	 *
	 * @param k		secret key K
	 * @param rand	random value RAND
	 * @param macs	buffer receiving encryption key CK
	 */
	void (*f3)(eap_aka_3gpp2_functions_t *this, u_char k[K_LENGTH],
				u_char rand[RAND_LENGTH], u_char ck[CK_LENGTH]);
	/**
	 * Calculate IK from RAND using K
	 *
	 * @param k		secret key K
	 * @param rand	random value RAND
	 * @param macs	buffer receiving integrity key IK
	 */
	void (*f4)(eap_aka_3gpp2_functions_t *this, u_char k[K_LENGTH],
				u_char rand[RAND_LENGTH], u_char ik[IK_LENGTH]);
	/**
	 * Calculate AK from a RAND using K
	 *
	 * @param k		secret key K
	 * @param rand	random value RAND
	 * @param macs	buffer receiving anonymity key AK
	 */
	void (*f5)(eap_aka_3gpp2_functions_t *this, u_char k[K_LENGTH],
				u_char rand[RAND_LENGTH], u_char ak[AK_LENGTH]);
	/**
	 * Calculate AKS from a RAND using K
	 *
	 * @param k		secret key K
	 * @param rand	random value RAND
	 * @param macs	buffer receiving resynchronization anonymity key AKS
	 */
	void (*f5star)(eap_aka_3gpp2_functions_t *this, u_char k[K_LENGTH],
				u_char rand[RAND_LENGTH], u_char aks[AK_LENGTH]);

	/**
	 * Destroy a eap_aka_3gpp2_functions_t.
	 */
	void (*destroy)(eap_aka_3gpp2_functions_t *this);
};

/**
 * Create a eap_aka_3gpp2_functions instance.
 *
 * @return			function set, NULL on error
 */
eap_aka_3gpp2_functions_t *eap_aka_3gpp2_functions_create();

#endif /** EAP_AKA_3GPP2_FUNCTIONS_ @}*/
