/*
 * Copyright (C) 2010 Martin Willi
 * Copyright (C) 2010 revosec AG
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
 * @defgroup tls_eap tls_eap
 * @{ @ingroup libtls
 */

#ifndef TLS_EAP_H_
#define TLS_EAP_H_

typedef struct tls_eap_t tls_eap_t;

#include <eap/eap.h>

#include "tls_application.h"

/**
 * TLS over EAP helper, as used by EAP-TLS and EAP-TTLS.
 */
struct tls_eap_t {

	/**
	 * Initiate TLS over EAP exchange (as client).
	 *
	 * @param out			allocated EAP packet data to send
	 * @return
	 *						- NEED_MORE if more exchanges required
	 *						- FAILED if initiation failed
	 */
	status_t (*initiate)(tls_eap_t *this, chunk_t *out);

	/**
	 * Process a received EAP-TLS/TTLS packet, create response.
	 *
	 * @param in			EAP packet data to process
	 * @param out			allocated EAP packet data to send
	 * @return
	 *						- SUCCESS if TLS negotiation completed
	 *						- FAILED if TLS negotiation failed
	 *						- NEED_MORE if more exchanges required
	 */
	status_t (*process)(tls_eap_t *this, chunk_t in, chunk_t *out);

	/**
	 * Get the EAP-MSK.
	 *
	 * @return				MSK
	 */
	chunk_t (*get_msk)(tls_eap_t *this);

	/**
	 * Destroy a tls_eap_t.
	 */
	void (*destroy)(tls_eap_t *this);
};

/**
 * Create a tls_eap instance.
 *
 * @param type				EAP type, EAP-TLS or EAP-TTLS
 * @param is_server			role
 * @param server			server identity
 * @param peer				peer identity, NULL to omit peer authentication
 * @param application		TLS application layer, if any
 * @param frag_size			maximum size of a TLS fragment we send
 */
tls_eap_t *tls_eap_create(eap_type_t type, bool is_server,
						  identification_t *server, identification_t *peer,
						  tls_application_t *application, size_t frag_size);

#endif /** TLS_EAP_H_ @}*/
