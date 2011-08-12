/*
 * Copyright (C) 2011 Andreas Steffen
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
 * @defgroup tnc_ifmap_soap tnc_ifmap_soap
 * @{ @ingroup tnc_ifmap 
 */

#ifndef TNC_IFMAP_SOAP_H_
#define TNC_IFMAP_SOAP_H_

#include <library.h>
#include <utils/host.h>
#include <sa/ike_sa.h>

typedef struct tnc_ifmap_soap_t tnc_ifmap_soap_t;

/**
 * Implements the TNC IF-MAP 2.0 SOAP Binding
 */
struct tnc_ifmap_soap_t {

	/**
	 * Creates a new IF-MAP session
	 *
	 * @return				TRUE if command was successful
	 */
	bool (*newSession)(tnc_ifmap_soap_t *this);

	/**
	 * Purges all metadata published by this publisher
	 *
	 * @return				TRUE if command was successful
	 */
	bool (*purgePublisher)(tnc_ifmap_soap_t *this);

	/**
	 * Publish metadata about established/deleted IKE_SAs 
	 *
	 * @param ike_sa		IKE_SA for which metadate is published
	 * @param up			TRUE if IKE_SEA is up, FALSE if down
	 * @return				TRUE if command was successful
	 */
	bool (*publish_ike_sa)(tnc_ifmap_soap_t *this, ike_sa_t *ike_sa, bool up);

	/**
	 * Publish PEP device-ip metadata 
	 *
	 * @param host			IP address of local endpoint
	 * @return				TRUE if command was successful
	 */
	bool (*publish_device_ip)(tnc_ifmap_soap_t *this, host_t *host);

	/**
	 * Publish enforcement-report metadata
	 *
	 * @param host			Host to be enforced
	 * @param action		Enforcement action ("block" or "quarantine")
	 * @param reason		Enforcement reason
	 * @return				TRUE if command was successful
	 */
	bool (*publish_enforcement_report)(tnc_ifmap_soap_t *this, host_t *host,
									   char *action, char *reason);

	/**
	 * Ends an IF-MAP session
	 *
	 * @return				TRUE if command was successful
	 */
	bool (*endSession)(tnc_ifmap_soap_t *this);

	/**
	 * Destroy a tnc_ifmap_soap_t.
	 */
	void (*destroy)(tnc_ifmap_soap_t *this);
};

/**
 * Create a tnc_ifmap_soap instance.
 */
tnc_ifmap_soap_t *tnc_ifmap_soap_create();

#endif /** TNC_IFMAP_SOAP_H_ @}*/
