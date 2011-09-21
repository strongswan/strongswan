/*
 * Copyright (C) 2011 Sansar Choinyambuu
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
 * @defgroup pts_dh_group pts_dh_group
 * @{ @ingroup pts
 */

#ifndef PTS_DH_GROUP_H_
#define PTS_DH_GROUP_H_

#include <library.h>
#include <crypto/diffie_hellman.h>

typedef enum pts_dh_group_t pts_dh_group_t;

/**
 * PTS Diffie Hellman Group Values
 */
enum pts_dh_group_t {
	/** IKE Group 2 */
	PTS_DH_GROUP_IKE2 =					 (1<<15),
	/** IKE Group 5 */
	PTS_DH_GROUP_IKE5 =					 (1<<14),
	/** IKE Group 14 */
	PTS_DH_GROUP_IKE14 =				 (1<<13),
	/** IKE Group 19 */
	PTS_DH_GROUP_IKE19 =				 (1<<12),
	/** IKE Group 20 */
	PTS_DH_GROUP_IKE20 =				 (1<<11),
};

/**
 * Diffie-Hellman Group Values
 * see section 3.8.6 of PTS Protocol: Binding to TNC IF-M Specification
 *
 *					   1
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |1|2|3|4|5|R|R|R|R|R|R|R|R|R|R|R|
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  
 */

/**
 * Probe available PTS measurement algorithms
 *
 * @param groups		set of available groups
 * @return				TRUE if mandatory group PTS_DH_GROUP_IKE19 is available
 */
bool pts_probe_dh_groups(pts_dh_group_t *groups);

/**
 * Update supported Diffie Hellman Groups according to configuration
 *
 * @param dh_group		configured Diffie Hellman Group
 * @param groups		set of available groups
 */
bool pts_update_supported_dh_groups(char *dh_group, pts_dh_group_t *groups);

/**
 * Convert pts_dh_group_t to diffie_hellman_group_t
 *
 * @param dh_group		PTS Diffie Hellman Group type
 * @return				libstrongswan diffie hellman group type
 */
diffie_hellman_group_t pts_dh_group_to_strongswan_dh_group(pts_dh_group_t dh_group);

#endif /** PTS_DH_GROUP_H_ @}*/
