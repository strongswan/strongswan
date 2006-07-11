/**
 * @file identification.h
 *
 * @brief Interface of identification_t.
 *
 */

/*
 * Copyright (C) 2005-2006 Martin Willi
 * Copyright (C) 2005 Jan Hutter
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


#ifndef IDENTIFICATION_H_
#define IDENTIFICATION_H_

#include "types.h"

#define MAX_WILDCARDS     14

typedef enum id_type_t id_type_t;

/**
 * @brief ID Types in a ID payload.
 *
 * @ingroup utils
 */
enum id_type_t {

	/**
	 * private type which matches any other id.
	 */
	ID_ANY = 0,

	/**
	 * ID data is a single four (4) octet IPv4 address.
	 */
	ID_IPV4_ADDR = 1,

	/**
	 * ID data is a fully-qualified domain name string.
	 * An example of a ID_FQDN is "example.com".
	 * The string MUST not contain any terminators (e.g., NULL, CR, etc.).
	 */
	ID_FQDN = 2,

	/**
	 * ID data is a fully-qualified RFC822 email address string.
	 * An example of an ID_RFC822_ADDR is "jsmith@example.com".
	 * The string MUST NOT contain any terminators.
	 */
	ID_RFC822_ADDR = 3,

	/**
	 * ID data is an IPv4 subnet (IKEv1 only)
	 */
	ID_IPV4_ADDR_SUBNET = 4,

	/**
	 * ID data is a single sixteen (16) octet IPv6 address.
	 */
	ID_IPV6_ADDR = 5,

	/**
	 * ID data is an IPv6 subnet (IKEv1 only)
	 */
	ID_IPV6_ADDR_SUBNET = 6,

	/**
	 * ID data is an IPv4 address range (IKEv1 only)
	 */
	ID_IPV4_ADDR_RANGE = 7,

	/**
	 * ID data is an IPv6 address range (IKEv1 only)
	 */
	ID_IPV6_ADDR_RANGE = 8,

	/**
	 * ID data is the binary DER encoding of an ASN.1 X.501 Distinguished Name
	 */
	ID_DER_ASN1_DN = 9,

	/**
	 * ID data is the binary DER encoding of an ASN.1 X.509 GeneralName
	 */
	ID_DER_ASN1_GN = 10,

	/**
	 * ID data is an opaque octet stream which may be used to pass vendor-
	 * specific information necessary to do certain proprietary
	 * types of identification.
	 */
	ID_KEY_ID = 11,

	/**
	 * private type which represents a GeneralName of type URI
	 */
	ID_DER_ASN1_GN_URI = 201,

};

/**
 * String mappings for id_type_t.
 */
extern enum_names id_type_names;

typedef struct identification_t identification_t;

/**
 * @brief Generic identification, such as used in ID payload.
 * 
 * The following types are possible:
 * - ID_IPV4_ADDR
 * - ID_FQDN
 * - ID_RFC822_ADDR
 * - ID_IPV6_ADDR
 * - ID_DER_ASN1_DN
 * - ID_DER_ASN1_GN
 * - ID_KEY_ID
 * - ID_DER_ASN1_GN_URI
 * 
 * @b Constructors:
 * - identification_create_from_string()
 * - identification_create_from_encoding()
 * 
 * @todo Support for ID_DER_ASN1_GN is minimal right now. Comparison
 * between them and ID_IPV4_ADDR/RFC822_ADDR would be nice.
 *
 * @ingroup utils
 */
struct identification_t {
	
	/**
	 * @brief Get the encoding of this id, to send over
	 * the network.
	 * 
	 * @warning Result points to internal data, do NOT free!
	 * 
	 * @param this		the identification_t object
	 * @return 			a chunk containing the encoded bytes
	 */
	chunk_t (*get_encoding) (identification_t *this);
	
	/**
	 * @brief Get the type of this identification.
	 * 
	 * @param this		the identification_t object
	 * @return 			id_type_t
	 */
	id_type_t (*get_type) (identification_t *this);
	
	/**
	 * @brief Get a string representation of this id.
	 * 
	 * @warning Result points to internal data, do NOT free!
	 * 
	 * @param this		the identification_t object
	 * @return 			string
	 */
	char *(*get_string) (identification_t *this);
	
	/**
	 * @brief Check if two identification_t objects are equal.
	 * 
	 * @param this		the identification_t object
	 * @param other		other identification_t object
	 * @return 			TRUE if the IDs are equal
	 */
	bool (*equals) (identification_t *this, identification_t *other);
	
	/**
	 * @brief Check if an ID matches a wildcard ID.
	 * 
	 * An identification_t may contain wildcards, such as
	 * *@strongswan.org. This call checks if a given ID
	 * (e.g. tester@strongswan.org) belongs to a such wildcard
	 * ID. Returns TRUE if
	 * - IDs are identical
	 * - other is of type ID_ANY
	 * - other contains a wildcard and matches this
	 * 
	 * @param this		the ID without wildcard
	 * @param other		the ID containing a wildcard
	 * @param wildcards	returns the number of wildcards
	 * @return 			TRUE if match is found
	 */
	bool (*matches) (identification_t *this, identification_t *other, int *wildcards);
	
	/**
	 * @brief Check if an ID is a wildcard ID.
	 *
	 * If the ID represents multiple IDs (with wildcards, or
	 * as the type ID_ANY), TRUE is returned. If it is unique,
	 * FALSE is returned.
	 * 
	 * @param this		identification_t object
	 * @return 			TRUE if ID contains wildcards
	 */
	bool (*contains_wildcards) (identification_t *this);
	
	/**
	 * @brief Clone a identification_t instance.
	 * 
	 * @param this		the identification_t object to clone
	 * @return 			clone of this
	 */
	identification_t *(*clone) (identification_t *this);

	/**
	 * @brief Destroys a identification_t object.
	 *
	 * @param this 		identification_t object
	 */
	void (*destroy) (identification_t *this);
};

/**
 * @brief Creates an identification_t object from a string.
 * 
 * @param string	input string, which will be converted
 * @return
 * 					- created identification_t object, or
 * 					- NULL if unsupported string supplied.
 *
 * The input string may be e.g. one of the following:
 * - ID_IPV4_ADDR:		192.168.0.1
 * - ID_IPV6_ADDR:		2001:0db8:85a3:08d3:1319:8a2e:0370:7345
 * - ID_FQDN:			@www.strongswan.org (@indicates FQDN)
 * - ID_RFC822_ADDR:	alice@wonderland.org
 * - ID_DER_ASN1_DN:	C=CH, O=Linux strongSwan, CN=bob
 *
 * In favour of pluto, domainnames are prepended with an @, since
 * pluto resolves domainnames without an @ to IPv4 addresses. Since
 * we use a seperate host_t class for addresses, this doesn't
 * make sense for us.
 * 
 * A distinguished name may contain one or more of the following RDNs:
 * ND, UID, DC, CN, S, SN, serialNumber, C, L, ST, O, OU, T, D,
 * N, G, I, ID, EN, EmployeeNumber, E, Email, emailAddress, UN, 
 * unstructuredName, TCGID.
 *
 * @ingroup utils
 */
identification_t * identification_create_from_string(char *string);

/**
 * @brief Creates an identification_t object from an encoded chunk.
 * 
 * @param type		type of this id, such as ID_IPV4_ADDR
 * @param encoded	encoded bytes, such as from identification_t.get_encoding
 * @return			identification_t object
 *
 * In contrast to identification_create_from_string(), this constructor never
 * returns NULL, even when the conversion to a string representation fails.
 *
 * @ingroup utils
 */
identification_t * identification_create_from_encoding(id_type_t type, chunk_t encoded);


#endif /* IDENTIFICATION_H_ */
