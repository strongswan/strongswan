/**
 * @file proposal.h
 *
 * @brief Interface of proposal_t.
 *
 */

/*
 * Copyright (C) 2006 Martin Willi
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

#ifndef PROPOSAL_H_
#define PROPOSAL_H_

#include <types.h>
#include <utils/identification.h>
#include <utils/linked_list.h>
#include <utils/host.h>
#include <crypto/crypters/crypter.h>
#include <crypto/signers/signer.h>
#include <crypto/diffie_hellman.h>
#include <config/traffic_selector.h>


typedef enum protocol_id_t protocol_id_t;

/**
 * Protocol ID of a proposal.
 * 
 * @ingroup config
 */
enum protocol_id_t {
	PROTO_NONE = 0,
	PROTO_IKE = 1,
	PROTO_AH = 2,
	PROTO_ESP = 3,
};

/** 
 * String mappings for protocol_id_t.
 * 
 * @ingroup config
 */
extern mapping_t protocol_id_m[];


typedef enum transform_type_t transform_type_t;

/**
 * Type of a transform, as in IKEv2 RFC 3.3.2.
 * 
 * @ingroup payloads
 */
enum transform_type_t {
	UNDEFINED_TRANSFORM_TYPE = 241,
	ENCRYPTION_ALGORITHM = 1,
	PSEUDO_RANDOM_FUNCTION = 2,
	INTEGRITY_ALGORITHM = 3,
	DIFFIE_HELLMAN_GROUP = 4,
	EXTENDED_SEQUENCE_NUMBERS = 5
};

/** 
 * String mappings for transform_type_t.
 * 
 * @ingroup payloads
 */
extern mapping_t transform_type_m[];


typedef enum extended_sequence_numbers_t extended_sequence_numbers_t;

/** 
 * Extended sequence numbers, as in IKEv2 RFC 3.3.2.
 * 
 * @ingroup payloads
 */
enum extended_sequence_numbers_t {
	NO_EXT_SEQ_NUMBERS = 0,
	EXT_SEQ_NUMBERS = 1
};

/** 
 * String mappings for extended_sequence_numbers_t.
 * 
 * @ingroup payloads
 */
extern mapping_t extended_sequence_numbers_m[];


typedef struct algorithm_t algorithm_t;

/**
 * Struct used to store different kinds of algorithms. The internal
 * lists of algorithms contain such structures.
 */
struct algorithm_t {
	/**
	 * Value from an encryption_algorithm_t/integrity_algorithm_t/...
	 */
	u_int16_t algorithm;
	
	/**
	 * the associated key size in bits, or zero if not needed
	 */
	u_int16_t key_size;
};

typedef struct proposal_t proposal_t;

/**
 * @brief Stores a set of algorithms used for an SA.
 * 
 * A proposal stores algorithms for a specific 
 * protocol. It can store algorithms for one protocol.
 * Proposals with multiple protocols are not supported,
 * as it's not specified in RFC4301 anymore.
 * 
 * @b Constructors:
 *   - proposal_create()
 * 
 * @ingroup config
 */
struct proposal_t {
	
	/**
	 * @brief Add an algorithm to the proposal.
	 * 
	 * The algorithms are stored by priority, first added
	 * is the most preferred.
	 * Key size is only needed for encryption algorithms
	 * with variable key size (such as AES). Must be set
	 * to zero if key size is not specified.
	 * The alg parameter accepts encryption_algorithm_t,
	 * integrity_algorithm_t, dh_group_number_t and
	 * extended_sequence_numbers_t.
	 * 
	 * @param this					calling object
	 * @param type					kind of algorithm
	 * @param alg					identifier for algorithm
	 * @param key_size				key size to use
	 */
	void (*add_algorithm) (proposal_t *this, transform_type_t type, u_int16_t alg, size_t key_size);
	
	/**
	 * @brief Get an iterator over algorithms for a specifc algo type.
	 * 
	 * @param this					calling object
	 * @param type					kind of algorithm
	 * @return						iterator over algorithm_t's
	 */
	iterator_t *(*create_algorithm_iterator) (proposal_t *this, transform_type_t type);
	
	/**
	 * @brief Get the algorithm for a type to use.
	 * 
	 * If there are multiple algorithms, only the first is returned.
	 * Result is still owned by proposal, do not modify!
	 * 
	 * @param this					calling object
	 * @param type					kind of algorithm
	 * @param[out] algo				pointer which receives algorithm and key size
	 * @return						TRUE if algorithm of this kind available
	 */
	bool (*get_algorithm) (proposal_t *this, transform_type_t type, algorithm_t** algo);

	/**
	 * @brief Compare two proposal, and select a matching subset.
	 * 
	 * If the proposals are for the same protocols (AH/ESP), they are
	 * compared. If they have at least one algorithm of each type
	 * in common, a resulting proposal of this kind is created.
	 * 
	 * @param this					calling object
	 * @param other					proposal to compair agains
	 * @return						
	 * 								- selected proposal, if possible
	 * 								- NULL, if proposals don't match
	 */
	proposal_t *(*select) (proposal_t *this, proposal_t *other);
	
	/**
	 * @brief Get the protocol ID of the proposal.
	 *
	 * @param this				calling object
	 * @return					protocol of the proposal
	 */
	protocol_id_t (*get_protocol) (proposal_t *this);
	
	/**
	 * @brief Get the SPI of the proposal.
	 * 
	 * @param this				calling object
	 * @return					spi for proto
	 */
	u_int64_t (*get_spi) (proposal_t *this);
	
	/**
	 * @brief Set the SPI of the proposal.
	 * 
	 * @param this				calling object
	 * @param spi				spi to set for proto
	 */
	void (*set_spi) (proposal_t *this, u_int64_t spi);
	
	/**
	 * @brief Clone a proposal.
	 * 
	 * @param this				proposal to clone
	 * @return					clone of it
	 */
	proposal_t *(*clone) (proposal_t *this);
	
	/**
	 * @brief Destroys the proposal object.
	 * 
	 * @param this				calling object
	 */
	void (*destroy) (proposal_t *this);
};

/**
 * @brief Create a child proposal for AH, ESP or IKE.
 *
 * @param protocol			protocol, such as PROTO_ESP
 * @return 					proposal_t object
 *
 * @ingroup config
 */
proposal_t *proposal_create(protocol_id_t protocol);

/**
 * @brief Create a default proposal if nothing further specified.
 *
 * @param protocol			protocol, such as PROTO_ESP
 * @return 					proposal_t object
 *
 * @ingroup config
 */
proposal_t *proposal_create_default(protocol_id_t protocol);

/**
 * @brief Create a proposal from a string identifying the algorithms.
 *
 * The string is in the same form as a in the ipsec.conf file.
 * E.g.:	aes128-sha2_256-modp2048
 *          3des-md5
 * An additional '!' at the end of the string forces this proposal,
 * without it the peer may choose another algorithm we support.
 *
 * @param protocol			protocol, such as PROTO_ESP
 * @param algs				algorithms as string
 * @return 					proposal_t object
 * 
 * @ingroup config
 */
proposal_t *proposal_create_from_string(protocol_id_t protocol, const char *algs);

#endif /* PROPOSAL_H_ */
