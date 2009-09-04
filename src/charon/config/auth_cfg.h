/*
 * Copyright (C) 2007-2009 Martin Willi
 * Copyright (C) 2008 Tobias Brunner
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
 * @defgroup auth_cfg auth_cfg
 * @{ @ingroup config
 */

#ifndef AUTH_CFG_H_
#define AUTH_CFG_H_

#include <utils/enumerator.h>

typedef struct auth_cfg_t auth_cfg_t;
typedef enum auth_rule_t auth_rule_t;

/**
 * Authentication config to use during authentication process.
 *
 * Each authentication config contains a set of rules. These rule-sets are used
 * in two ways:
 * - For configs specifying local authentication behavior, the rules define
 *   which authentication method in which way.
 * - For configs specifying remote peer authentication, the rules define
 *   constraints the peer has to fullfill.
 *
 * Additionally to the rules, there is a set of helper items. These are used
 * to transport credentials during the authentication process.
 */
enum auth_rule_t {

	/** identity to use for IKEv2 authentication exchange, identification_t* */
	AUTH_RULE_IDENTITY,
	/** authentication class, auth_class_t */
	AUTH_RULE_AUTH_CLASS,
	/** EAP identity to use within EAP-Identity exchange, identification_t* */
	AUTH_RULE_EAP_IDENTITY,
	/** EAP type to propose for peer authentication, eap_type_t */
	AUTH_RULE_EAP_TYPE,
	/** EAP vendor for vendor specific type, u_int32_t */
	AUTH_RULE_EAP_VENDOR,
	/** certificate authority, certificate_t* */
	AUTH_RULE_CA_CERT,
	/** intermediate certificate in trustchain, certificate_t* */
	AUTH_RULE_IM_CERT,
	/** subject certificate, certificate_t* */
	AUTH_RULE_SUBJECT_CERT,
	/** result of a CRL validation, cert_validation_t */
	AUTH_RULE_CRL_VALIDATION,
	/** result of a OCSP validation, cert_validation_t */
	AUTH_RULE_OCSP_VALIDATION,
	/** subject is in attribute certificate group, identification_t* */
	AUTH_RULE_AC_GROUP,

	/** intermediate certificate, certificate_t* */
	AUTH_HELPER_IM_CERT,
	/** subject certificate, certificate_t* */
	AUTH_HELPER_SUBJECT_CERT,
	/** Hash and URL of a intermediate certificate, char* */
	AUTH_HELPER_IM_HASH_URL,
	/** Hash and URL of a end-entity certificate, char* */
	AUTH_HELPER_SUBJECT_HASH_URL,
};

/**
 * enum name for auth_rule_t.
 */
extern enum_name_t *auth_rule_names;

/**
 * Authentication/Authorization round.
 *
 * RFC4739 defines multiple authentication rounds. This class defines such
 * a round from a configuration perspective, either for the local or the remote
 * peer. Local config are called "rulesets", as they define how we authenticate.
 * Remote peer configs are called "constraits", they define what is needed to
 * complete the authentication round successfully.
 *
 * @verbatim

   [Repeat for each configuration]
   +--------------------------------------------------+
   |                                                  |
   |                                                  |
   |   +----------+     IKE_AUTH       +--------- +   |
   |   |  config  |   ----------->     |          |   |
   |   |  ruleset |                    |          |   |
   |   +----------+ [ <----------- ]   |          |   |
   |                [ optional EAP ]   |   Peer   |   |
   |   +----------+ [ -----------> ]   |          |   |
   |   |  config  |                    |          |   |
   |   |  constr. |   <-----------     |          |   |
   |   +----------+     IKE_AUTH       +--------- +   |
   |                                                  |
   |                                                  |
   +--------------------------------------------------+

   @endverbatim
 *
 * Values for each items are either pointers (casted to void*) or short
 * integers (use uintptr_t cast).
 */
struct auth_cfg_t {

	/**
	 * Add an rule to the set.
	 *
	 * @param rule		rule type
	 * @param ...		associated value to rule
	 */
	void (*add)(auth_cfg_t *this, auth_rule_t rule, ...);

	/**
	 * Get an rule value.
	 *
	 * @param rule		rule type
	 * @return			bool if item has been found
	 */
	void* (*get)(auth_cfg_t *this, auth_rule_t rule);

	/**
	 * Create an enumerator over added rules.
	 *
	 * @return			enumerator over (auth_rule_t, union{void*,uintpr_t})
	 */
	enumerator_t* (*create_enumerator)(auth_cfg_t *this);

	/**
	 * Replace an rule at enumerator position.
	 *
	 * @param pos		enumerator position position
	 * @param rule		rule type
	 * @param ...		associated value to rule
	 */
	void (*replace)(auth_cfg_t *this, enumerator_t *pos,
					auth_rule_t rule, ...);

	/**
	 * Check if a used config fulfills a set of configured constraints.
	 *
	 * @param constraints	required authorization rules
	 * @param log_error		wheter to log compliance errors
	 * @return				TRUE if this complies with constraints
	 */
	bool (*complies)(auth_cfg_t *this, auth_cfg_t *constraints, bool log_error);

	/**
	 * Merge items from other into this.
	 *
	 * @param other		items to read for merge
	 * @param copy		TRUE to copy items, FALSE to move them
	 */
	void (*merge)(auth_cfg_t *this, auth_cfg_t *other, bool copy);

	/**
	 * Purge all rules in a config.
	 *
	 * @param keep_ca	wheter to keep AUTH_RULE_CA_CERT entries
	 */
	void (*purge)(auth_cfg_t *this, bool keep_ca);

	/**
	 * Check two configs for equality.
	 *
	 * @param other		other config to compaire against this
	 * @return			TRUE if auth infos identical
	 */
	bool (*equals)(auth_cfg_t *this, auth_cfg_t *other);

	/**
	 * Clone a authentication config, including all rules.
	 *
	 * @return			cloned configuration
	 */
	auth_cfg_t* (*clone)(auth_cfg_t *this);

	/**
	 * Destroy a config with all associated rules/values.
	 */
	void (*destroy)(auth_cfg_t *this);
};

/**
 * Create a authentication config.
 */
auth_cfg_t *auth_cfg_create();

#endif /** AUTH_CFG_H_ @}*/
