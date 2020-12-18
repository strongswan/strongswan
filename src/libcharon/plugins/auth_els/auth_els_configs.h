/* Copyright (C) 2019-2020 Marvell */

/**
 * @defgroup auth_els auth_els
 * @ingroup cplugins
 *
 * @defgroup auth_els_configs auth_els_configs
 * @{ @ingroup auth_els
 */

#ifndef AUTH_ELS_CONFIGS_H_
#define AUTH_ELS_CONFIGS_H_

#include <credentials/credential_set.h>
#include <daemon.h>

// ESP proposal default
#define ESP_ENCR_PROPOSAL_DEFAULT_128_BIT    "aes128gcm16"

// IKE proposal default
#define IKE_PROPOSAL_DEFAULT_128_BIT         "aes128gcm16-prfsha256-curve25519"

#define HOST_NAME_SIZE          16
#define HOST_ID_SIZE            4
#define REMOTE_PORT_ID_SIZE     4
#define PEER_NAME_SIZE          33

typedef struct auth_els_configs_t auth_els_configs_t;
struct auth_els_configs_t {

	backend_t* (*get_backend)(auth_els_configs_t *this);
	credential_set_t* (*get_creds)(auth_els_configs_t *this);
	bool (*reload_config)(auth_els_configs_t *this);
        chunk_t (*get_shared_secret) (auth_els_configs_t *this,
				bool initiator, char *host_name, char *rport_name);
        proposal_t* (*get_esp_proposal) (auth_els_configs_t *this);
        proposal_t* (*get_ike_proposal) (auth_els_configs_t *this);
        
	void (*destroy)(auth_els_configs_t *this);
};

auth_els_configs_t *auth_els_configs_create();

#endif /** AUTH_ELS_CONFIGS_H_ @}*/
