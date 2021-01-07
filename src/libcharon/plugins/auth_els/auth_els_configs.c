/*
 * Copyright (C) 2019-2020 Marvell 
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <unistd.h>
#include <dirent.h>
#include <signal.h>
#include <errno.h>

#ifdef AUTH_ELS_KMIP	// If we are not compiling KMIP, then don't want these
#include <openssl/bio.h>
#endif

#include <collections/linked_list.h>
#include <threading/thread.h>
#include <threading/condvar.h>
#include <threading/mutex.h>
#include <processing/jobs/callback_job.h>
#include <credentials/keys/shared_key.h>
#include <utils/identification.h>

#include <config/child_cfg.h>

#include "auth_els_utils.h"
#include "auth_els_configs.h"

typedef struct auth_els_backend_t auth_els_backend_t;
struct auth_els_backend_t {

	backend_t public;
	linked_list_t* configs;
};

typedef struct auth_els_psk_creds_t auth_els_psk_creds_t;
struct auth_els_psk_creds_t {

	credential_set_t credential_set;
	linked_list_t* auth_els_psks;
};

typedef struct {
	enumerator_t public;
	enumerator_t *inner;
	shared_key_t *current;
	identification_t *me;
	identification_t *other;
} shared_enumerator_t;

enum shared_secret_type_t {
	SHARED_SECRET_TYPE_WWPN,
	SHARED_SECRET_TYPE_CONFIG_FILE,
	SHARED_SECRET_TYPE_KMIP,
};

struct private_auth_els_configs_t {

	auth_els_configs_t public;

	auth_els_backend_t backend;
	auth_els_psk_creds_t* creds;
	
	chunk_t shared_secret;
	enum shared_secret_type_t secret_type;
	
	proposal_t *esp_proposal;
	proposal_t *ike_proposal;
};
typedef struct private_auth_els_configs_t private_auth_els_configs_t;


METHOD(enumerator_t, shared_enumerator_enumerate, bool,
	shared_enumerator_t *this, va_list args)
{
	DBG4(DBG_CFG, "auth_els - entering shared_enumerator_enumerate");

	shared_key_t **key;
	shared_enumerator_t *rport_shared_key;
	enumerator_t *e1;
	id_match_t local_match = ID_MATCH_NONE, remote_match = ID_MATCH_NONE;
	id_match_t *me_match;
	id_match_t *other_match;

	VA_ARGS_VGET(args, key, me_match, other_match);

	if ((this != NULL) && (this->inner != NULL))
	{
		e1 = this->inner;//->create_enumerator(this->inner);
		while (e1->enumerate(e1, &rport_shared_key))
		{
			if( (rport_shared_key == NULL) ||
				(rport_shared_key->me == NULL) ||
				(rport_shared_key->other == NULL) )
			{
				DBG4(DBG_CFG, "auth_els - shared_enumerator_enumerate shared key is NULL");
				continue;
			}

			if ( (this == NULL) || (this->me == NULL) || (this->other == NULL) ) {
				DBG4(DBG_CFG, "auth_els - shared_enumerator_enumerate local or remote identification is NULL");
				continue;
			}

			local_match = this->me->matches(this->me, rport_shared_key->me);
			remote_match = this->other->matches(this->other, rport_shared_key->other);
			if (me_match)
				*me_match = local_match;
			if (other_match)
				*other_match = remote_match;
			DBG_STD ("me_match=%N other_match=%N",
					id_match_names, local_match, id_match_names, remote_match);
			if ( (local_match >= ID_MATCH_PERFECT) && (remote_match >= ID_MATCH_PERFECT) )
			{
				chunk_t key_s = rport_shared_key->current->get_key(rport_shared_key->current);
				this->current = shared_key_create( SHARED_IKE, chunk_clone(key_s));
				*key = this->current;
				DBG_STD ("matching shared key for %Y - %Y is %#B",
						rport_shared_key->me, rport_shared_key->other,
						&key_s);

				return TRUE;
			}
		}
	}

	return FALSE;
}

METHOD(enumerator_t, shared_enumerator_destroy, void,
	   shared_enumerator_t *this)
{
	DESTROY_IF(this->inner);
	DESTROY_IF(this->me);
	DESTROY_IF(this->other);
	DESTROY_IF(this->current);
	free(this);
}

METHOD(credential_set_t, create_shared_enumerator, enumerator_t*,
		auth_els_psk_creds_t *this, shared_key_type_t type,
	identification_t *me, identification_t *other)
{
	DBG4(DBG_CFG, "auth_els - entering create_shared_enumerator");
	DBG_ENTER;
	
	shared_enumerator_t *data;

	if (type != SHARED_IKE)
	{
		return NULL;
	}

	if ((me == NULL) || (other == NULL))
	{
		DBG_STD ("local or remote identification is NULL");
		return NULL;
	}

	if (this->auth_els_psks == NULL)
	{
		this->auth_els_psks = linked_list_create ();
	}

	INIT(data,
		.public = {
			.enumerate = enumerator_enumerate_default,
			.venumerate = _shared_enumerator_enumerate,
			.destroy = _shared_enumerator_destroy,
		},
		.inner = this->auth_els_psks->create_enumerator(this->auth_els_psks),
		.current = NULL,
		.me = identification_create_from_encoding(me->get_type(me),	me->get_encoding(me)),
		.other = identification_create_from_encoding(other->get_type(other), other->get_encoding(other)),
	);

	return &data->public;
}

CALLBACK(ike_filter, bool,
	void *data, enumerator_t *orig, va_list args)
{
	//DBG4(DBG_CFG, "auth_els - entering ike_filter  me => %#H", me);

	peer_cfg_t *cfg;
	ike_cfg_t **out;
	ike_cfg_t *ikecfg;

	host_t *me = (host_t *)data;

	VA_ARGS_VGET(args, out);

	while (orig->enumerate(orig, &cfg))
	{
		ikecfg = cfg->get_ike_cfg(cfg);
		if (ikecfg && me)
		{
			if (ikecfg->get_my_port(ikecfg) == me->get_port(me))
			{
				//DBG4(DBG_CFG, "auth_els - ike_filter ike_cfg found for me => %#H", me);
				*out = ikecfg;
				return TRUE;
			}
		}
	}
	return FALSE;
}

METHOD(backend_t, create_ike_cfg_enumerator, enumerator_t*,
	auth_els_backend_t *this, host_t *me, host_t *other)
{
	if (this->configs == NULL)
	{
		this->configs = linked_list_create ();
	}
	return enumerator_create_filter(
							this->configs->create_enumerator(this->configs),
							(void*)ike_filter, me, (void*)nop);
}

typedef struct {
	identification_t *me;
	identification_t *other;
} peer_data_t;

CALLBACK(peer_filter, bool,
	void *data, enumerator_t *orig, va_list args)
{
	peer_cfg_t *cfg;
	peer_cfg_t **out;
	id_match_t match_me = ID_MATCH_NONE;
	id_match_t match_other = ID_MATCH_NONE;

	peer_data_t *peer_data = (peer_data_t*)data;
	identification_t *me = (identification_t *)peer_data->me;
	identification_t *other = (identification_t *)peer_data->other;

	//DBG4(DBG_CFG, "auth_els - auth_els_configs - peer_filter looking for peer configs matching [%Y]...[%Y]",
	//		 me, other);

	VA_ARGS_VGET(args, out);

	if ((me == NULL) || (me->get_encoding(me).ptr == NULL))
		return FALSE;

	if ((other == NULL) || (other->get_encoding(other).ptr == NULL))
		return FALSE;

	//DBG4(DBG_CFG, "auth_els - entering peer_filter  me => name %s", me->get_encoding(me).ptr);

	while (orig->enumerate(orig, &cfg))
	{
		enumerator_t *enumerator;
		auth_cfg_t *auth;
		identification_t *candidate;
		enumerator = cfg->create_auth_cfg_enumerator(cfg, TRUE);
		while (enumerator->enumerate(enumerator, &auth))
		{
			candidate = auth->get(auth, AUTH_RULE_IDENTITY);
			if (candidate)
			{
				if (me)
				{
					//DBG1(DBG_CFG, "auth_els - auth_els_configs - peer_filter enumerator me[%Y]...my[%Y]",
					//		 me, candidate);
					match_me = me->matches(me, candidate);
				}

				if (match_me == ID_MATCH_PERFECT)
				{
					break;
				}

			}
		}
		enumerator->destroy(enumerator);

		enumerator = cfg->create_auth_cfg_enumerator(cfg, FALSE);
		while (enumerator->enumerate(enumerator, &auth))
		{
			candidate = auth->get(auth, AUTH_RULE_IDENTITY);
			if (candidate)
			{
				if (other)
				{
					//DBG4(DBG_CFG, "auth_els - auth_els_configs - peer_filter enumerator other[%Y]...remote[%Y]",
					//		 other, candidate);
					match_other = other->matches(other, candidate);
				}

				if (match_other == ID_MATCH_PERFECT)
				{
					//DBG4(DBG_CFG, "auth_els - peer_filter id_match=%N", id_match_names, match);
					break;
				}
			}
		}
		enumerator->destroy(enumerator);

		if ((match_me == ID_MATCH_PERFECT) && (match_other == ID_MATCH_PERFECT))
		{
			//DBG4(DBG_CFG, "auth_els - peer_filter id_match=%N", id_match_names, match);
			*out = cfg;
			return TRUE;
		}
	}
	return FALSE;
}

void destroy_peer_cfg_enum (void *data)
{
	free (data);
}

METHOD(backend_t, create_peer_cfg_enumerator, enumerator_t*,
	auth_els_backend_t *this, identification_t *me, identification_t *other)
{
	if (this->configs == NULL)
	{
		this->configs = linked_list_create ();
	}

	peer_data_t *data;
	INIT(data,
		.me = me,
		.other = other,
	);

	return enumerator_create_filter(
			this->configs->create_enumerator(this->configs),
			(void*)peer_filter, data, destroy_peer_cfg_enum);
}

METHOD(backend_t, get_peer_cfg_by_name, peer_cfg_t*,
	auth_els_backend_t *this, char *name)
{
	DBG2(DBG_CFG, "auth_els - entering get_peer_cfg_by_name name=%s", name);
	enumerator_t *e1;
	peer_cfg_t *current, *found = NULL;

	if (this->configs == NULL)
	{
		this->configs = linked_list_create ();
	}

	e1 = this->configs->create_enumerator(this->configs);
	while (e1->enumerate(e1, &current))
	{
		if (strncaseeq(current->get_name(current), name, 32))
		{
			found = current;
			break;
		}
	}
	e1->destroy(e1);
	return found;
}

static auth_els_psk_creds_t *auth_els_psk_creds_create()
{
	auth_els_psk_creds_t *this;

	INIT(this,
		.credential_set = {
			.create_shared_enumerator = _create_shared_enumerator,
			.create_private_enumerator = (void*)return_null,
			.create_cert_enumerator = (void*)return_null,
			.create_cdp_enumerator  = (void*)return_null,
			.cache_cert = (void*)nop,
		},
		.auth_els_psks = NULL,
	);

	return this;
}

METHOD(auth_els_configs_t, reload_config, bool,
	private_auth_els_configs_t *this)
{

	char *shared_secret_section, *shared_secret_string = NULL;
	enumerator_t* enumerator;

	enumerator = lib->settings->create_section_enumerator(lib->settings,
			"%s.plugins.auth-els.shared_secret_config", lib->ns);

	while (enumerator->enumerate(enumerator, &shared_secret_section))
	{
		shared_secret_string = lib->settings->get_str(lib->settings,
				"%s.plugins.auth-els.shared_secret_config.%s.shared_secret", NULL,
				lib->ns, shared_secret_section);
		DBG1(DBG_CFG, "auth_els - add_rport_cfg - config file secret: %s", shared_secret_string);
	}
	enumerator->destroy(enumerator);
		
	if (shared_secret_string == NULL)
	{
		this->secret_type = SHARED_SECRET_TYPE_WWPN;
	}
	else
	{
		this->shared_secret = chunk_clone (chunk_create (shared_secret_string, strlen (shared_secret_string)));
		this->secret_type = SHARED_SECRET_TYPE_CONFIG_FILE;
	}

	char *proposal = lib->settings->get_str(lib->settings,
					"%s.plugins.auth-els.algorithm_config.esp_proposal", NULL,
					lib->ns);
	
	if (proposal)
	{
		// If the user gives us a proposal, then validate below.
		DBG_STD ("User encryption algorithms proposal: %s", proposal);
	}
	else
	{
		proposal = ESP_ENCR_PROPOSAL_DEFAULT_128_BIT;		
		DBG_STD ("Default encryption algorithms proposal: %s", proposal);
	}
	
	this->esp_proposal = proposal_create_from_string(PROTO_ESP, proposal);
	if (this->esp_proposal == NULL)
	{
		DBG_FATAL ("Invalid ESP proposal");
		return FALSE;
	}
	
	proposal = lib->settings->get_str(lib->settings,
					"%s.plugins.auth-els.algorithm_config.ike_proposal", NULL,
					lib->ns);
	
	if (proposal)
	{
		// If the user gives us a proposal, then validate below.
		DBG_STD ("User ike algorithms proposal: %s", proposal);
	}
	else
	{
		proposal = IKE_PROPOSAL_DEFAULT_128_BIT;
		
		DBG_STD ("Default ike algorithms proposal: %s", proposal);
	}
	
	this->ike_proposal = proposal_create_from_string(PROTO_IKE, proposal);
	if (this->ike_proposal == NULL)
	{
		DBG_FATAL ("Invalid IKE proposal");
		return FALSE;
	}

	uint16_t esp_enc_alg, ike_enc_alg, prf, dh_group;
	uint16_t key_size_temp, esp_key_size;
	this->esp_proposal->get_algorithm (this->esp_proposal, ENCRYPTION_ALGORITHM, (uint16_t*) &esp_enc_alg, &key_size_temp);
	
	if ((esp_enc_alg != ENCR_AES_GCM_ICV16) && (esp_enc_alg != ENCR_NULL_AUTH_AES_GMAC))
	{
		DBG_STD ("Invalid encryption algorithm specified: %N, set to default", encryption_algorithm_names, esp_enc_alg);
		this->esp_proposal->destroy (this->esp_proposal);
		this->esp_proposal = proposal_create_from_string(PROTO_ESP, ESP_ENCR_PROPOSAL_DEFAULT_128_BIT);
	}
	
	this->esp_proposal->get_algorithm (this->esp_proposal, ENCRYPTION_ALGORITHM, &esp_enc_alg, &esp_key_size);
	this->ike_proposal->get_algorithm (this->ike_proposal, ENCRYPTION_ALGORITHM, &ike_enc_alg, &key_size_temp);
	this->ike_proposal->get_algorithm (this->ike_proposal, DIFFIE_HELLMAN_GROUP, &dh_group, &key_size_temp);
	this->ike_proposal->get_algorithm (this->ike_proposal, PSEUDO_RANDOM_FUNCTION, &prf, &key_size_temp);
	
	// We don't have a separate integrity algorithm because GCM and GMAC are AEAD which has integrity algorithm built in.
	DBG_STD ("chosen algorithms:  esp encryption: %N, %d, ike encryption: %N, %d, PRF: %N, %d, DH Group: %N, %d", 
				encryption_algorithm_names, esp_enc_alg, esp_enc_alg,
				encryption_algorithm_names, ike_enc_alg, ike_enc_alg,
				pseudo_random_function_names, prf, prf, 
				diffie_hellman_group_names, dh_group, dh_group);
	
	enumerator = this->esp_proposal->create_enumerator (this->esp_proposal, ENCRYPTION_ALGORITHM);
	while (enumerator->enumerate (enumerator, &esp_enc_alg, &esp_key_size))
	{
		DBG_STD ("Possible key size for ESP GCM: %d", esp_key_size);
	}
	enumerator->destroy (enumerator);

	return TRUE;
}

METHOD(auth_els_configs_t, get_esp_proposal, proposal_t*, private_auth_els_configs_t *this)
{
	// We have to return a clone because the proposal is destroyed whenever the ike_sa is destroyed.
	proposal_t *clone_prop = this->esp_proposal->clone (this->esp_proposal, 0);
	return clone_prop;
}

METHOD(auth_els_configs_t, get_ike_proposal, proposal_t*, private_auth_els_configs_t *this)
{
	// We have to return a clone because the proposal is destroyed whenever the ike_sa is destroyed.
	proposal_t *clone_prop = this->ike_proposal->clone (this->ike_proposal, 0);
	return clone_prop;
}

METHOD(auth_els_configs_t, get_shared_secret, chunk_t, private_auth_els_configs_t *this,
				bool initiator, char *host_name, char *rport_name)
{
	if (this->secret_type == SHARED_SECRET_TYPE_WWPN)
	{
		uint8_t default_shared_secret[(2 * HOST_NAME_SIZE) + 1] = { 0 };
		chunk_t shared_secret;
		
		if (initiator)
		{
			strncpy(default_shared_secret, host_name, HOST_NAME_SIZE);
			strncpy(default_shared_secret+HOST_NAME_SIZE, rport_name, HOST_NAME_SIZE);
		}
		else
		{
			strncpy(default_shared_secret, rport_name, HOST_NAME_SIZE);
			strncpy(default_shared_secret+HOST_NAME_SIZE, host_name, HOST_NAME_SIZE);
		}
		default_shared_secret[(2 * HOST_NAME_SIZE)] = '\0';	// Make sure default secret is only 32 bytes.
		
		shared_secret = chunk_clone (chunk_create (default_shared_secret, (2 * HOST_NAME_SIZE) + 1));
		
		return shared_secret;
	}
	else
	{
		return chunk_clone (this->shared_secret);
	}
}

METHOD(auth_els_configs_t, get_backend, backend_t*,
	private_auth_els_configs_t *this)
{
	return &this->backend.public;
}

METHOD(auth_els_configs_t, get_creds, credential_set_t*,
	private_auth_els_configs_t *this)
{
	return &this->creds->credential_set;
}

METHOD(auth_els_configs_t, destroy, void,
	private_auth_els_configs_t *this)
{
	peer_cfg_t *current;
	enumerator_t *config_enum = this->backend.configs->create_enumerator(this->backend.configs);
	
	DBG_ENTER;
	
	while (config_enum->enumerate(config_enum, &current))
	{
		this->backend.configs->remove (this->backend.configs, current, NULL);
		current->destroy(current);
	}
	if (this->creds->auth_els_psks)
	{
		this->creds->auth_els_psks->destroy_function (this->creds->auth_els_psks, (void*)_shared_enumerator_destroy);
	}
	free (this->creds);
	
	if (this->secret_type != SHARED_SECRET_TYPE_WWPN)
	{
		chunk_free (&this->shared_secret);
	}
	DESTROY_IF (this->esp_proposal);
	DESTROY_IF (this->ike_proposal);
	free(this);
}

auth_els_configs_t *auth_els_configs_create()
{
	private_auth_els_configs_t *this;

	INIT(this,
		.public = {
			.destroy = _destroy,
			.get_backend = _get_backend,
			.get_creds = _get_creds,
			.reload_config = _reload_config,
			.get_shared_secret = _get_shared_secret,
			.get_esp_proposal = _get_esp_proposal,
			.get_ike_proposal = _get_ike_proposal,
		},
		.backend = {
			.configs = NULL,
			.public = {
				.create_peer_cfg_enumerator = (void*)_create_peer_cfg_enumerator,
				.create_ike_cfg_enumerator = (void*)_create_ike_cfg_enumerator,
				.get_peer_cfg_by_name = (void*)_get_peer_cfg_by_name,
			},
		},
		.creds = auth_els_psk_creds_create(),
		.ike_proposal = NULL,
		.esp_proposal = NULL,
	);
	
	return &this->public;
}
