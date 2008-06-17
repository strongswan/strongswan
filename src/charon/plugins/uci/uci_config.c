/*
 * Copyright (C) 2008 Thomas Kallenberg
 * Copyright (C) 2008 Tobias Brunner
 * Copyright (C) 2008 Martin Willi
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
 *
 * $Id$
 */

#include "uci_config.h"
#include "uci_parser.h"

#include <daemon.h>

typedef struct private_uci_config_t private_uci_config_t;

/**
 * Private data of an uci_config_t object
 */
struct private_uci_config_t {

	/**
	 * Public part
	 */
	uci_config_t public;
	
	/**
	 * UCI parser context
	 */
	uci_parser_t *parser;
};

/**
 * enumerator implementation for create_peer_cfg_enumerator
 */
typedef struct {
	/** implements enumerator */
	enumerator_t public;
	/** currently enumerated peer config */
	peer_cfg_t *peer_cfg;
	/** inner uci_parser section enumerator */
	enumerator_t *inner;
} peer_enumerator_t;

/**
 * Implementation of peer_enumerator_t.public.enumerate
 */
static bool peer_enumerator_enumerate(peer_enumerator_t *this, peer_cfg_t **cfg)
{
	char *name, *local_id, *remote_ip;
	child_cfg_t *child_cfg;
	ike_cfg_t *ike_cfg;
	
	/* defaults */
	name = "unnamed";
	local_id = "%any";
	remote_ip = "0.0.0.0";
	
	if (this->inner->enumerate(this->inner, &name, &local_id, &remote_ip))
	{
		DESTROY_IF(this->peer_cfg);
		ike_cfg = ike_cfg_create(FALSE, FALSE, "0.0.0.0", remote_ip);
		ike_cfg->add_proposal(ike_cfg, proposal_create_default(PROTO_IKE));
		this->peer_cfg = peer_cfg_create(
					name, 2, ike_cfg,
					identification_create_from_string(local_id),
					identification_create_from_encoding(ID_ANY, chunk_empty),
					CERT_SEND_IF_ASKED, UNIQUE_NO, CONF_AUTH_PSK,
					0, 0, 				/* EAP method, vendor */
					1, 3600*12, 0,  	/* keytries, rekey, reauth */
					3600, 1800,			/* jitter, overtime */
					TRUE, 60, 			/* mobike, dpddelay */
					NULL, NULL, 		/* vip, pool */
					FALSE, NULL, NULL); /* mediation, med by, peer id */
		child_cfg = child_cfg_create(
					name, 3600*4, 3600*3, 360, NULL, TRUE,
					MODE_TUNNEL, ACTION_NONE, ACTION_NONE, FALSE);
		child_cfg->add_proposal(child_cfg, proposal_create_default(PROTO_ESP));
		child_cfg->add_traffic_selector(child_cfg, TRUE,
								traffic_selector_create_dynamic(0, 0, 65535));
		child_cfg->add_traffic_selector(child_cfg, FALSE,
								traffic_selector_create_dynamic(0, 0, 65535));
		this->peer_cfg->add_child_cfg(this->peer_cfg, child_cfg);
		*cfg = this->peer_cfg;
		return TRUE;
	}
	return FALSE;
}

/**
 * Implementation of peer_enumerator_t.public.destroy
 */
static void peer_enumerator_destroy(peer_enumerator_t *this)
{
	DESTROY_IF(this->peer_cfg);
	this->inner->destroy(this->inner);
	free(this);
}

/**
 * Implementation of backend_t.create_peer_cfg_enumerator.
 */
static enumerator_t* create_peer_cfg_enumerator(private_uci_config_t *this,
												identification_t *me, 
												identification_t *other)
{
	peer_enumerator_t *e = malloc_thing(peer_enumerator_t);
	
	e->public.enumerate = (void*)peer_enumerator_enumerate;
	e->public.destroy = (void*)peer_enumerator_destroy;
	e->peer_cfg = NULL;
	e->inner = this->parser->create_section_enumerator(this->parser, 
										"local_id", "remote_ip", NULL);
	if (!e->inner)
	{
		free(e);
		return NULL;
	}
	return &e->public;
}

/**
 * enumerator implementation for create_ike_cfg_enumerator
 */
typedef struct {
	/** implements enumerator */
	enumerator_t public;
	/** currently enumerated ike config */
	ike_cfg_t *ike_cfg;
	/** inner uci_parser section enumerator */
	enumerator_t *inner;
} ike_enumerator_t;

/**
 * Implementation of peer_enumerator_t.public.enumerate
 */
static bool ike_enumerator_enumerate(ike_enumerator_t *this, ike_cfg_t **cfg)
{
	char *name, *remote_ip;
	
	/* defaults */
	name = "unnamed";
	remote_ip = "0.0.0.0";
	
	if (this->inner->enumerate(this->inner, &name, &remote_ip))
	{
		DESTROY_IF(this->ike_cfg);
		this->ike_cfg = ike_cfg_create(FALSE, FALSE, "0.0.0.0", remote_ip);
		this->ike_cfg->add_proposal(this->ike_cfg,
									proposal_create_default(PROTO_IKE));

		*cfg = this->ike_cfg;
		return TRUE;
	}
	return FALSE;
}

/**
 * Implementation of ike_enumerator_t.public.destroy
 */
static void ike_enumerator_destroy(ike_enumerator_t *this)
{
	DESTROY_IF(this->ike_cfg);
	this->inner->destroy(this->inner);
	free(this);
}

/**
 * Implementation of backend_t.create_ike_cfg_enumerator.
 */
static enumerator_t* create_ike_cfg_enumerator(private_uci_config_t *this,
											   host_t *me, host_t *other)
{
	ike_enumerator_t *e = malloc_thing(ike_enumerator_t);
	
	e->public.enumerate = (void*)ike_enumerator_enumerate;
	e->public.destroy = (void*)ike_enumerator_destroy;
	e->ike_cfg = NULL;
	e->inner = this->parser->create_section_enumerator(this->parser, 
												"remote_ip", NULL);
	if (!e->inner)
	{
		free(e);
		return NULL;
	}
	return &e->public;
}

/**
 * implements backend_t.get_peer_cfg_by_name.
 */
static peer_cfg_t *get_peer_cfg_by_name(private_uci_config_t *this, char *name)
{
	enumerator_t *enumerator;
	peer_cfg_t *current, *found = NULL;
		
	enumerator = create_peer_cfg_enumerator(this, NULL, NULL);
	if (enumerator)
	{
		while (enumerator->enumerate(enumerator, &current))
		{
			if (streq(name, current->get_name(current)))
			{
				found = current->get_ref(current);
				break;
			}
		}
		enumerator->destroy(enumerator);
	}
	return found;
}

/**
 * Implementation of uci_config_t.destroy.
 */
static void destroy(private_uci_config_t *this)
{
	free(this);
}

/**
 * Described in header.
 */
uci_config_t *uci_config_create(uci_parser_t *parser)
{
	private_uci_config_t *this = malloc_thing(private_uci_config_t);

	this->public.backend.create_peer_cfg_enumerator = (enumerator_t*(*)(backend_t*, identification_t *me, identification_t *other))create_peer_cfg_enumerator;
	this->public.backend.create_ike_cfg_enumerator = (enumerator_t*(*)(backend_t*, host_t *me, host_t *other))create_ike_cfg_enumerator;
	this->public.backend.get_peer_cfg_by_name = (peer_cfg_t* (*)(backend_t*,char*))get_peer_cfg_by_name;
	this->public.destroy = (void(*)(uci_config_t*))destroy;
	
	this->parser = parser;
	
	return &this->public;
}

