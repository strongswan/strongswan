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

#include "hook.h"

#include <encoding/payloads/sa_payload.h>
#include <encoding/payloads/nonce_payload.h>
#include <encoding/payloads/auth_payload.h>
#include <encoding/payloads/id_payload.h>

typedef struct private_set_reserved_t private_set_reserved_t;

/**
 * Private data of an set_reserved_t object.
 */
struct private_set_reserved_t {

	/**
	 * Implements the hook_t interface.
	 */
	hook_t hook;

	/**
	 * Alter requests or responses?
	 */
	bool req;

	/**
	 * ID of message to alter.
	 */
	int id;

	/**
	 * Hook name
	 */
	char *name;

	/**
	 * Our IKE_SA_INIT data, required to rebuild AUTH
	 */
	chunk_t ike_init;

	/**
	 * Received NONCE, required to rebuild AUTH
	 */
	chunk_t nonce;
};

/**
 * Rebuild our AUTH data
 */
static bool rebuild_auth(private_set_reserved_t *this, ike_sa_t *ike_sa,
						 message_t *message)
{
	enumerator_t *enumerator;
	chunk_t octets, auth_data;
	private_key_t *private;
	auth_cfg_t *auth;
	payload_t *payload;
	auth_payload_t *auth_payload;
	auth_method_t auth_method;
	signature_scheme_t scheme;
	keymat_t *keymat;
	identification_t *id;
	id_payload_t *id_payload;
	char reserved[3];
	u_int8_t *byte;
	int i;

	id_payload = (id_payload_t*)message->get_payload(message,
					message->get_request(message) ? ID_INITIATOR : ID_RESPONDER);
	if (!id_payload)
	{
		DBG1(DBG_CFG, "ID payload not found to rebuild AUTH");
		return FALSE;
	}
	id = id_payload->get_identification(id_payload);
	for (i = 0; i < countof(reserved); i++)
	{
		byte = payload_get_field(&id_payload->payload_interface,
								 RESERVED_BYTE, i);
		if (byte)
		{
			reserved[i] = *byte;
		}
	}

	auth = auth_cfg_create();
	private = lib->credmgr->get_private(lib->credmgr, KEY_ANY, id, auth);
	auth->destroy(auth);
	if (private == NULL)
	{
		DBG1(DBG_CFG, "no private key found for '%Y' to rebuild AUTH", id);
		id->destroy(id);
		return FALSE;
	}

	switch (private->get_type(private))
	{
		case KEY_RSA:
			scheme = SIGN_RSA_EMSA_PKCS1_SHA1;
			auth_method = AUTH_RSA;
			break;
		case KEY_ECDSA:
			/* we try to deduct the signature scheme from the keysize */
			switch (private->get_keysize(private))
			{
				case 256:
					scheme = SIGN_ECDSA_256;
					auth_method = AUTH_ECDSA_256;
					break;
				case 384:
					scheme = SIGN_ECDSA_384;
					auth_method = AUTH_ECDSA_384;
					break;
				case 521:
					scheme = SIGN_ECDSA_521;
					auth_method = AUTH_ECDSA_521;
					break;
				default:
					DBG1(DBG_CFG, "%d bit ECDSA private key size not supported",
							private->get_keysize(private));
					id->destroy(id);
					return FALSE;
			}
			break;
		default:
			DBG1(DBG_CFG, "private key of type %N not supported",
					key_type_names, private->get_type(private));
			id->destroy(id);
			return FALSE;
	}
	keymat = ike_sa->get_keymat(ike_sa);
	octets = keymat->get_auth_octets(keymat, FALSE, this->ike_init,
									 this->nonce, id, reserved);
	if (!private->sign(private, scheme, octets, &auth_data))
	{
		chunk_free(&octets);
		private->destroy(private);
		id->destroy(id);
		return FALSE;
	}
	auth_payload = auth_payload_create();
	auth_payload->set_auth_method(auth_payload, auth_method);
	auth_payload->set_data(auth_payload, auth_data);
	chunk_free(&auth_data);
	chunk_free(&octets);
	private->destroy(private);

	enumerator = message->create_payload_enumerator(message);
	while (enumerator->enumerate(enumerator, &payload))
	{
		if (payload->get_type(payload) == AUTHENTICATION)
		{
			message->remove_payload_at(message, enumerator);
			payload->destroy(payload);
		}
	}
	enumerator->destroy(enumerator);

	message->add_payload(message, (payload_t*)auth_payload);
	DBG1(DBG_CFG, "rebuilding AUTH payload for '%Y' with %N",
		 id, auth_method_names, auth_method);
	id->destroy(id);
	return TRUE;
}

/**
 * Set reserved bit of a payload
 */
static void set_bit(private_set_reserved_t *this, message_t *message,
					payload_type_t type, u_int nr)
{
	enumerator_t *payloads;
	payload_t *payload;
	bool *bit;

	if (type == HEADER)
	{
		message->set_reserved_header_bit(message, nr);
		DBG1(DBG_CFG, "setting reserved bit %d of %N",
			  nr, payload_type_short_names, type);
	}
	else
	{
		payloads = message->create_payload_enumerator(message);
		while (payloads->enumerate(payloads, &payload))
		{
			if (payload->get_type(payload) == type)
			{
				bit = payload_get_field(payload, RESERVED_BIT, nr);
				if (bit)
				{
					DBG1(DBG_CFG, "setting reserved bit %d of %N",
						 nr, payload_type_short_names, type);
					*bit = TRUE;
				}
			}
		}
		payloads->destroy(payloads);
	}
}

/**
 * Set reserved byte of a payload
 */
static void set_byte(private_set_reserved_t *this, message_t *message,
					 payload_type_t type, u_int nr, u_int8_t byteval)
{
	enumerator_t *payloads;
	payload_t *payload;
	u_int8_t *byte;

	if (type == TRANSFORM_SUBSTRUCTURE || type == PROPOSAL_SUBSTRUCTURE)
	{
		enumerator_t *transforms, *proposals;
		transform_substructure_t *transform;
		proposal_substructure_t *proposal;
		sa_payload_t *sa;

		payloads = message->create_payload_enumerator(message);
		while (payloads->enumerate(payloads, &payload))
		{
			if (payload->get_type(payload) == SECURITY_ASSOCIATION)
			{
				sa = (sa_payload_t*)payload;
				proposals = sa->create_substructure_enumerator(sa);
				while (proposals->enumerate(proposals, &proposal))
				{
					if (type == PROPOSAL_SUBSTRUCTURE)
					{
						byte = payload_get_field(&proposal->payload_interface,
												 RESERVED_BYTE, nr);
						if (byte)
						{
							DBG1(DBG_CFG, "setting reserved byte %d of %N to %d",
								 nr, payload_type_short_names, type, byteval);
							*byte = byteval;
						}
					}
					else if (type == TRANSFORM_SUBSTRUCTURE)
					{
						transforms = proposal->create_substructure_enumerator(
																	proposal);
						while (transforms->enumerate(transforms, &transform))
						{
							byte = payload_get_field(&transform->payload_interface,
													 RESERVED_BYTE, nr);
							if (byte)
							{
								DBG1(DBG_CFG, "setting reserved byte %d of %N to %d",
									 nr, payload_type_short_names, type, byteval);
								*byte = byteval;
							}
						}
						transforms->destroy(transforms);
					}
				}
				proposals->destroy(proposals);
			}
		}
		payloads->destroy(payloads);
	}
	else
	{
		payloads = message->create_payload_enumerator(message);
		while (payloads->enumerate(payloads, &payload))
		{
			if (payload->get_type(payload) == type)
			{
				byte = payload_get_field(payload, RESERVED_BYTE, nr);
				if (byte)
				{
					DBG1(DBG_CFG, "setting reserved byte %d of %N to %d",
						  nr, payload_type_short_names, type, byteval);
					*byte = byteval;
				}
			}
		}
		payloads->destroy(payloads);
	}
}

/**
 * Mangle reserved bits and bytes. Returns TRUE if IKE_AUTH must be rebuilt
 */
static bool set_reserved(private_set_reserved_t *this, message_t *message)
{
	enumerator_t *bits, *bytes, *types;
	payload_type_t type;
	char *nr, *name;
	u_int8_t byteval;
	bool rebuild = FALSE;

	types = conftest->test->create_section_enumerator(conftest->test,
												"hooks.%s", this->name);
	while (types->enumerate(types, &name))
	{
		type = atoi(name);
		if (!type)
		{
			type = enum_from_name(payload_type_short_names, name);
			if (type == -1)
			{
				DBG1(DBG_CFG, "invalid payload name '%s'", name);
				break;
			}
		}
		nr = conftest->test->get_str(conftest->test,
							"hooks.%s.%s.bits", "", this->name, name);
		bits = enumerator_create_token(nr, ",", " ");
		while (bits->enumerate(bits, &nr))
		{
			set_bit(this, message, type, atoi(nr));
		}
		bits->destroy(bits);

		nr = conftest->test->get_str(conftest->test,
							"hooks.%s.%s.bytes", "", this->name, name);
		byteval = conftest->test->get_int(conftest->test,
							"hooks.%s.%s.byteval", 255, this->name, name);
		bytes = enumerator_create_token(nr, ",", " ");
		while (bytes->enumerate(bytes, &nr))
		{
			set_byte(this, message, type, atoi(nr), byteval);
		}
		bytes->destroy(bytes);
		if ((this->req && type == ID_INITIATOR) ||
			(!this->req && type == ID_RESPONDER))
		{
			rebuild = TRUE;
		}
	}
	types->destroy(types);
	return rebuild;
}

METHOD(listener_t, message, bool,
	private_set_reserved_t *this, ike_sa_t *ike_sa, message_t *message,
	bool incoming)
{
	if (!incoming &&
		message->get_request(message) == this->req &&
		message->get_message_id(message) == this->id)
	{
		if (set_reserved(this, message))
		{
			if (message->get_message_id(message) == 1)
			{
				rebuild_auth(this, ike_sa, message);
			}
		}
	}
	if (message->get_exchange_type(message) == IKE_SA_INIT)
	{
		if (incoming)
		{
			nonce_payload_t *nonce;

			nonce = (nonce_payload_t*)message->get_payload(message, NONCE);
			if (nonce)
			{
				free(this->nonce.ptr);
				this->nonce = nonce->get_nonce(nonce);
			}
		}
		else
		{
			packet_t *packet;

			if (message->generate(message, NULL, &packet) == SUCCESS)
			{
				free(this->ike_init.ptr);
				this->ike_init = chunk_clone(packet->get_data(packet));
				packet->destroy(packet);
			}

		}
	}
	return TRUE;
}

METHOD(hook_t, destroy, void,
	private_set_reserved_t *this)
{
	free(this->ike_init.ptr);
	free(this->nonce.ptr);
	free(this->name);
	free(this);
}

/**
 * Create the IKE_AUTH fill hook
 */
hook_t *set_reserved_hook_create(char *name)
{
	private_set_reserved_t *this;

	INIT(this,
		.hook = {
			.listener = {
				.message = _message,
			},
			.destroy = _destroy,
		},
		.req = conftest->test->get_bool(conftest->test,
										"hooks.%s.request", TRUE, name),
		.id = conftest->test->get_int(conftest->test,
										"hooks.%s.id", 0, name),
		.name = strdup(name),
	);

	return &this->hook;
}
