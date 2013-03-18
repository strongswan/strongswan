/*
 * Copyright (C) 2009 Martin Willi
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

#include "eap_radius.h"
#include "eap_radius_plugin.h"
#include "eap_radius_forward.h"
#include "eap_radius_provider.h"
#include "eap_radius_accounting.h"

#include <radius_message.h>
#include <radius_client.h>

#include <daemon.h>

typedef struct private_eap_radius_t private_eap_radius_t;

/**
 * Private data of an eap_radius_t object.
 */
struct private_eap_radius_t {

	/**
	 * Public authenticator_t interface.
	 */
	eap_radius_t public;

	/**
	 * ID of the server
	 */
	identification_t *server;

	/**
	 * ID of the peer
	 */
	identification_t *peer;

	/**
	 * EAP method type we are proxying
	 */
	eap_type_t type;

	/**
	 * EAP vendor, if any
	 */
	u_int32_t vendor;

	/**
	 * EAP message identifier
	 */
	u_int8_t identifier;

	/**
	 * RADIUS client instance
	 */
	radius_client_t *client;

	/**
	 * TRUE to use EAP-Start, FALSE to send EAP-Identity Response directly
	 */
	bool eap_start;

	/**
	 * Prefix to prepend to EAP identity
	 */
	char *id_prefix;

	/**
	 * Handle the Class attribute as group membership information?
	 */
	bool class_group;

	/**
	 * Handle the Filter-Id attribute as IPsec CHILD_SA name?
	 */
	bool filter_id;
};

/**
 * Add EAP-Identity to RADIUS message
 */
static void add_eap_identity(private_eap_radius_t *this,
							 radius_message_t *request)
{
	struct {
		/** EAP code (REQUEST/RESPONSE) */
		u_int8_t code;
		/** unique message identifier */
		u_int8_t identifier;
		/** length of whole message */
		u_int16_t length;
		/** EAP type */
		u_int8_t type;
		/** identity data */
		u_int8_t data[];
	} __attribute__((__packed__)) *hdr;
	chunk_t id, prefix;
	size_t len;

	id = this->peer->get_encoding(this->peer);
	prefix = chunk_create(this->id_prefix, strlen(this->id_prefix));
	len = sizeof(*hdr) + prefix.len + id.len;

	hdr = alloca(len);
	hdr->code = EAP_RESPONSE;
	hdr->identifier = this->identifier;
	hdr->length = htons(len);
	hdr->type = EAP_IDENTITY;
	memcpy(hdr->data, prefix.ptr, prefix.len);
	memcpy(hdr->data + prefix.len, id.ptr, id.len);

	request->add(request, RAT_EAP_MESSAGE, chunk_create((u_char*)hdr, len));
}

/**
 * Copy EAP-Message attribute from RADIUS message to an new EAP payload
 */
static bool radius2ike(private_eap_radius_t *this,
					   radius_message_t *msg, eap_payload_t **out)
{
	enumerator_t *enumerator;
	eap_payload_t *payload;
	chunk_t data, message = chunk_empty;
	int type;

	enumerator = msg->create_enumerator(msg);
	while (enumerator->enumerate(enumerator, &type, &data))
	{
		if (type == RAT_EAP_MESSAGE && data.len)
		{
			message = chunk_cat("mc", message, data);
		}
	}
	enumerator->destroy(enumerator);
	if (message.len)
	{
		*out = payload = eap_payload_create_data(message);

		/* apply EAP method selected by RADIUS server */
		this->type = payload->get_type(payload, &this->vendor);

		DBG3(DBG_IKE, "%N payload %B", eap_type_names, this->type, &message);
		free(message.ptr);
		return TRUE;
	}
	return FALSE;
}

/**
 * Add a set of RADIUS attributes to a request message
 */
static void add_radius_request_attrs(private_eap_radius_t *this,
									 radius_message_t *request)
{
	ike_sa_t *ike_sa;
	host_t *host;
	char buf[40];
	u_int32_t value;
	chunk_t chunk;

	chunk = chunk_from_str(this->id_prefix);
	chunk = chunk_cata("cc", chunk, this->peer->get_encoding(this->peer));
	request->add(request, RAT_USER_NAME, chunk);

	/* virtual NAS-Port-Type */
	value = htonl(5);
	request->add(request, RAT_NAS_PORT_TYPE, chunk_from_thing(value));
	/* framed ServiceType */
	value = htonl(2);
	request->add(request, RAT_SERVICE_TYPE, chunk_from_thing(value));

	ike_sa = charon->bus->get_sa(charon->bus);
	if (ike_sa)
	{
		value = htonl(ike_sa->get_unique_id(ike_sa));
		request->add(request, RAT_NAS_PORT, chunk_from_thing(value));
		request->add(request, RAT_NAS_PORT_ID,
					 chunk_from_str(ike_sa->get_name(ike_sa)));

		host = ike_sa->get_my_host(ike_sa);
		chunk = host->get_address(host);
		switch (host->get_family(host))
		{
			case AF_INET:
				request->add(request, RAT_NAS_IP_ADDRESS, chunk);
				break;
			case AF_INET6:
				request->add(request, RAT_NAS_IPV6_ADDRESS, chunk);
			default:
				break;
		}
		snprintf(buf, sizeof(buf), "%#H", host);
		request->add(request, RAT_CALLED_STATION_ID, chunk_from_str(buf));
		host = ike_sa->get_other_host(ike_sa);
		snprintf(buf, sizeof(buf), "%#H", host);
		request->add(request, RAT_CALLING_STATION_ID, chunk_from_str(buf));
	}

	eap_radius_forward_from_ike(request);
}

METHOD(eap_method_t, initiate, status_t,
	private_eap_radius_t *this, eap_payload_t **out)
{
	radius_message_t *request, *response;
	status_t status = FAILED;

	request = radius_message_create(RMC_ACCESS_REQUEST);
	add_radius_request_attrs(this, request);

	if (this->eap_start)
	{
		request->add(request, RAT_EAP_MESSAGE, chunk_empty);
	}
	else
	{
		add_eap_identity(this, request);
	}

	response = this->client->request(this->client, request);
	if (response)
	{
		eap_radius_forward_to_ike(response);
		switch (response->get_code(response))
		{
			case RMC_ACCESS_CHALLENGE:
				if (radius2ike(this, response, out))
				{
					status = NEED_MORE;
				}
				break;
			case RMC_ACCESS_ACCEPT:
				/* Microsoft RADIUS servers can run in a mode where they respond
				 * like this on the first request (i.e. without authentication),
				 * we treat this as Access-Reject */
			case RMC_ACCESS_REJECT:
			default:
				DBG1(DBG_IKE, "RADIUS authentication of '%Y' failed",
					 this->peer);
				break;
		}
		response->destroy(response);
	}
	else
	{
		eap_radius_handle_timeout(NULL);
	}
	request->destroy(request);
	return status;
}

/**
 * Handle the Class attribute as group membership information
 */
static void process_class(private_eap_radius_t *this, radius_message_t *msg)
{
	enumerator_t *enumerator;
	chunk_t data;
	int type;

	enumerator = msg->create_enumerator(msg);
	while (enumerator->enumerate(enumerator, &type, &data))
	{
		if (type == RAT_CLASS)
		{
			identification_t *id;
			ike_sa_t *ike_sa;
			auth_cfg_t *auth;

			if (data.len >= 44)
			{	/* quirk: ignore long class attributes, these are used for
				 * other purposes by some RADIUS servers (such as NPS). */
				continue;
			}

			ike_sa = charon->bus->get_sa(charon->bus);
			if (ike_sa)
			{
				auth = ike_sa->get_auth_cfg(ike_sa, FALSE);
				id = identification_create_from_data(data);
				DBG1(DBG_CFG, "received group membership '%Y' from RADIUS", id);
				auth->add(auth, AUTH_RULE_GROUP, id);
			}
		}
	}
	enumerator->destroy(enumerator);
}

/**
 * Handle the Filter-Id attribute as IPsec CHILD_SA name
 */
static void process_filter_id(private_eap_radius_t *this, radius_message_t *msg)
{
	enumerator_t *enumerator;
	int type;
	u_int8_t tunnel_tag;
	u_int32_t tunnel_type;
	chunk_t filter_id = chunk_empty, data;
	bool is_esp_tunnel = FALSE;

	enumerator = msg->create_enumerator(msg);
	while (enumerator->enumerate(enumerator, &type, &data))
	{
		switch (type)
		{
			case RAT_TUNNEL_TYPE:
				if (data.len != 4)
				{
					continue;
				}
				tunnel_tag = *data.ptr;
				*data.ptr = 0x00;
				tunnel_type = untoh32(data.ptr);
				DBG1(DBG_IKE, "received RADIUS attribute Tunnel-Type: "
							  "tag = %u, value = %u", tunnel_tag, tunnel_type);
				is_esp_tunnel = (tunnel_type == RADIUS_TUNNEL_TYPE_ESP);
				break;
			case RAT_FILTER_ID:
				filter_id = data;
				DBG1(DBG_IKE, "received RADIUS attribute Filter-Id: "
							  "'%.*s'", (int)filter_id.len, filter_id.ptr);
				break;
			default:
				break;
		}
	}
	enumerator->destroy(enumerator);

	if (is_esp_tunnel && filter_id.len)
	{
		identification_t *id;
		ike_sa_t *ike_sa;
		auth_cfg_t *auth;

		ike_sa = charon->bus->get_sa(charon->bus);
		if (ike_sa)
		{
			auth = ike_sa->get_auth_cfg(ike_sa, FALSE);
			id = identification_create_from_data(filter_id);
			auth->add(auth, AUTH_RULE_GROUP, id);
		}
	}
}

/**
 * Handle Session-Timeout attribte and Interim updates
 */
static void process_timeout(private_eap_radius_t *this, radius_message_t *msg)
{
	enumerator_t *enumerator;
	ike_sa_t *ike_sa;
	chunk_t data;
	int type;

	ike_sa = charon->bus->get_sa(charon->bus);
	if (ike_sa)
	{
		enumerator = msg->create_enumerator(msg);
		while (enumerator->enumerate(enumerator, &type, &data))
		{
			if (type == RAT_SESSION_TIMEOUT && data.len == 4)
			{
				ike_sa->set_auth_lifetime(ike_sa, untoh32(data.ptr));
			}
			else if (type == RAT_ACCT_INTERIM_INTERVAL && data.len == 4)
			{
				eap_radius_accounting_start_interim(ike_sa, untoh32(data.ptr));
			}
		}
		enumerator->destroy(enumerator);
	}
}

/**
 * Handle Framed-IP-Address and other IKE configuration attributes
 */
static void process_cfg_attributes(private_eap_radius_t *this,
								   radius_message_t *msg)
{
	eap_radius_provider_t *provider;
	enumerator_t *enumerator;
	ike_sa_t *ike_sa;
	host_t *host;
	chunk_t data;
	int type, vendor;

	ike_sa = charon->bus->get_sa(charon->bus);
	provider = eap_radius_provider_get();
	if (provider && ike_sa)
	{
		enumerator = msg->create_enumerator(msg);
		while (enumerator->enumerate(enumerator, &type, &data))
		{
			if (type == RAT_FRAMED_IP_ADDRESS && data.len == 4)
			{
				host = host_create_from_chunk(AF_INET, data, 0);
				if (host)
				{
					provider->add_framed_ip(provider, this->peer, host);
				}
			}
		}
		enumerator->destroy(enumerator);

		enumerator = msg->create_vendor_enumerator(msg);
		while (enumerator->enumerate(enumerator, &vendor, &type, &data))
		{
			if (vendor == PEN_ALTIGA /* aka Cisco VPN3000 */)
			{
				switch (type)
				{
					case 15: /* CVPN3000-IPSec-Banner1 */
					case 36: /* CVPN3000-IPSec-Banner2 */
						if (ike_sa->supports_extension(ike_sa, EXT_CISCO_UNITY))
						{
							provider->add_attribute(provider, this->peer,
													UNITY_BANNER, data);
						}
						break;
					default:
						break;
				}
			}
		}
		enumerator->destroy(enumerator);
	}
}

METHOD(eap_method_t, process, status_t,
	private_eap_radius_t *this, eap_payload_t *in, eap_payload_t **out)
{
	radius_message_t *request, *response;
	status_t status = FAILED;
	chunk_t data;

	request = radius_message_create(RMC_ACCESS_REQUEST);
	add_radius_request_attrs(this, request);

	data = in->get_data(in);
	DBG3(DBG_IKE, "%N payload %B", eap_type_names, this->type, &data);

	/* fragment data suitable for RADIUS */
	while (data.len > MAX_RADIUS_ATTRIBUTE_SIZE)
	{
		request->add(request, RAT_EAP_MESSAGE,
					 chunk_create(data.ptr,MAX_RADIUS_ATTRIBUTE_SIZE));
		data = chunk_skip(data, MAX_RADIUS_ATTRIBUTE_SIZE);
	}
	request->add(request, RAT_EAP_MESSAGE, data);

	response = this->client->request(this->client, request);
	if (response)
	{
		eap_radius_forward_to_ike(response);
		switch (response->get_code(response))
		{
			case RMC_ACCESS_CHALLENGE:
				if (radius2ike(this, response, out))
				{
					status = NEED_MORE;
					break;
				}
				status = FAILED;
				break;
			case RMC_ACCESS_ACCEPT:
				if (this->class_group)
				{
					process_class(this, response);
				}
				if (this->filter_id)
				{
					process_filter_id(this, response);
				}
				process_timeout(this, response);
				process_cfg_attributes(this, response);
				DBG1(DBG_IKE, "RADIUS authentication of '%Y' successful",
					 this->peer);
				status = SUCCESS;
				break;
			case RMC_ACCESS_REJECT:
			default:
				DBG1(DBG_IKE, "RADIUS authentication of '%Y' failed",
					 this->peer);
				status = FAILED;
				break;
		}
		response->destroy(response);
	}
	request->destroy(request);
	return status;
}

METHOD(eap_method_t, get_type, eap_type_t,
	private_eap_radius_t *this, u_int32_t *vendor)
{
	*vendor = this->vendor;
	return this->type;
}

METHOD(eap_method_t, get_msk, status_t,
	private_eap_radius_t *this, chunk_t *out)
{
	chunk_t msk;

	msk = this->client->get_msk(this->client);
	if (msk.len)
	{
		*out = msk;
		return SUCCESS;
	}
	return FAILED;
}

METHOD(eap_method_t, get_identifier, u_int8_t,
	private_eap_radius_t *this)
{
	return this->identifier;
}

METHOD(eap_method_t, set_identifier, void,
	private_eap_radius_t *this, u_int8_t identifier)
{
	this->identifier = identifier;
}

METHOD(eap_method_t, is_mutual, bool,
	private_eap_radius_t *this)
{
	switch (this->type)
	{
		case EAP_AKA:
		case EAP_SIM:
			return TRUE;
		default:
			return FALSE;
	}
}

METHOD(eap_method_t, destroy, void,
	private_eap_radius_t *this)
{
	this->peer->destroy(this->peer);
	this->server->destroy(this->server);
	this->client->destroy(this->client);
	free(this);
}

/**
 * Generic constructor
 */
eap_radius_t *eap_radius_create(identification_t *server, identification_t *peer)
{
	private_eap_radius_t *this;

	INIT(this,
		.public = {
			.eap_method = {
				.initiate = _initiate,
				.process = _process,
				.get_type = _get_type,
				.is_mutual = _is_mutual,
				.get_msk = _get_msk,
				.get_identifier = _get_identifier,
				.set_identifier = _set_identifier,
				.destroy = _destroy,
			},
		},
		/* initially EAP_RADIUS, but is set to the method selected by RADIUS */
		.type = EAP_RADIUS,
		.eap_start = lib->settings->get_bool(lib->settings,
									"%s.plugins.eap-radius.eap_start", FALSE,
									charon->name),
		.id_prefix = lib->settings->get_str(lib->settings,
									"%s.plugins.eap-radius.id_prefix", "",
									charon->name),
		.class_group = lib->settings->get_bool(lib->settings,
									"%s.plugins.eap-radius.class_group", FALSE,
									charon->name),
		.filter_id = lib->settings->get_bool(lib->settings,
									"%s.plugins.eap-radius.filter_id", FALSE,
									charon->name),
	);
	this->client = eap_radius_create_client();
	if (!this->client)
	{
		free(this);
		return NULL;
	}
	this->peer = peer->clone(peer);
	this->server = server->clone(server);
	return &this->public;
}
