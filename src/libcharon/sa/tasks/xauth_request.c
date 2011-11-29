
#include "xauth_request.h"

#include <daemon.h>
#include <hydra.h>
#include <encoding/payloads/cp_payload.h>

typedef struct private_xauth_request_t private_xauth_request_t;

enum {
	XAUTH_STATUS_FAIL = 0,
	XAUTH_STATUS_OK = 1,
};

/**
 * Private members of a xauth_request_t task.
 */
struct private_xauth_request_t {

	/**
	 * Public methods and task_t interface.
	 */
	xauth_request_t public;

	/**
	 * Assigned IKE_SA.
	 */
	ike_sa_t *ike_sa;

	/**
	 * Are we the initiator?
	 */
	bool initiator;

	/**
	 * virtual ip
	 */
	host_t *virtual_ip;

	/**
	 * list of attributes requested and its handler, entry_t
	 */
	linked_list_t *requested;

	/**
	 * The current and next state of the task
	 */
	enum {
		TASK_XAUTH_INIT,
		TASK_XAUTH_PASS_VERIFY,
		TASK_XAUTH_COMPLETE,
	} state, next_state;

	/**
	 * The status of the XAuth request
	 */
	status_t status;

	/**
	 * The current auth config
	 */
	auth_cfg_t *auth_cfg;

	/**
	 * The received XAuth Status
	 */
	u_int16_t xauth_status_data;

	/**
	 * The received XAuth user name
	 */
	chunk_t xauth_user_name;

	/**
	 * The received XAuth user pass
	 */
	chunk_t xauth_user_pass;

	/**
	 * Whether the user name attribute was received
	 */
	bool xauth_user_name_recv;

	/**
	 * Whether the user pass attribute was received
	 */
	bool xauth_user_pass_recv;

	/**
	 * Whether the XAuth status attribute was received
	 */
	bool xauth_status_recv;
};

/**
 * Entry for a requested attribute and the requesting handler
 */
typedef struct {
	/** attribute requested */
	configuration_attribute_type_t type;
	/** handler requesting this attribute */
	attribute_handler_t *handler;
} entry_t;

/**
 * Get the first authentcation config from peer config
 */
static auth_cfg_t *get_auth_cfg(private_xauth_request_t *this, bool local)
{
	enumerator_t *enumerator;
	auth_cfg_t *cfg = NULL;
	peer_cfg_t *peer_cfg = this->ike_sa->get_peer_cfg(this->ike_sa);

	enumerator = peer_cfg->create_auth_cfg_enumerator(peer_cfg,
															local);
	enumerator->enumerate(enumerator, &cfg);
	enumerator->destroy(enumerator);
	return cfg;
}

/**
 * build INTERNAL_IPV4/6_ADDRESS attribute from virtual ip
 */
static configuration_attribute_t *build_vip(host_t *vip)
{
	configuration_attribute_type_t type;
	chunk_t chunk, prefix;

	if (vip->get_family(vip) == AF_INET)
	{
		type = INTERNAL_IP4_ADDRESS;
		if (vip->is_anyaddr(vip))
		{
			chunk = chunk_empty;
		}
		else
		{
			chunk = vip->get_address(vip);
		}
	}
	else
	{
		type = INTERNAL_IP6_ADDRESS;
		if (vip->is_anyaddr(vip))
		{
			chunk = chunk_empty;
		}
		else
		{
			prefix = chunk_alloca(1);
			*prefix.ptr = 64;
			chunk = vip->get_address(vip);
			chunk = chunk_cata("cc", chunk, prefix);
		}
	}
	return configuration_attribute_create_chunk(CONFIGURATION_ATTRIBUTE,
												type, chunk);
}

/**
 * Handle a received attribute as initiator
 */
static void handle_attribute(private_xauth_request_t *this,
							 configuration_attribute_t *ca)
{
	attribute_handler_t *handler = NULL;
	enumerator_t *enumerator;
	entry_t *entry;

	/* find the handler which requested this attribute */
	enumerator = this->requested->create_enumerator(this->requested);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->type == ca->get_type(ca))
		{
			handler = entry->handler;
			this->requested->remove_at(this->requested, enumerator);
			free(entry);
			break;
		}
	}
	enumerator->destroy(enumerator);

	/* and pass it to the handle function */
	handler = hydra->attributes->handle(hydra->attributes,
							this->ike_sa->get_other_id(this->ike_sa), handler,
							ca->get_type(ca), ca->get_chunk(ca));
	if (handler)
	{
		this->ike_sa->add_configuration_attribute(this->ike_sa,
				handler, ca->get_type(ca), ca->get_chunk(ca));
	}
}

/**
 * process a single configuration attribute
 */
static void process_attribute(private_xauth_request_t *this,
							  configuration_attribute_t *ca)
{
	host_t *ip;
	chunk_t addr;
	int family = AF_INET6;

	switch (ca->get_type(ca))
	{
		case XAUTH_USER_NAME:
			this->xauth_user_name = ca->get_chunk(ca);
			this->xauth_user_name_recv = TRUE;
			break;
		case XAUTH_USER_PASSWORD:
			this->xauth_user_pass = ca->get_chunk(ca);
			this->xauth_user_pass_recv = TRUE;
			break;
		case XAUTH_STATUS:
			this->xauth_status_data = ca->get_value(ca);
			this->xauth_status_recv = TRUE;
			break;
		case INTERNAL_IP4_ADDRESS:
			family = AF_INET;
			/* fall */
		case INTERNAL_IP6_ADDRESS:
		{
			addr = ca->get_chunk(ca);
			if (addr.len == 0)
			{
				ip = host_create_any(family);
			}
			else
			{
				/* skip prefix byte in IPv6 payload*/
				if (family == AF_INET6)
				{
					addr.len--;
				}
				ip = host_create_from_chunk(family, addr, 0);
			}
			if (ip)
			{
				DESTROY_IF(this->virtual_ip);
				this->virtual_ip = ip;
			}
			break;
		}
		case INTERNAL_IP4_SERVER:
		case INTERNAL_IP6_SERVER:
			/* assume it's a Windows client if we see proprietary attributes */
			this->ike_sa->enable_extension(this->ike_sa, EXT_MS_WINDOWS);
			/* fall */
		default:
		{
			if (this->initiator)
			{
				handle_attribute(this, ca);
			}
		}
	}
}

/**
 * Scan for configuration payloads and attributes
 */
static status_t process_payloads(private_xauth_request_t *this, message_t *message)
{
	enumerator_t *enumerator, *attributes;
	payload_t *payload;

	enumerator = message->create_payload_enumerator(message);
	while (enumerator->enumerate(enumerator, &payload))
	{
		switch(payload->get_type(payload))
		{
			case CONFIGURATION:
			case CONFIGURATION_V1:
			{
				cp_payload_t *cp = (cp_payload_t*)payload;
				configuration_attribute_t *ca;

				switch (cp->get_type(cp))
				{
					case CFG_REQUEST:
					case CFG_REPLY:
					case CFG_SET:
					case CFG_ACK:
					{
						attributes = cp->create_attribute_enumerator(cp);
						while (attributes->enumerate(attributes, &ca))
						{
							DBG2(DBG_IKE, "processing %N attribute",
								 configuration_attribute_type_names, ca->get_type(ca));
							process_attribute(this, ca);
						}
						attributes->destroy(attributes);
						break;
					}
					default:
						DBG1(DBG_IKE, "ignoring %N config payload",
							 config_type_names, cp->get_type(cp));
						break;
				}

				switch(this->state)
				{
					case TASK_XAUTH_INIT:
						if(((cp->get_type(cp) != CFG_REQUEST) && (cp->get_type(cp) != CFG_REPLY)) ||
								(this->xauth_user_name_recv != TRUE) ||
								(this->xauth_user_pass_recv != TRUE))
						{
							/* Didn't get an XAuth message, assume we're a ConfigMode message, set state appropriately */
							this->state = TASK_XAUTH_COMPLETE;
							this->next_state = TASK_XAUTH_COMPLETE;
							this->status = SUCCESS;
							break;
						}
						this->next_state = TASK_XAUTH_PASS_VERIFY;
						break;
					case TASK_XAUTH_PASS_VERIFY:
						if(((cp->get_type(cp) != CFG_SET) && (cp->get_type(cp) != CFG_ACK)) ||
								(this->xauth_status_recv != TRUE))
						{
							DBG1(DBG_IKE, "Didn't receive XAuth status.");
							return FAILED;
						}
						/* Set the return status for the build call */
						if(cp->get_type(cp) != CFG_ACK)
						{
							this->status = (this->xauth_status_data == XAUTH_STATUS_OK ? SUCCESS : FAILED);
						}
						else
						{
							this->status = SUCCESS;
						}
						this->next_state = TASK_XAUTH_COMPLETE;
						break;
					default:
						this->next_state = TASK_XAUTH_COMPLETE;
						this->status = SUCCESS;
						break;
				}
			}
			default:
				break;
		}
	}
	enumerator->destroy(enumerator);
	return NEED_MORE;
}

METHOD(task_t, build_i, status_t,
	private_xauth_request_t *this, message_t *message)
{
	cp_payload_t *cp = NULL;
	chunk_t chunk = chunk_empty;
	ike_version_t version;
	payload_type_t cp_type;
	payload_type_t ca_type;
	host_t *vip;
	peer_cfg_t *config;
	enumerator_t *enumerator;
	attribute_handler_t *handler;
	configuration_attribute_type_t type;
	chunk_t data;

	DBG1(DBG_IKE, "%s: state %d", __func__, this->state);

	version = this->ike_sa->get_version(this->ike_sa);
	if(version == IKEV1)
	{
		if(this->ike_sa->get_state(this->ike_sa) != IKE_ESTABLISHED)
		{
			DBG1(DBG_IKE, "!!!!!!!!!!!!!!!!!!!!!!!!!NEED_MORE!!!!!!!!!!!!!!!!!!!!!");
			return NEED_MORE;
		}

		if(!this->auth_cfg)
		{
			this->auth_cfg = get_auth_cfg(this, TRUE);
		}
		switch((uintptr_t)this->auth_cfg->get(this->auth_cfg, AUTH_RULE_AUTH_CLASS))
		{
			case AUTH_CLASS_XAUTH_PSK:
			case AUTH_CLASS_XAUTH_PUBKEY:
				break;
			default:
				/* We aren't XAuth, so do nothing */
			DBG1(DBG_IKE, "!!!!!!!!!!!!!!!!!!!!!!!!!SUCCESS!!!!!!!!!!!!!!!!!!!!!");
				return SUCCESS;
		}
		cp_type = CONFIGURATION_V1;
		ca_type = CONFIGURATION_ATTRIBUTE_V1;
	}
	else /* IKEv2 */
	{
		/* IKEv2 does not support XAuth, skip those states. */
		this->state = TASK_XAUTH_COMPLETE;
		if (message->get_message_id(message) == 1)
		{	/* in first IKE_AUTH only */
			DBG1(DBG_IKE, "!!!!!!!!!!!!!!!!!!!!!!!!!NEED_MORE!!!!!!!!!!!!!!!!!!!!!");
			return NEED_MORE;
		}
		cp_type = CONFIGURATION;
		ca_type = CONFIGURATION_ATTRIBUTE;
	}
	switch(this->state)
	{
		case TASK_XAUTH_INIT:
			cp = cp_payload_create_type(cp_type, CFG_REQUEST);
			cp->add_attribute(cp, configuration_attribute_create_chunk(
						ca_type, XAUTH_USER_NAME, chunk));
			cp->add_attribute(cp, configuration_attribute_create_chunk(
						ca_type, XAUTH_USER_PASSWORD, chunk));
			break;
		case TASK_XAUTH_PASS_VERIFY:
			cp = cp_payload_create_type(cp_type, CFG_SET);
			cp->add_attribute(cp, configuration_attribute_create_value(
						XAUTH_STATUS,
						(this->status == FAILED ? XAUTH_STATUS_FAIL : XAUTH_STATUS_OK)));
			break;
		case TASK_XAUTH_COMPLETE:
			/* ConfigMode stuff */
			/* reuse virtual IP if we already have one */
			vip = this->ike_sa->get_virtual_ip(this->ike_sa, TRUE);
			if (!vip)
			{
				config = this->ike_sa->get_peer_cfg(this->ike_sa);
				vip = config->get_virtual_ip(config);
			}
			if (vip)
			{
				cp = cp_payload_create_type(cp_type, CFG_REQUEST);
				cp->add_attribute(cp, build_vip(vip));
			}

			enumerator = hydra->attributes->create_initiator_enumerator(hydra->attributes,
									this->ike_sa->get_other_id(this->ike_sa), vip);
			while (enumerator->enumerate(enumerator, &handler, &type, &data))
			{
				configuration_attribute_t *ca;
				entry_t *entry;

				/* create configuration attribute */
				DBG2(DBG_IKE, "building %N attribute",
					 configuration_attribute_type_names, type);
				ca = configuration_attribute_create_chunk(ca_type,
														  type, data);
				if (!cp)
				{
					cp = cp_payload_create_type(cp_type, CFG_REQUEST);
				}
				cp->add_attribute(cp, ca);

				/* save handler along with requested type */
				entry = malloc_thing(entry_t);
				entry->type = type;
				entry->handler = handler;

				this->requested->insert_last(this->requested, entry);
			}
			enumerator->destroy(enumerator);

			break;
		default:
			DBG1(DBG_IKE, "!!!!!!!!!!!!!!!!!!!!!!!!!FAILED!!!!!!!!!!!!!!!!!!!!!");
			return FAILED;

	}
	/* Add the payloads into the message */
	if(cp)
	{
		message->add_payload(message, (payload_t *)cp);
	}

			DBG1(DBG_IKE, "!!!!!!!!!!!!!!!!!!!!!!!!!NEED_MORE!!!!!!!!!!!!!!!!!!!!!");
	return NEED_MORE;
}

METHOD(task_t, process_r, status_t,
	private_xauth_request_t *this, message_t *message)
{
	ike_version_t version;
	payload_type_t cp_type;
	DBG1(DBG_IKE, "%s: state %d", __func__, this->state);

	version = this->ike_sa->get_version(this->ike_sa);
	if(version == IKEV1)
	{
		if(this->ike_sa->get_state(this->ike_sa) != IKE_ESTABLISHED)
		{
			return NEED_MORE;
		}
		if(!this->auth_cfg)
		{
			this->auth_cfg = get_auth_cfg(this, TRUE);
		}
		switch((uintptr_t)this->auth_cfg->get(this->auth_cfg, AUTH_RULE_AUTH_CLASS))
		{
			case AUTH_CLASS_XAUTH_PSK:
			case AUTH_CLASS_XAUTH_PUBKEY:
				break;
			default:
				/* We aren't XAuth, so do we should expect ConfigMode stuff */
				return SUCCESS;
		}
		cp_type = CONFIGURATION_V1;
	}
	else /* IKEv2 */
	{
		/* IKEv2 does not support XAuth, skip those states. */
		this->state = TASK_XAUTH_COMPLETE;
		if (message->get_message_id(message) == 1)
		{	/* in first IKE_AUTH only */
			return NEED_MORE;
		}
		cp_type = CONFIGURATION;
	}

	return process_payloads(this, message);
}

METHOD(task_t, build_r, status_t,
	private_xauth_request_t *this, message_t *message)
{
	chunk_t user_name = chunk_from_chars('j', 'o', 's', 't');
	chunk_t user_pass = chunk_from_chars('j', 'o', 's', 't');
	status_t status;
	cp_payload_t *cp = NULL;
	payload_type_t cp_type = CONFIGURATION;
	payload_type_t ca_type = CONFIGURATION_ATTRIBUTE;
	ike_version_t version;
	identification_t *id;
	enumerator_t *enumerator;
	configuration_attribute_type_t type;
	chunk_t value;
	host_t *vip = NULL;
	peer_cfg_t *config;

	DBG1(DBG_IKE, "%s: state %d", __func__, this->state);
	if(this->ike_sa->get_state(this->ike_sa) != IKE_ESTABLISHED)
	{
		return NEED_MORE;
	}
	version = this->ike_sa->get_version(this->ike_sa);
	if(version == IKEV1)
	{
		if(!this->auth_cfg)
		{
			this->auth_cfg = get_auth_cfg(this, TRUE);
		}
		switch((uintptr_t)this->auth_cfg->get(this->auth_cfg, AUTH_RULE_AUTH_CLASS))
		{
			case AUTH_CLASS_XAUTH_PSK:
			case AUTH_CLASS_XAUTH_PUBKEY:
				break;
			default:
				this->state = TASK_XAUTH_COMPLETE;
				return SUCCESS;
		}
		cp_type = CONFIGURATION_V1;
		ca_type = CONFIGURATION_ATTRIBUTE_V1;
	}

	switch(this->state)
	{
		case TASK_XAUTH_INIT:
			/* TODO-IKEv1: Fetch the user/pass from an authenticator */
			cp = cp_payload_create_type(cp_type, CFG_REPLY);
			cp->add_attribute(cp, configuration_attribute_create_chunk(
						ca_type, XAUTH_USER_NAME, user_name));
			cp->add_attribute(cp, configuration_attribute_create_chunk(
						ca_type, XAUTH_USER_PASSWORD, user_pass));
			chunk_clear(&user_name);
			chunk_clear(&user_pass);

			this->state = TASK_XAUTH_PASS_VERIFY;
			status = NEED_MORE;
			break;
		case TASK_XAUTH_PASS_VERIFY:
			cp = cp_payload_create_type(cp_type, CFG_ACK);
			cp->add_attribute(cp, configuration_attribute_create_value(
						XAUTH_STATUS, XAUTH_STATUS_OK));
			status = this->status;
			this->state = TASK_XAUTH_COMPLETE;
			break;
		case TASK_XAUTH_COMPLETE:
			id = this->ike_sa->get_other_eap_id(this->ike_sa);

			config = this->ike_sa->get_peer_cfg(this->ike_sa);
			if (this->virtual_ip)
			{
				DBG1(DBG_IKE, "peer requested virtual IP %H", this->virtual_ip);
				if (config->get_pool(config))
				{
					vip = hydra->attributes->acquire_address(hydra->attributes,
								config->get_pool(config), id, this->virtual_ip);
				}
				if (vip == NULL)
				{
					DBG1(DBG_IKE, "no virtual IP found, sending %N",
						 notify_type_names, INTERNAL_ADDRESS_FAILURE);
					message->add_notify(message, FALSE, INTERNAL_ADDRESS_FAILURE,
										chunk_empty);
					return SUCCESS;
				}
				DBG1(DBG_IKE, "assigning virtual IP %H to peer '%Y'", vip, id);
				this->ike_sa->set_virtual_ip(this->ike_sa, FALSE, vip);

				cp = cp_payload_create_type(cp_type, CFG_REPLY);
				cp->add_attribute(cp, build_vip(vip));
			}

			/* query registered providers for additional attributes to include */
			enumerator = hydra->attributes->create_responder_enumerator(
							hydra->attributes, config->get_pool(config), id, vip);
			while (enumerator->enumerate(enumerator, &type, &value))
			{
				if (!cp)
				{
					cp = cp_payload_create_type(cp_type, CFG_REPLY);
				}
				DBG2(DBG_IKE, "building %N attribute",
					 configuration_attribute_type_names, type);
				cp->add_attribute(cp,
					configuration_attribute_create_chunk(ca_type,
														 type, value));
			}
			enumerator->destroy(enumerator);
			status = SUCCESS;
			break;
		default:
			return FAILED;
	}
	return status;
}

METHOD(task_t, process_i, status_t,
	private_xauth_request_t *this, message_t *message)
{
	status_t status;
	DBG1(DBG_IKE, "%s: state %d", __func__, this->state);
	if (this->ike_sa->get_state(this->ike_sa) == IKE_ESTABLISHED)
	{	/* in last IKE_AUTH exchange */

		status = process_payloads(this, message);
		this->state = this->next_state;

		DBG1(DBG_IKE, "state %d, complete state %d", this->state, TASK_XAUTH_COMPLETE);
		DBG1(DBG_IKE, "status %d SUCCESS %d", this->status, SUCCESS);

		if (this->virtual_ip)
		{
			this->ike_sa->set_virtual_ip(this->ike_sa, TRUE, this->virtual_ip);
		}
		if(this->state == TASK_XAUTH_COMPLETE)
			return this->status;
		return status;
	}
	return NEED_MORE;

}

METHOD(task_t, get_type, task_type_t,
	private_xauth_request_t *this)
{
	return TASK_XAUTH_REQUEST;
}

METHOD(task_t, migrate, void,
	private_xauth_request_t *this, ike_sa_t *ike_sa)
{
	DESTROY_IF(this->virtual_ip);

	this->ike_sa = ike_sa;
	this->virtual_ip = NULL;
	this->requested->destroy_function(this->requested, free);
	this->requested = linked_list_create();
}

METHOD(task_t, destroy, void,
	private_xauth_request_t *this)
{
	DESTROY_IF(this->virtual_ip);
	this->requested->destroy_function(this->requested, free);
	free(this);
}

METHOD(task_t, swap_initiator, void,
	private_xauth_request_t *this)
{
	if(this->initiator)
	{
		this->public.task.build = _build_r;
		this->public.task.process = _process_r;
		this->initiator = FALSE;
	}
	else
	{
		this->public.task.build = _build_i;
		this->public.task.process = _process_i;
		this->initiator = TRUE;
	}
}

/*
 * Described in header.
 */
xauth_request_t *xauth_request_create(ike_sa_t *ike_sa, bool initiator)
{
	private_xauth_request_t *this;

	INIT(this,
		.public = {
			.task = {
				.get_type = _get_type,
				.migrate = _migrate,
				.destroy = _destroy,
				.swap_initiator = _swap_initiator,
			},
		},
		.initiator = initiator,
		.ike_sa = ike_sa,
		.requested = linked_list_create(),
		.state = TASK_XAUTH_INIT,
		.next_state = TASK_XAUTH_INIT,
		.xauth_status_data = XAUTH_STATUS_FAIL,
		.xauth_user_name = chunk_empty,
		.xauth_user_pass = chunk_empty,
		.xauth_user_name_recv = FALSE,
		.xauth_user_pass_recv = FALSE,
		.xauth_status_recv = FALSE,
	);

	if (initiator)
	{
		this->public.task.build = _build_i;
		this->public.task.process = _process_i;
	}
	else
	{
		this->public.task.build = _build_r;
		this->public.task.process = _process_r;
	}

	return &this->public;
}
