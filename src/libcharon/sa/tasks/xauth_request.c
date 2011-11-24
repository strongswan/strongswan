
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
	 * The user name
	 */
	chunk_t user_name;

	/**
	 * The user pass
	 */
	chunk_t user_pass;

	/**
	 * The current state of the task
	 */
	enum {
		TASK_XAUTH_INIT,
		TASK_XAUTH_PASS_DONE,
	} state;

	/**
	 * The status of the XAuth request
	 */
	status_t status;
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

METHOD(task_t, build_i, status_t,
	private_xauth_request_t *this, message_t *message)
{
	cp_payload_t *cp;
	chunk_t chunk = chunk_empty;

	switch(this->state)
	{
		case TASK_XAUTH_INIT:
			cp = cp_payload_create_type(CONFIGURATION_V1, CFG_REQUEST);
			cp->add_attribute(cp, configuration_attribute_create_chunk(
						CONFIGURATION_ATTRIBUTE_V1, XAUTH_USER_NAME, chunk));
			cp->add_attribute(cp, configuration_attribute_create_chunk(
						CONFIGURATION_ATTRIBUTE_V1, XAUTH_USER_PASSWORD, chunk));
			break;
		case TASK_XAUTH_PASS_DONE:
			cp = cp_payload_create_type(CONFIGURATION_V1, CFG_SET);
			cp->add_attribute(cp, configuration_attribute_create_value(
						XAUTH_STATUS,
						(this->status == FAILED ? XAUTH_STATUS_FAIL : XAUTH_STATUS_OK)));
			break;
		default:
			return FAILED;

	}
	/* Add the payloads into the message */
	message->add_payload(message, (payload_t *)cp);


	return NEED_MORE;
}

METHOD(task_t, process_r, status_t,
	private_xauth_request_t *this, message_t *message)
{
	return NEED_MORE;
}

METHOD(task_t, build_r, status_t,
	private_xauth_request_t *this, message_t *message)
{
	return NEED_MORE;
}

METHOD(task_t, process_i, status_t,
	private_xauth_request_t *this, message_t *message)
{
	cp_payload_t *cp_payload;
	enumerator_t *enumerator;
	configuration_attribute_t *ca;
	chunk_t status_chunk = chunk_empty;

	cp_payload = (cp_payload_t *)message->get_payload(message, CONFIGURATION_V1);
	enumerator = cp_payload->create_attribute_enumerator(cp_payload);
	while (enumerator->enumerate(enumerator, &ca))
	{
		switch(ca->get_type(ca))
		{
			case XAUTH_USER_NAME:
				this->user_name = ca->get_chunk(ca);
				break;
			case XAUTH_USER_PASSWORD:
				this->user_pass = ca->get_chunk(ca);
				break;
			case XAUTH_STATUS:
				status_chunk = ca->get_chunk(ca);
				break;
			default:
				DBG3(DBG_IKE, "Unknown config attribute type %d, ignored", ca->get_type(ca));
		}
	}
	enumerator->destroy(enumerator);

	switch(this->state)
	{
		case TASK_XAUTH_INIT:

			if(cp_payload->get_type(cp_payload) != CFG_REPLY)
			{
				DBG1(DBG_IKE, "ERROR: ConfigMode payload is not a reply");
				return FAILED;
			}

			this->state = TASK_XAUTH_PASS_DONE;
			if((this->user_name.len == 0) || (this->user_pass.len == 0))
			{
				DBG1(DBG_IKE, "ERROR: Did not get user name or user pass, aborting");
				this->status = FAILED;
				/* We should close out the XAuth negotiation cleanly by sending a "failed" message */
				return NEED_MORE;
			}

			/* TODO-IKEv1: Do actual user/pass verification */
//			if(!chunk_compare(this->user_name, this->user_pass))
//			{
//				this->status = FAILED;
//				DBG1(DBG_IKE, "ERROR: user/pass verification failure");
				/* We should close out the XAuth negotiation cleanly by sending a "failed" message */
//				return NEED_MORE;
//			}

			this->status = SUCCESS;
			return NEED_MORE;
		case TASK_XAUTH_PASS_DONE:
			if(cp_payload->get_type(cp_payload) != CFG_ACK)
			{
				DBG1(DBG_IKE, "ERROR: ConfigMode payload is not a status ack");
				return FAILED;
			}
			if(status_chunk.len != 0)
			{
				DBG1(DBG_IKE, "Status payload of an ack had data, hmm....");
			}

			DBG1(DBG_IKE, "Done with XAUTH!!!");
			return this->status;
	}
	return FAILED;
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
		.user_name = chunk_empty,
		.user_pass = chunk_empty,
		.state = TASK_XAUTH_INIT,
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
