
#include "xauth_request.h"

#include <daemon.h>
#include <hydra.h>
#include <encoding/payloads/cp_payload.h>
#include <encoding/payloads/hash_payload.h>
#include <encoding/generator.h>

typedef struct private_xauth_request_t private_xauth_request_t;

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
 * Scan for configuration payloads and attributes
 */
static void process_payloads(private_xauth_request_t *this, message_t *message)
{
}

METHOD(task_t, build_i, status_t,
	private_xauth_request_t *this, message_t *message)
{
	cp_payload_t *cp;
	chunk_t chunk = chunk_empty;
	hash_payload_t *hash_payload;
	generator_t *generator;
	chunk_t attr_chunk;
	chunk_t mid_chunk;
	u_int32_t *lenpos;
	u_int32_t message_id;
	keymat_t *keymat;
	prf_t *prf;
	chunk_t hash_in, hash_out;

	DBG1(DBG_IKE, "BUILDING XAUTH REQUEST PACKET");
	/* TODO1: Create ATTR payload */
	cp = cp_payload_create(CONFIGURATION_V1);
	cp->add_attribute(cp, configuration_attribute_create_chunk(
				CONFIGURATION_ATTRIBUTE_V1, XAUTH_USER_NAME, chunk));
	cp->add_attribute(cp, configuration_attribute_create_chunk(
				CONFIGURATION_ATTRIBUTE_V1, XAUTH_USER_PASSWORD, chunk));

	/* Create HASH payload */
	hash_payload = hash_payload_create();
	/* TODO1: Add data into the hash */

	/* Calculate the chunk for the ATTR payload */
	generator = generator_create();
	cp->payload_interface.set_next_type(&cp->payload_interface, NO_PAYLOAD);
	generator->generate_payload(generator, (payload_t *)cp);
	attr_chunk = generator->get_chunk(generator, &lenpos);

	/* Get the message ID in network order */
	htoun32(&message_id, message->get_message_id(message));
	mid_chunk = chunk_from_thing(message_id);

	/* Get the hashed data */
	hash_in = chunk_cat("cc", mid_chunk, attr_chunk);

	message->add_payload(message, (payload_t *)hash_payload);
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
			},
		},
		.initiator = initiator,
		.ike_sa = ike_sa,
		.requested = linked_list_create(),
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
