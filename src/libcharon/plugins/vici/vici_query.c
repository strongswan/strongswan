/*
 * Copyright (C) 2014 Martin Willi
 * Copyright (C) 2014 revosec AG
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

#include "vici_query.h"
#include "vici_builder.h"

#include <inttypes.h>

#include <daemon.h>

typedef struct private_vici_query_t private_vici_query_t;

/**
 * Private data of an vici_query_t object.
 */
struct private_vici_query_t {

	/**
	 * Public vici_query_t interface.
	 */
	vici_query_t public;

	/**
	 * Dispatcher
	 */
	vici_dispatcher_t *dispatcher;
};

/**
 * List details of a CHILD_SA
 */
static void list_child(private_vici_query_t *this, vici_builder_t *b,
					   child_sa_t *child, time_t now)
{
	time_t t;
	u_int64_t bytes, packets;
	u_int16_t alg, ks;
	proposal_t *proposal;
	enumerator_t *enumerator;
	traffic_selector_t *ts;

	b->add_kv(b, "reqid", "%u", child->get_reqid(child));
	b->add_kv(b, "state", "%N", child_sa_state_names, child->get_state(child));
	b->add_kv(b, "mode", "%N", ipsec_mode_names, child->get_mode(child));
	if (child->get_state(child) == CHILD_INSTALLED ||
		child->get_state(child) == CHILD_REKEYING)
	{
		b->add_kv(b, "protocol", "%N", protocol_id_names,
				  child->get_protocol(child));
		if (child->has_encap(child))
		{
			b->add_kv(b, "encap", "yes");
		}
		b->add_kv(b, "spi-in", "%.8x", ntohl(child->get_spi(child, TRUE)));
		b->add_kv(b, "spi-out", "%.8x", ntohl(child->get_spi(child, FALSE)));

		if (child->get_ipcomp(child) != IPCOMP_NONE)
		{
			b->add_kv(b, "cpi-in", "%.4x", ntohs(child->get_cpi(child, TRUE)));
			b->add_kv(b, "cpi-out", "%.4x", ntohs(child->get_cpi(child, FALSE)));
		}
		proposal = child->get_proposal(child);
		if (proposal)
		{
			if (proposal->get_algorithm(proposal, ENCRYPTION_ALGORITHM,
										&alg, &ks) && alg != ENCR_UNDEFINED)
			{
				b->add_kv(b, "encr-alg", "%N", encryption_algorithm_names, alg);
				if (ks)
				{
					b->add_kv(b, "encr-keysize", "%u", ks);
				}
			}
			if (proposal->get_algorithm(proposal, INTEGRITY_ALGORITHM,
										&alg, &ks) && alg != ENCR_UNDEFINED)
			{
				b->add_kv(b, "integ-alg", "%N", integrity_algorithm_names, alg);
				if (ks)
				{
					b->add_kv(b, "integ-keysize", "%u", ks);
				}
			}
			if (proposal->get_algorithm(proposal, PSEUDO_RANDOM_FUNCTION,
										&alg, NULL))
			{
				b->add_kv(b, "prf-alg", "%N", pseudo_random_function_names, alg);
			}
			if (proposal->get_algorithm(proposal, DIFFIE_HELLMAN_GROUP,
										&alg, NULL))
			{
				b->add_kv(b, "dh-group", "%N", diffie_hellman_group_names, alg);
			}
			if (proposal->get_algorithm(proposal, EXTENDED_SEQUENCE_NUMBERS,
										&alg, NULL) && alg == EXT_SEQ_NUMBERS)
			{
				b->add_kv(b, "esn", "1");
			}
		}

		child->get_usestats(child, TRUE,  &t, &bytes, &packets);
		b->add_kv(b, "bytes-in", "%" PRIu64, bytes);
		b->add_kv(b, "packets-in", "%" PRIu64, packets);
		if (t)
		{
			b->add_kv(b, "use-in", "%"PRIu64, (u_int64_t)(now - t));
		}

		child->get_usestats(child, FALSE, &t, &bytes, &packets);
		b->add_kv(b, "bytes-out", "%"PRIu64, bytes);
		b->add_kv(b, "packets-out", "%"PRIu64, packets);
		if (t)
		{
			b->add_kv(b, "use-out", "%"PRIu64, (u_int64_t)(now - t));
		}

		t = child->get_lifetime(child, FALSE);
		if (t)
		{
			b->add_kv(b, "rekey-time", "%"PRId64, (int64_t)(t - now));
		}
		t = child->get_lifetime(child, TRUE);
		if (t)
		{
			b->add_kv(b, "life-time", "%"PRId64, (int64_t)(t - now));
		}
		t = child->get_installtime(child);
		b->add_kv(b, "install-time", "%"PRId64, (int64_t)(now - t));
	}

	b->begin_list(b, "local-ts");
	enumerator = child->create_ts_enumerator(child, TRUE);
	while (enumerator->enumerate(enumerator, &ts))
	{
		b->add_li(b, "%R", ts);
	}
	enumerator->destroy(enumerator);
	b->end_list(b /* local-ts */);

	b->begin_list(b, "remote-ts");
	enumerator = child->create_ts_enumerator(child, FALSE);
	while (enumerator->enumerate(enumerator, &ts))
	{
		b->add_li(b, "%R", ts);
	}
	enumerator->destroy(enumerator);
	b->end_list(b /* remote-ts */);
}

/**
 * List tasks in a specific queue
 */
static void list_task_queue(private_vici_query_t *this, vici_builder_t *b,
							ike_sa_t *ike_sa, task_queue_t q, char *name)
{
	enumerator_t *enumerator;
	bool has = FALSE;
	task_t *task;

	enumerator = ike_sa->create_task_enumerator(ike_sa, q);
	while (enumerator->enumerate(enumerator, &task))
	{
		if (!has)
		{
			b->begin_list(b, name);
			has = TRUE;
		}
		b->add_li(b, "%N", task_type_names, task->get_type(task));
	}
	enumerator->destroy(enumerator);
	if (has)
	{
		b->end_list(b);
	}
}

/**
 * List details of an IKE_SA
 */
static void list_ike(private_vici_query_t *this, vici_builder_t *b,
					 ike_sa_t *ike_sa, time_t now)
{
	time_t t;
	ike_sa_id_t *id;
	identification_t *eap;
	proposal_t *proposal;
	u_int16_t alg, ks;

	b->add_kv(b, "uniqueid", "%u", ike_sa->get_unique_id(ike_sa));
	b->add_kv(b, "version", "%u", ike_sa->get_version(ike_sa));
	b->add_kv(b, "state", "%N", ike_sa_state_names, ike_sa->get_state(ike_sa));

	b->add_kv(b, "local-host", "%H", ike_sa->get_my_host(ike_sa));
	b->add_kv(b, "local-id", "%Y", ike_sa->get_my_id(ike_sa));

	b->add_kv(b, "remote-host", "%H", ike_sa->get_other_host(ike_sa));
	b->add_kv(b, "remote-id", "%Y", ike_sa->get_other_id(ike_sa));

	eap = ike_sa->get_other_eap_id(ike_sa);

	if (!eap->equals(eap, ike_sa->get_other_id(ike_sa)))
	{
		if (ike_sa->get_version(ike_sa) == IKEV1)
		{
			b->add_kv(b, "remote-xauth-id", "%Y", eap);
		}
		else
		{
			b->add_kv(b, "remote-eap-id", "%Y", eap);
		}
	}

	id = ike_sa->get_id(ike_sa);
	if (id->is_initiator(id))
	{
		b->add_kv(b, "initiator", "yes");
	}
	b->add_kv(b, "initiator-spi", "%.16"PRIx64, id->get_initiator_spi(id));
	b->add_kv(b, "responder-spi", "%.16"PRIx64, id->get_responder_spi(id));

	proposal = ike_sa->get_proposal(ike_sa);
	if (proposal)
	{
		if (proposal->get_algorithm(proposal, ENCRYPTION_ALGORITHM, &alg, &ks))
		{
			b->add_kv(b, "encr-alg", "%N", encryption_algorithm_names, alg);
			if (ks)
			{
				b->add_kv(b, "encr-keysize", "%u", ks);
			}
		}
		if (proposal->get_algorithm(proposal, INTEGRITY_ALGORITHM, &alg, &ks))
		{
			b->add_kv(b, "integ-alg", "%N", integrity_algorithm_names, alg);
			if (ks)
			{
				b->add_kv(b, "integ-keysize", "%u", ks);
			}
		}
		if (proposal->get_algorithm(proposal, PSEUDO_RANDOM_FUNCTION, &alg, NULL))
		{
			b->add_kv(b, "prf-alg", "%N", pseudo_random_function_names, alg);
		}
		if (proposal->get_algorithm(proposal, DIFFIE_HELLMAN_GROUP, &alg, NULL))
		{
			b->add_kv(b, "dh-group", "%N", diffie_hellman_group_names, alg);
		}
	}

	if (ike_sa->get_state(ike_sa) == IKE_ESTABLISHED)
	{
		t = ike_sa->get_statistic(ike_sa, STAT_ESTABLISHED);
		b->add_kv(b, "established", "%"PRId64, (int64_t)(now - t));
		t = ike_sa->get_statistic(ike_sa, STAT_REKEY);
		if (t)
		{
			b->add_kv(b, "rekey-time", "%"PRId64, (int64_t)(t - now));
		}
		t = ike_sa->get_statistic(ike_sa, STAT_REAUTH);
		if (t)
		{
			b->add_kv(b, "reauth-time", "%"PRId64, (int64_t)(t - now));
		}
	}

	list_task_queue(this, b, ike_sa, TASK_QUEUE_QUEUED, "tasks-queued");
	list_task_queue(this, b, ike_sa, TASK_QUEUE_ACTIVE, "tasks-active");
	list_task_queue(this, b, ike_sa, TASK_QUEUE_PASSIVE, "tasks-passive");
}

CALLBACK(list_sas, vici_message_t*,
	private_vici_query_t *this, char *name, u_int id, vici_message_t *request)
{
	vici_builder_t *b;
	enumerator_t *isas, *csas;
	ike_sa_t *ike_sa;
	child_sa_t *child_sa;
	time_t now;
	char *ike;
	u_int ike_id;
	bool bl;

	bl = request->get_str(request, NULL, "noblock") == NULL;
	ike = request->get_str(request, NULL, "ike");
	ike_id = request->get_int(request, 0, "ike-id");

	isas = charon->controller->create_ike_sa_enumerator(charon->controller, bl);
	while (isas->enumerate(isas, &ike_sa))
	{
		if (ike && !streq(ike, ike_sa->get_name(ike_sa)))
		{
			continue;
		}
		if (ike_id && ike_id != ike_sa->get_unique_id(ike_sa))
		{
			continue;
		}

		now = time_monotonic(NULL);

		b = vici_builder_create();
		b->begin_section(b, ike_sa->get_name(ike_sa));

		list_ike(this, b, ike_sa, now);

		b->begin_section(b, "child-sas");
		csas = ike_sa->create_child_sa_enumerator(ike_sa);
		while (csas->enumerate(csas, &child_sa))
		{
			b->begin_section(b, child_sa->get_name(child_sa));
			list_child(this, b, child_sa, now);
			b->end_section(b);
		}
		csas->destroy(csas);
		b->end_section(b /* child-sas */ );

		b->end_section(b);

		this->dispatcher->raise_event(this->dispatcher, "list-sa", id,
									  b->finalize(b));
	}
	isas->destroy(isas);

	b = vici_builder_create();
	return b->finalize(b);
}

static void manage_command(private_vici_query_t *this,
						   char *name, vici_command_cb_t cb, bool reg)
{
	this->dispatcher->manage_command(this->dispatcher, name,
									 reg ? cb : NULL, this);
}

/**
 * (Un-)register dispatcher functions
 */
static void manage_commands(private_vici_query_t *this, bool reg)
{
	this->dispatcher->manage_event(this->dispatcher, "list-sa", reg);
	manage_command(this, "list-sas", list_sas, reg);
}

METHOD(vici_query_t, destroy, void,
	private_vici_query_t *this)
{
	manage_commands(this, FALSE);
	free(this);
}

/**
 * See header
 */
vici_query_t *vici_query_create(vici_dispatcher_t *dispatcher)
{
	private_vici_query_t *this;

	INIT(this,
		.public = {
			.destroy = _destroy,
		},
		.dispatcher = dispatcher,
	);

	manage_commands(this, TRUE);

	return &this->public;
}
