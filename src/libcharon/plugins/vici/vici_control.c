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

#include "vici_control.h"
#include "vici_builder.h"

#include <inttypes.h>

#include <daemon.h>
#include <collections/array.h>

typedef struct private_vici_control_t private_vici_control_t;

/**
 * Private data of an vici_control_t object.
 */
struct private_vici_control_t {

	/**
	 * Public vici_control_t interface.
	 */
	vici_control_t public;

	/**
	 * Dispatcher
	 */
	vici_dispatcher_t *dispatcher;
};

/**
 * Log callback helper data
 */
typedef struct {
	/** dispatcher to send log messages over */
	vici_dispatcher_t *dispatcher;
	/** connection ID to send messages to */
	u_int id;
	/** loglevel */
	level_t level;
} log_info_t;

/**
 * Log using vici event messages
 */
static bool log_vici(log_info_t *info, debug_t group, level_t level,
					 ike_sa_t *ike_sa, char *text)
{
	if (level <= info->level)
	{
		vici_message_t *message;
		vici_builder_t *builder;

		builder = vici_builder_create();
		builder->add_kv(builder, "group", "%N", debug_names, group);
		builder->add_kv(builder, "level", "%d", level);
		if (ike_sa)
		{
			builder->add_kv(builder, "ikesa-name", "%s",
							ike_sa->get_name(ike_sa));
			builder->add_kv(builder, "ikesa-uniqueid", "%u",
							ike_sa->get_unique_id(ike_sa));
		}
		builder->add_kv(builder, "msg", "%s", text);

		message = builder->finalize(builder);
		if (message)
		{
			info->dispatcher->raise_event(info->dispatcher, "control-log",
										  info->id, message);
		}
	}
	return TRUE;
}

/**
 * Send a (error) reply message
 */
static vici_message_t* send_reply(private_vici_control_t *this, char *fmt, ...)
{
	vici_builder_t *builder;
	va_list args;

	builder = vici_builder_create();
	builder->add_kv(builder, "success", fmt ? "no" : "yes");
	if (fmt)
	{
		va_start(args, fmt);
		builder->vadd_kv(builder, "errmsg", fmt, args);
		va_end(args);
	}
	return builder->finalize(builder);
}

/**
 * Get the child_cfg having name from peer_cfg
 */
static child_cfg_t* get_child_from_peer(peer_cfg_t *peer_cfg, char *name)
{
	child_cfg_t *current, *found = NULL;
	enumerator_t *enumerator;

	enumerator = peer_cfg->create_child_cfg_enumerator(peer_cfg);
	while (enumerator->enumerate(enumerator, &current))
	{
		if (streq(current->get_name(current), name))
		{
			found = current;
			found->get_ref(found);
			break;
		}
	}
	enumerator->destroy(enumerator);
	return found;
}

CALLBACK(initiate, vici_message_t*,
	private_vici_control_t *this, char *name, u_int id, vici_message_t *request)
{
	child_cfg_t *child_cfg = NULL;
	peer_cfg_t *peer_cfg;
	enumerator_t *enumerator;
	char *child;
	u_int timeout;
	log_info_t log = {
		.dispatcher = this->dispatcher,
		.id = id,
	};

	child = request->get_str(request, NULL, "child");
	timeout = request->get_int(request, 0, "timeout");
	log.level = request->get_int(request, 1, "loglevel");

	if (!child)
	{
		return send_reply(this, "missing configuration name");
	}
	enumerator = charon->backends->create_peer_cfg_enumerator(charon->backends,
											NULL, NULL, NULL, NULL, IKE_ANY);
	while (enumerator->enumerate(enumerator, &peer_cfg))
	{
		child_cfg = get_child_from_peer(peer_cfg, child);
		if (child_cfg)
		{
			peer_cfg->get_ref(peer_cfg);
			break;
		}
	}
	enumerator->destroy(enumerator);

	if (!child_cfg)
	{
		return send_reply(this, "CHILD_SA config '%s' not found", child);
	}
	switch (charon->controller->initiate(charon->controller,
				peer_cfg, child_cfg, (controller_cb_t)log_vici, &log, timeout))
	{
		case SUCCESS:
			return send_reply(this, NULL);
		case OUT_OF_RES:
			return send_reply(this, "CHILD_SA '%s' not established after %dms",
							  child, timeout);
		case FAILED:
		default:
			return send_reply(this, "establishing CHILD_SA '%s' failed", child);
	}
}

CALLBACK(terminate, vici_message_t*,
	private_vici_control_t *this, char *name, u_int id, vici_message_t *request)
{
	enumerator_t *enumerator, *isas, *csas;
	char *child, *ike;
	u_int timeout, child_id, ike_id, current, *del, done = 0;
	ike_sa_t *ike_sa;
	child_sa_t *child_sa;
	array_t *ids;
	vici_message_t *reply;
	log_info_t log = {
		.dispatcher = this->dispatcher,
		.id = id,
	};

	child = request->get_str(request, NULL, "child");
	ike = request->get_str(request, NULL, "ike");
	child_id = request->get_int(request, 0, "child-id");
	ike_id = request->get_int(request, 0, "ike-id");
	timeout = request->get_int(request, 0, "timeout");
	log.level = request->get_int(request, 1, "loglevel");

	if (!child && !ike && !ike_id && !child_id)
	{
		return send_reply(this, "missing terminate selector");
	}

	ids = array_create(sizeof(u_int), 0);

	isas = charon->controller->create_ike_sa_enumerator(charon->controller, TRUE);
	while (isas->enumerate(isas, &ike_sa))
	{
		if (child || child_id)
		{
			if (ike && !streq(ike, ike_sa->get_name(ike_sa)))
			{
				continue;
			}
			if (ike_id && ike_id != ike_sa->get_unique_id(ike_sa))
			{
				continue;
			}
			csas = ike_sa->create_child_sa_enumerator(ike_sa);
			while (csas->enumerate(csas, &child_sa))
			{
				if (child && !streq(child, child_sa->get_name(child_sa)))
				{
					continue;
				}
				if (child_id && child_sa->get_reqid(child_sa) != child_id)
				{
					continue;
				}
				current = child_sa->get_reqid(child_sa);
				array_insert(ids, ARRAY_TAIL, &current);
			}
			csas->destroy(csas);
		}
		else if (ike && streq(ike, ike_sa->get_name(ike_sa)))
		{
			current = ike_sa->get_unique_id(ike_sa);
			array_insert(ids, ARRAY_TAIL, &current);
		}
		else if (ike_id && ike_id == ike_sa->get_unique_id(ike_sa))
		{
			array_insert(ids, ARRAY_TAIL, &ike_id);
		}
	}
	isas->destroy(isas);

	enumerator = array_create_enumerator(ids);
	while (enumerator->enumerate(enumerator, &del))
	{
		if (child || child_id)
		{
			if (charon->controller->terminate_child(charon->controller, *del,
						(controller_cb_t)log_vici, &log, timeout) == SUCCESS)
			{
				done++;
			}
		}
		else
		{
			if (charon->controller->terminate_ike(charon->controller, *del,
						(controller_cb_t)log_vici, &log, timeout) == SUCCESS)
			{
				done++;
			}
		}
	}
	enumerator->destroy(enumerator);

	if (array_count(ids) == 0)
	{
		reply = send_reply(this, "no matching SAs to terminate found");
	}
	else if (done < array_count(ids))
	{
		if (array_count(ids) == 1)
		{
			reply = send_reply(this, "terminating SA failed");
		}
		else
		{
			reply = send_reply(this, "terminated %u of %u SAs",
							   done, array_count(ids));
		}
	}
	else
	{
		reply = send_reply(this, NULL);
	}
	array_destroy(ids);
	return reply;
}

static void manage_command(private_vici_control_t *this,
						   char *name, vici_command_cb_t cb, bool reg)
{
	this->dispatcher->manage_command(this->dispatcher, name,
									 reg ? cb : NULL, this);
}

/**
 * (Un-)register dispatcher functions
 */
static void manage_commands(private_vici_control_t *this, bool reg)
{
	manage_command(this, "initiate", initiate, reg);
	manage_command(this, "terminate", terminate, reg);
	this->dispatcher->manage_event(this->dispatcher, "control-log", reg);
}

METHOD(vici_control_t, destroy, void,
	private_vici_control_t *this)
{
	manage_commands(this, FALSE);
	free(this);
}

/**
 * See header
 */
vici_control_t *vici_control_create(vici_dispatcher_t *dispatcher)
{
	private_vici_control_t *this;

	INIT(this,
		.public = {
			.destroy = _destroy,
		},
		.dispatcher = dispatcher,
	);

	manage_commands(this, TRUE);

	return &this->public;
}
