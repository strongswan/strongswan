/*
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

#include "stroke_control.h"

#include <daemon.h>

typedef struct private_stroke_control_t private_stroke_control_t;

/**
 * private data of stroke_control
 */
struct private_stroke_control_t {

	/**
	 * public functions
	 */
	stroke_control_t public;
};


typedef struct stroke_log_info_t stroke_log_info_t;

/**
 * helper struct to say what and where to log when using controller callback
 */
struct stroke_log_info_t {

	/**
	 * level to log up to
	 */
	level_t level;
	
	/**
	 * where to write log
	 */
	FILE* out;
};

/**
 * logging to the stroke interface
 */
static bool stroke_log(stroke_log_info_t *info, signal_t signal, level_t level,
					   ike_sa_t *ike_sa, char *format, va_list args)
{
	if (level <= info->level)
	{
		if (vfprintf(info->out, format, args) < 0 ||
			fprintf(info->out, "\n") < 0 ||
			fflush(info->out) != 0)
		{
			return FALSE;
		}
	}
	return TRUE;
}

/**
 * get the child_cfg with the same name as the peer cfg
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

/**
 * Implementation of stroke_control_t.initiate.
 */
static void initiate(private_stroke_control_t *this, stroke_msg_t *msg, FILE *out)
{
	peer_cfg_t *peer_cfg;
	child_cfg_t *child_cfg;
	stroke_log_info_t info;
	
	peer_cfg = charon->backends->get_peer_cfg_by_name(charon->backends,
													  msg->initiate.name);
	if (peer_cfg == NULL)
	{
		DBG1(DBG_CFG, "no config named '%s'\n", msg->initiate.name);
		return;
	}
	if (peer_cfg->get_ike_version(peer_cfg) != 2)
	{
		DBG1(DBG_CFG, "ignoring initiation request for IKEv%d config",
			 peer_cfg->get_ike_version(peer_cfg));
		peer_cfg->destroy(peer_cfg);
		return;
	}
	
	child_cfg = get_child_from_peer(peer_cfg, msg->initiate.name);
	if (child_cfg == NULL)
	{
		DBG1(DBG_CFG, "no child config named '%s'\n", msg->initiate.name);
		peer_cfg->destroy(peer_cfg);
		return;
	}
	
	if (msg->output_verbosity < 0)
	{
		charon->controller->initiate(charon->controller, peer_cfg, child_cfg,
									 NULL, NULL);
	}
	else
	{
		info.out = out;
		info.level = msg->output_verbosity;
		charon->controller->initiate(charon->controller, peer_cfg, child_cfg,
									 (controller_cb_t)stroke_log, &info);
	}
}

/**
 * Implementation of stroke_control_t.terminate.
 */
static void terminate(private_stroke_control_t *this, stroke_msg_t *msg, FILE *out)
{
	char *string, *pos = NULL, *name = NULL;
	u_int32_t id = 0;
	bool child;
	int len;
	ike_sa_t *ike_sa;
	iterator_t *iterator;
	stroke_log_info_t info;
	
	string = msg->terminate.name;
	
	len = strlen(string);
	if (len < 1)
	{
		DBG1(DBG_CFG, "error parsing string");
		return;
	}
	switch (string[len-1])
	{
		case '}':
			child = TRUE;
			pos = strchr(string, '{');
			break;
		case ']':
			child = FALSE;
			pos = strchr(string, '[');
			break;
		default:
			name = string;
			child = FALSE;
			break;
	}
	
	if (name)
	{
		/* is a single name */
	}
	else if (pos == string + len - 2)
	{	/* is name[] or name{} */
		string[len-2] = '\0';
		name = string;
	}
	else
	{	/* is name[123] or name{23} */
		string[len-1] = '\0';
		id = atoi(pos + 1);
		if (id == 0)
		{
			DBG1(DBG_CFG, "error parsing string");
			return;
		}
	}
	
	info.out = out;
	info.level = msg->output_verbosity;
	
	iterator = charon->controller->create_ike_sa_iterator(charon->controller);
	while (iterator->iterate(iterator, (void**)&ike_sa))
	{
		child_sa_t *child_sa;
		iterator_t *children;
		
		if (child)
		{
			children = ike_sa->create_child_sa_iterator(ike_sa);
			while (children->iterate(children, (void**)&child_sa))
			{
				if ((name && streq(name, child_sa->get_name(child_sa))) ||
					(id && id == child_sa->get_reqid(child_sa)))
				{
					id = child_sa->get_reqid(child_sa);
					children->destroy(children);
					iterator->destroy(iterator);
					
					charon->controller->terminate_child(charon->controller, id,
									(controller_cb_t)stroke_log, &info);
					return;
				}
			}
			children->destroy(children);
		}
		else if ((name && streq(name, ike_sa->get_name(ike_sa))) ||
				 (id && id == ike_sa->get_unique_id(ike_sa)))
		{
			id = ike_sa->get_unique_id(ike_sa);
			/* unlock manager first */
			iterator->destroy(iterator);
			
			charon->controller->terminate_ike(charon->controller, id,
								 	(controller_cb_t)stroke_log, &info);
			return;
		}
		
	}
	iterator->destroy(iterator);
	DBG1(DBG_CFG, "no such SA found");

}

/**
 * Implementation of stroke_control_t.route.
 */
static void route(private_stroke_control_t *this, stroke_msg_t *msg, FILE *out)
{
	peer_cfg_t *peer_cfg;
	child_cfg_t *child_cfg;
	stroke_log_info_t info;
	
	peer_cfg = charon->backends->get_peer_cfg_by_name(charon->backends,
													  msg->route.name);
	if (peer_cfg == NULL)
	{
		fprintf(out, "no config named '%s'\n", msg->route.name);
		return;
	}
	if (peer_cfg->get_ike_version(peer_cfg) != 2)
	{
		peer_cfg->destroy(peer_cfg);
		return;
	}
	
	child_cfg = get_child_from_peer(peer_cfg, msg->route.name);
	if (child_cfg == NULL)
	{
		fprintf(out, "no child config named '%s'\n", msg->route.name);
		peer_cfg->destroy(peer_cfg);
		return;
	}
	
	info.out = out;
	info.level = msg->output_verbosity;
	charon->controller->route(charon->controller, peer_cfg, child_cfg,
							  (controller_cb_t)stroke_log, &info);
	peer_cfg->destroy(peer_cfg);
	child_cfg->destroy(child_cfg);
}

/**
 * Implementation of stroke_control_t.unroute.
 */
static void unroute(private_stroke_control_t *this, stroke_msg_t *msg, FILE *out)
{
	char *name;
	ike_sa_t *ike_sa;
	iterator_t *iterator;
	stroke_log_info_t info;
	
	name = msg->terminate.name;
	
	info.out = out;
	info.level = msg->output_verbosity;
	
	iterator = charon->controller->create_ike_sa_iterator(charon->controller);
	while (iterator->iterate(iterator, (void**)&ike_sa))
	{
		child_sa_t *child_sa;
		iterator_t *children;
		u_int32_t id;

		children = ike_sa->create_child_sa_iterator(ike_sa);
		while (children->iterate(children, (void**)&child_sa))
		{
			if (child_sa->get_state(child_sa) == CHILD_ROUTED &&
				streq(name, child_sa->get_name(child_sa)))
			{
				id = child_sa->get_reqid(child_sa);
				children->destroy(children);
				iterator->destroy(iterator);
				charon->controller->unroute(charon->controller, id,
								(controller_cb_t)stroke_log, &info);
				return;
			}
		}
		children->destroy(children);
	}
	iterator->destroy(iterator);
	DBG1(DBG_CFG, "no such SA found");
}

/**
 * Implementation of stroke_control_t.destroy
 */
static void destroy(private_stroke_control_t *this)
{
	free(this);
}

/*
 * see header file
 */
stroke_control_t *stroke_control_create()
{
	private_stroke_control_t *this = malloc_thing(private_stroke_control_t);
	
	this->public.initiate = (void(*)(stroke_control_t*, stroke_msg_t *msg, FILE *out))initiate;
	this->public.terminate = (void(*)(stroke_control_t*, stroke_msg_t *msg, FILE *out))terminate;
	this->public.route = (void(*)(stroke_control_t*, stroke_msg_t *msg, FILE *out))route;
	this->public.unroute = (void(*)(stroke_control_t*, stroke_msg_t *msg, FILE *out))unroute;
	this->public.destroy = (void(*)(stroke_control_t*))destroy;
	
	return &this->public;
}

