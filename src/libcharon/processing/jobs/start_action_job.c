/*
 * Copyright (C) 2011 Andreas Steffen
 * HSR Hochschule fuer Technik Rapperswil
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

#include "start_action_job.h"

#include <daemon.h>


typedef struct private_start_action_job_t private_start_action_job_t;

/**
 * Private data of an start_action_job_t object.
 */
struct private_start_action_job_t {
	/**
	 * Public start_action_job_t interface.
	 */
	start_action_job_t public;
};

METHOD(job_t, destroy, void,
	private_start_action_job_t *this)
{
	free(this);
}

METHOD(job_t, execute, void,
	private_start_action_job_t *this)
{
	enumerator_t *enumerator, *children;
	peer_cfg_t *peer_cfg;
	child_cfg_t *child_cfg;
	char *name;

	enumerator = charon->backends->create_peer_cfg_enumerator(charon->backends,
													NULL, NULL, NULL, NULL);
	while (enumerator->enumerate(enumerator, &peer_cfg))
	{
		if (peer_cfg->get_ike_version(peer_cfg) != 2)
		{
			continue;
		}

		children = peer_cfg->create_child_cfg_enumerator(peer_cfg);
		while (children->enumerate(children, &child_cfg))
		{
			name = child_cfg->get_name(child_cfg);

			switch (child_cfg->get_start_action(child_cfg))
			{
				case ACTION_RESTART:
					DBG1(DBG_JOB, "start action: initiate '%s'", name);
					charon->controller->initiate(charon->controller,
												 peer_cfg->get_ref(peer_cfg),
												 child_cfg->get_ref(child_cfg),
												 NULL, NULL);
					break;
				case ACTION_ROUTE:
					DBG1(DBG_JOB, "start action: route '%s'", name);
					charon->traps->install(charon->traps, peer_cfg, child_cfg);
					break;
				case ACTION_NONE:
					break;
			}
		}
		children->destroy(children);
	}
	enumerator->destroy(enumerator);
	destroy(this);
}

/*
 * Described in header
 */
start_action_job_t *start_action_job_create(void)
{
	private_start_action_job_t *this;

	INIT(this,
		.public = {
			.job_interface = {
				.execute = _execute,
				.destroy = _destroy,
			},
		},
	)
	return &this->public;
}

