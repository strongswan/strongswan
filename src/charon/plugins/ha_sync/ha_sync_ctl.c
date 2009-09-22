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
 */

#include "ha_sync_ctl.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>

#include <processing/jobs/callback_job.h>

#define HA_SYNC_FIFO IPSEC_PIDDIR "/charon.ha"

typedef struct private_ha_sync_ctl_t private_ha_sync_ctl_t;

/**
 * Private data of an ha_sync_ctl_t object.
 */
struct private_ha_sync_ctl_t {

	/**
	 * Public ha_sync_ctl_t interface.
	 */
	ha_sync_ctl_t public;

	/**
	 * Segments to control
	 */
	ha_sync_segments_t *segments;

	/**
	 * FIFO reader thread
	 */
	callback_job_t *job;
};

/**
 * FIFO dispatching function
 */
static job_requeue_t dispatch_fifo(private_ha_sync_ctl_t *this)
{
	int fifo, old;
	char buf[8];
	u_int segment;

	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &old);
	fifo = open(HA_SYNC_FIFO, O_RDONLY);
	pthread_setcancelstate(old, NULL);
	if (fifo == -1)
	{
		DBG1(DBG_CFG, "opening HA sync fifo failed: %s", strerror(errno));
		sleep(1);
		return JOB_REQUEUE_FAIR;
	}

	memset(buf, 0, sizeof(buf));
	if (read(fifo, buf, sizeof(buf)-1) > 1)
	{
		segment = atoi(&buf[1]);
		if (segment)
		{
			switch (buf[0])
			{
				case '+':
					this->segments->activate(this->segments, segment, TRUE);
					break;
				case '-':
					this->segments->deactivate(this->segments, segment, TRUE);
					break;
				case '*':
					this->segments->resync(this->segments, segment);
					break;
				default:
					break;
			}
		}
	}
	close(fifo);

	return JOB_REQUEUE_DIRECT;
}

/**
 * Implementation of ha_sync_ctl_t.destroy.
 */
static void destroy(private_ha_sync_ctl_t *this)
{
	this->job->cancel(this->job);
	free(this);
}

/**
 * See header
 */
ha_sync_ctl_t *ha_sync_ctl_create(ha_sync_segments_t *segments)
{
	private_ha_sync_ctl_t *this = malloc_thing(private_ha_sync_ctl_t);

	this->public.destroy = (void(*)(ha_sync_ctl_t*))destroy;

	if (access(HA_SYNC_FIFO, R_OK|W_OK) != 0)
	{
		if (mkfifo(HA_SYNC_FIFO, 600) != 0)
		{
			DBG1(DBG_CFG, "creating HA sync FIFO %s failed: %s",
				 HA_SYNC_FIFO, strerror(errno));
		}
	}

	this->segments = segments;
	this->job = callback_job_create((callback_job_cb_t)dispatch_fifo,
									this, NULL, NULL);
	charon->processor->queue_job(charon->processor, (job_t*)this->job);
	return &this->public;
}

