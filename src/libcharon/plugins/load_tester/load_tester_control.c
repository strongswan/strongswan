/*
 * Copyright (C) 2012 Martin Willi
 * Copyright (C) 2012 revosec AG
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

#include "load_tester_control.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>

#include <daemon.h>
#include <collections/hashtable.h>
#include <threading/thread.h>
#include <threading/mutex.h>
#include <threading/condvar.h>
#include <processing/jobs/callback_job.h>

typedef struct private_load_tester_control_t private_load_tester_control_t;
typedef struct init_listener_t init_listener_t;

/**
 * Private data of an load_tester_control_t object.
 */
struct private_load_tester_control_t {

	/**
	 * Public load_tester_control_t interface.
	 */
	load_tester_control_t public;

	/**
	 * Load tester unix socket file descriptor
	 */
	int socket;
};

/**
 * Listener to follow initiation progress
 */
struct init_listener_t {

	/**
	 * implements listener_t
	 */
	listener_t listener;

	/**
	 * Output stream to log to
	 */
	FILE *stream;

	/**
	 * IKE_SAs we have started to initiate
	 */
	hashtable_t *initiated;

	/**
	 * IKE_SAs we have completed to initate (success or failure)
	 */
	hashtable_t *completed;

	/**
	 * Mutex to lock IKE_SA tables
	 */
	mutex_t *mutex;

	/**
	 * Condvar to wait for completion
	 */
	condvar_t *condvar;
};

/**
 * Open load-tester listening socket
 */
static bool open_socket(private_load_tester_control_t *this)
{
	struct sockaddr_un addr;
	mode_t old;

	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, LOAD_TESTER_SOCKET);

	this->socket = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (this->socket == -1)
	{
		DBG1(DBG_CFG, "creating load-tester socket failed");
		return FALSE;
	}
	unlink(addr.sun_path);
	old = umask(~(S_IRWXU | S_IRWXG));
	if (bind(this->socket, (struct sockaddr*)&addr, sizeof(addr)) < 0)
	{
		DBG1(DBG_CFG, "binding load-tester socket failed: %s", strerror(errno));
		close(this->socket);
		return FALSE;
	}
	umask(old);
	if (chown(addr.sun_path, charon->caps->get_uid(charon->caps),
			  charon->caps->get_gid(charon->caps)) != 0)
	{
		DBG1(DBG_CFG, "changing load-tester socket permissions failed: %s",
			 strerror(errno));
	}
	if (listen(this->socket, 10) < 0)
	{
		DBG1(DBG_CFG, "listening on load-tester socket failed: %s", strerror(errno));
		close(this->socket);
		unlink(addr.sun_path);
		return FALSE;
	}
	return TRUE;
}

/**
 * Hashtable hash function
 */
static u_int hash(uintptr_t id)
{
	return id;
}

/**
 * Hashtable hash function
 */
static bool equals(uintptr_t a, uintptr_t b)
{
	return a == b;
}

METHOD(listener_t, alert, bool,
	init_listener_t *this, ike_sa_t *ike_sa, alert_t alert, va_list args)
{
	if (alert == ALERT_RETRANSMIT_SEND)
	{
		uintptr_t id;
		bool match = FALSE;

		id = ike_sa->get_unique_id(ike_sa);
		this->mutex->lock(this->mutex);
		if (this->initiated->get(this->initiated, (void*)id))
		{
			match = TRUE;
		}
		this->mutex->unlock(this->mutex);

		if (match)
		{
			fprintf(this->stream, "*");
			fflush(this->stream);
		}
	}
	return TRUE;
}

METHOD(listener_t, ike_state_change, bool,
	init_listener_t *this, ike_sa_t *ike_sa, ike_sa_state_t state)
{
	if (state == IKE_ESTABLISHED || state == IKE_DESTROYING)
	{
		uintptr_t id;
		bool match = FALSE;

		id = ike_sa->get_unique_id(ike_sa);
		this->mutex->lock(this->mutex);
		if (this->initiated->get(this->initiated, (void*)id))
		{
			match = !this->completed->put(this->completed, (void*)id, (void*)id);
		}
		this->mutex->unlock(this->mutex);

		if (match)
		{
			this->condvar->signal(this->condvar);
			fprintf(this->stream, state == IKE_ESTABLISHED ? "+" : "-");
			fflush(this->stream);
		}
	}
	return TRUE;
}

/**
 * Logging callback function used during initiate
 */
static bool initiate_cb(init_listener_t *this, debug_t group, level_t level,
						ike_sa_t *ike_sa, const char *message)
{
	uintptr_t id;

	if (ike_sa)
	{
		id = ike_sa->get_unique_id(ike_sa);
		this->mutex->lock(this->mutex);
		this->initiated->put(this->initiated, (void*)id, (void*)id);
		this->mutex->unlock(this->mutex);

		return FALSE;
	}

	return TRUE;
}

/**
 * Initiate load-test, write progress to stream
 */
static job_requeue_t initiate(FILE *stream)
{
	init_listener_t *listener;
	enumerator_t *enumerator;
	peer_cfg_t *peer_cfg;
	child_cfg_t *child_cfg;
	u_int i, count, failed = 0, delay = 0;
	char buf[16] = "";

	fflush(stream);
	if (fgets(buf, sizeof(buf), stream) == NULL)
	{
		return JOB_REQUEUE_NONE;
	}
	if (sscanf(buf, "%u %u", &count, &delay) < 1)
	{
		return JOB_REQUEUE_NONE;
	}

	INIT(listener,
		.listener = {
			.ike_state_change = _ike_state_change,
			.alert = _alert,
		},
		.stream = stream,
		.initiated = hashtable_create((void*)hash, (void*)equals, count),
		.completed = hashtable_create((void*)hash, (void*)equals, count),
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
		.condvar = condvar_create(CONDVAR_TYPE_DEFAULT),
	);

	charon->bus->add_listener(charon->bus, &listener->listener);

	for (i = 0; i < count; i++)
	{
		peer_cfg = charon->backends->get_peer_cfg_by_name(charon->backends,
														  "load-test");
		if (!peer_cfg)
		{
			failed++;
			fprintf(stream, "!");
			continue;
		}
		enumerator = peer_cfg->create_child_cfg_enumerator(peer_cfg);
		if (!enumerator->enumerate(enumerator, &child_cfg))
		{
			enumerator->destroy(enumerator);
			peer_cfg->destroy(peer_cfg);
			failed++;
			fprintf(stream, "!");
			continue;
		}
		enumerator->destroy(enumerator);

		switch (charon->controller->initiate(charon->controller,
										peer_cfg, child_cfg->get_ref(child_cfg),
										(void*)initiate_cb, listener, 0))
		{
			case NEED_MORE:
				/* Callback returns FALSE once it got track of this IKE_SA.
				 * FALL */
			case SUCCESS:
				fprintf(stream, ".");
				break;
			default:
				fprintf(stream, "!");
				break;
		}
		if (delay)
		{
			usleep(delay * 1000);
		}
		fflush(stream);
	}

	listener->mutex->lock(listener->mutex);
	while (listener->completed->get_count(listener->completed) < count - failed)
	{
		listener->condvar->wait(listener->condvar, listener->mutex);
	}
	listener->mutex->unlock(listener->mutex);

	charon->bus->remove_listener(charon->bus, &listener->listener);

	listener->initiated->destroy(listener->initiated);
	listener->completed->destroy(listener->completed);
	listener->mutex->destroy(listener->mutex);
	listener->condvar->destroy(listener->condvar);
	free(listener);

	fprintf(stream, "\n");

	return JOB_REQUEUE_NONE;
}

/**
 * Accept load-tester control connections, dispatch
 */
static job_requeue_t receive(private_load_tester_control_t *this)
{
	struct sockaddr_un addr;
	int fd, len = sizeof(addr);
	bool oldstate;
	FILE *stream;

	oldstate = thread_cancelability(TRUE);
	fd = accept(this->socket, (struct sockaddr*)&addr, &len);
	thread_cancelability(oldstate);

	if (fd != -1)
	{
		stream = fdopen(fd, "r+");
		if (stream)
		{
			DBG1(DBG_CFG, "client connected");
			lib->processor->queue_job(lib->processor,
				(job_t*)callback_job_create_with_prio(
					(callback_job_cb_t)initiate, stream, (void*)fclose,
					(callback_job_cancel_t)return_false, JOB_PRIO_CRITICAL));
		}
		else
		{
			close(fd);
		}
	}
	return JOB_REQUEUE_FAIR;
}

METHOD(load_tester_control_t, destroy, void,
	private_load_tester_control_t *this)
{
	if (this->socket != -1)
	{
		close(this->socket);
	}
	free(this);
}

/**
 * See header
 */
load_tester_control_t *load_tester_control_create()
{
	private_load_tester_control_t *this;

	INIT(this,
		.public = {
			.destroy = _destroy,
		},
	);

	if (open_socket(this))
	{
		lib->processor->queue_job(lib->processor, (job_t*)
			callback_job_create_with_prio((callback_job_cb_t)receive, this, NULL,
						(callback_job_cancel_t)return_false, JOB_PRIO_CRITICAL));
	}
	else
	{
		this->socket = -1;
	}

	return &this->public;
}
