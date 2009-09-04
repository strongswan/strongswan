/*
 * Copyright (C) 2007 Martin Willi
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

#include "dispatcher.h"

#include "request.h"
#include "session.h"

#include <fcgiapp.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>

#include <debug.h>
#include <utils/linked_list.h>

typedef struct private_dispatcher_t private_dispatcher_t;

/**
 * private data of the task manager
 */
struct private_dispatcher_t {

	/**
	 * public functions
	 */
	dispatcher_t public;

	/**
	 * fcgi socket fd
	 */
	int fd;

	/**
	 * thread list
	 */
	pthread_t *threads;

	/**
	 * number of threads in "threads"
	 */
	int thread_count;

	/**
	 * session locking mutex
	 */
	pthread_mutex_t mutex;

	/**
	 * List of sessions
	 */
	linked_list_t *sessions;

	/**
	 * session timeout
	 */
	time_t timeout;

	/**
	 * running in debug mode?
	 */
	bool debug;

	/**
	 * List of controllers controller_constructor_t
	 */
	linked_list_t *controllers;

	/**
	 * List of filters filter_constructor_t
	 */
	linked_list_t *filters;

	/**
	 * constructor function to create session context (in controller_entry_t)
	 */
	context_constructor_t context_constructor;

	/**
	 * user param to context constructor
	 */
	void *param;
};

typedef struct {
	/** constructor function */
	controller_constructor_t constructor;
	/** parameter to constructor */
	void *param;
} controller_entry_t;

typedef struct {
	/** constructor function */
	filter_constructor_t constructor;
	/** parameter to constructor */
	void *param;
} filter_entry_t;

typedef struct {
	/** session instance */
	session_t *session;
	/** condvar to wait for session */
	pthread_cond_t cond;
	/** client host address, to prevent session hijacking */
	char *host;
	/** TRUE if session is in use */
	bool in_use;
	/** last use of the session */
	time_t used;
	/** has the session been closed by the handler? */
	bool closed;
} session_entry_t;

/**
 * create a session and instanciate controllers
 */
static session_t* load_session(private_dispatcher_t *this)
{
	iterator_t *iterator;
	controller_entry_t *centry;
	filter_entry_t *fentry;
	session_t *session;
	context_t *context = NULL;
	controller_t *controller;
	filter_t *filter;

	if (this->context_constructor)
	{
		context = this->context_constructor(this->param);
	}
	session = session_create(context);

	iterator = this->controllers->create_iterator(this->controllers, TRUE);
	while (iterator->iterate(iterator, (void**)&centry))
	{
		controller = centry->constructor(context, centry->param);
		session->add_controller(session, controller);
	}
	iterator->destroy(iterator);

	iterator = this->filters->create_iterator(this->filters, TRUE);
	while (iterator->iterate(iterator, (void**)&fentry))
	{
		filter = fentry->constructor(context, fentry->param);
		session->add_filter(session, filter);
	}
	iterator->destroy(iterator);

	return session;
}

/**
 * create a new session entry
 */
static session_entry_t *session_entry_create(private_dispatcher_t *this,
											 char *host)
{
	session_entry_t *entry;

	entry = malloc_thing(session_entry_t);
	entry->in_use = FALSE;
	entry->closed = FALSE;
	pthread_cond_init(&entry->cond, NULL);
	entry->session = load_session(this);
	entry->used = time_monotonic(NULL);
	entry->host = strdup(host);

	return entry;
}

static void session_entry_destroy(session_entry_t *entry)
{
	entry->session->destroy(entry->session);
	free(entry->host);
	free(entry);
}

/**
 * Implementation of dispatcher_t.add_controller.
 */
static void add_controller(private_dispatcher_t *this,
						   controller_constructor_t constructor, void *param)
{
	controller_entry_t *entry = malloc_thing(controller_entry_t);

	entry->constructor = constructor;
	entry->param = param;
	this->controllers->insert_last(this->controllers, entry);
}

/**
 * Implementation of dispatcher_t.add_filter.
 */
static void add_filter(private_dispatcher_t *this,
					   filter_constructor_t constructor, void *param)
{
	filter_entry_t *entry = malloc_thing(filter_entry_t);

	entry->constructor = constructor;
	entry->param = param;
	this->filters->insert_last(this->filters, entry);
}

/**
 * Actual dispatching code
 */
static void dispatch(private_dispatcher_t *this)
{
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);

	while (TRUE)
	{
		request_t *request;
		session_entry_t *current, *found = NULL;
		iterator_t *iterator;
		time_t now;
		char *sid;

		pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
		request = request_create(this->fd, this->debug);
		pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);

		if (request == NULL)
		{
			continue;
		}
		sid = request->get_cookie(request, "SID");
		now = time_monotonic(NULL);

		/* find session */
		pthread_mutex_lock(&this->mutex);
		iterator = this->sessions->create_iterator(this->sessions, TRUE);
		while (iterator->iterate(iterator, (void**)&current))
		{
			/* check all sessions for timeout or close flag
			 * TODO: use a seperate cleanup thread */
			if (!current->in_use &&
				(current->used < now - this->timeout || current->closed))
			{
				iterator->remove(iterator);
				session_entry_destroy(current);
				continue;
			}
			/* find by session ID. Prevent session hijacking by host check */
			if (!found && sid &&
				streq(current->session->get_sid(current->session), sid) &&
				streq(current->host, request->get_host(request)))
			{
				found = current;
			}
		}
		iterator->destroy(iterator);

		if (found)
		{
			/* wait until session is unused */
			while (found->in_use)
			{
				pthread_cond_wait(&found->cond, &this->mutex);
			}
		}
		else
		{	/* create a new session if not found */
			found = session_entry_create(this, request->get_host(request));
			this->sessions->insert_first(this->sessions, found);
		}
		found->in_use = TRUE;
		pthread_mutex_unlock(&this->mutex);

		/* start processing */
		found->session->process(found->session, request);
		found->used = time_monotonic(NULL);

		/* release session */
		pthread_mutex_lock(&this->mutex);
		found->in_use = FALSE;
		found->closed = request->session_closed(request);
		pthread_cond_signal(&found->cond);
		pthread_mutex_unlock(&this->mutex);

		/* cleanup */
		request->destroy(request);
	}
}

/**
 * Implementation of dispatcher_t.run.
 */
static void run(private_dispatcher_t *this, int threads)
{
	this->thread_count = threads;
	this->threads = malloc(sizeof(pthread_t) * threads);
	while (threads)
	{
		if (pthread_create(&this->threads[threads - 1],
						   NULL, (void*)dispatch, this) == 0)
		{
			threads--;
		}
	}
}

/**
 * Implementation of dispatcher_t.waitsignal.
 */
static void waitsignal(private_dispatcher_t *this)
{
	sigset_t set;
	int sig;

	sigemptyset(&set);
	sigaddset(&set, SIGINT);
	sigaddset(&set, SIGTERM);
	sigaddset(&set, SIGHUP);
	sigprocmask(SIG_BLOCK, &set, NULL);
	sigwait(&set, &sig);
}

/**
 * Implementation of dispatcher_t.destroy
 */
static void destroy(private_dispatcher_t *this)
{
	FCGX_ShutdownPending();
	while (this->thread_count--)
	{
		pthread_cancel(this->threads[this->thread_count]);
		pthread_join(this->threads[this->thread_count], NULL);
	}
	this->sessions->destroy_function(this->sessions, (void*)session_entry_destroy);
	this->controllers->destroy_function(this->controllers, free);
	this->filters->destroy_function(this->filters, free);
	free(this->threads);
	free(this);
}

/*
 * see header file
 */
dispatcher_t *dispatcher_create(char *socket, bool debug, int timeout,
								context_constructor_t constructor, void *param)
{
	private_dispatcher_t *this = malloc_thing(private_dispatcher_t);

	this->public.add_controller = (void(*)(dispatcher_t*, controller_constructor_t, void*))add_controller;
	this->public.add_filter = (void(*)(dispatcher_t*,filter_constructor_t constructor, void *param))add_filter;
	this->public.run = (void(*)(dispatcher_t*, int threads))run;
	this->public.waitsignal = (void(*)(dispatcher_t*))waitsignal;
	this->public.destroy = (void(*)(dispatcher_t*))destroy;

	this->sessions = linked_list_create();
	this->controllers = linked_list_create();
	this->filters = linked_list_create();
	this->context_constructor = constructor;
	pthread_mutex_init(&this->mutex, NULL);
	this->param = param;
	this->fd = 0;
	this->timeout = timeout;
	this->debug = debug;
	this->threads = NULL;

	FCGX_Init();

	if (socket)
	{
		unlink(socket);
		this->fd = FCGX_OpenSocket(socket, 10);
	}
	return &this->public;
}

