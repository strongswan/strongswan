/*
 * Copyright (C) 2009 Tobias Brunner
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

#define _GNU_SOURCE
#include <pthread.h>
#include <signal.h>
#include <semaphore.h>

#include <library.h>
#include <debug.h>

#include <threading/thread_value.h>
#include <threading/mutex.h>
#include <utils/linked_list.h>

#include "thread.h"

typedef struct private_thread_t private_thread_t;

struct private_thread_t {
	/**
	 * Public interface.
	 */
	thread_t public;

	/**
	 * Human-readable ID of this thread.
	 */
	u_int id;

	/**
	 * ID of the underlying thread.
	 */
	pthread_t thread_id;

	/**
	 * Main function of this thread (NULL for the main thread).
	 */
	thread_main_t main;

	/**
	 * Argument for the main function.
	 */
	void *arg;

	/**
	 * Stack of cleanup handlers.
	 */
	linked_list_t *cleanup_handlers;

	/**
	 * Mutex to make modifying thread properties safe.
	 */
	mutex_t *mutex;

	/**
	 * Semaphore used to sync the creation/start of the thread.
	 */
	sem_t created;

	/**
	 * TRUE if this thread has been detached or joined, i.e. can be cleaned
	 * up after terminating.
	 */
	bool detached_or_joined;

	/**
	 * TRUE if the threads has terminated (cancelled, via thread_exit or
	 * returned from the main function)
	 */
	bool terminated;

};

typedef struct {
	/**
	 * Cleanup callback function.
	 */
	thread_cleanup_t cleanup;

	/**
	 * Argument provided to the cleanup function.
	 */
	void *arg;

} cleanup_handler_t;


/**
 * Next thread ID.
 */
static u_int next_id = 1;

/**
 * Mutex to safely access the next thread ID.
 */
static mutex_t *id_mutex;

/**
 * Store the thread object in a thread-specific value.
 */
static thread_value_t *current_thread;

#ifndef HAVE_PTHREAD_CANCEL
/* if pthread_cancel is not available, we emulate it using a signal */
#define SIG_CANCEL (SIGRTMIN+7)

/* the signal handler for SIG_CANCEL uses pthread_exit to terminate the
 * "cancelled" thread */
static void cancel_signal_handler(int sig)
{
	pthread_exit(NULL);
}
#endif


/**
 * Destroy an internal thread object.
 *
 * @note The mutex of this thread object has to be locked, it gets unlocked
 * automatically.
 */
static void thread_destroy(private_thread_t *this)
{
	if (!this->terminated || !this->detached_or_joined)
	{
		this->mutex->unlock(this->mutex);
		return;
	}
	this->cleanup_handlers->destroy(this->cleanup_handlers);
	this->mutex->unlock(this->mutex);
	this->mutex->destroy(this->mutex);
	sem_destroy(&this->created);
	free(this);
}

/**
 * Implementation of thread_t.cancel.
 */
static void cancel(private_thread_t *this)
{
	this->mutex->lock(this->mutex);
	if (pthread_equal(this->thread_id, pthread_self()))
	{
		this->mutex->unlock(this->mutex);
		DBG1("!!! CANNOT CANCEL CURRENT THREAD !!!");
		return;
	}
#ifdef HAVE_PTHREAD_CANCEL
	pthread_cancel(this->thread_id);
#else
	pthread_kill(this->thread_id, SIG_CANCEL);
#endif /* HAVE_PTHREAD_CANCEL */
	this->mutex->unlock(this->mutex);
}

/**
 * Implementation of thread_t.kill.
 */
static void _kill(private_thread_t *this, int sig)
{
	this->mutex->lock(this->mutex);
	if (pthread_equal(this->thread_id, pthread_self()))
	{
		/* it might actually be possible to send a signal to pthread_self (there
		 * is an example in raise(3) describing that), the problem is though,
		 * that the thread only returns here after the signal handler has
		 * returned, so depending on the signal, the lock might not get
		 * unlocked. */
		this->mutex->unlock(this->mutex);
		DBG1("!!! CANNOT SEND SIGNAL TO CURRENT THREAD !!!");
		return;
	}
	pthread_kill(this->thread_id, sig);
	this->mutex->unlock(this->mutex);
}

/**
 * Implementation of thread_t.detach.
 */
static void detach(private_thread_t *this)
{
	this->mutex->lock(this->mutex);
	pthread_detach(this->thread_id);
	this->detached_or_joined = TRUE;
	thread_destroy(this);
}

/**
 * Implementation of thread_t.join.
 */
static void *join(private_thread_t *this)
{
	pthread_t thread_id;
	void *val;
	this->mutex->lock(this->mutex);
	if (pthread_equal(this->thread_id, pthread_self()))
	{
		this->mutex->unlock(this->mutex);
		DBG1("!!! CANNOT JOIN CURRENT THREAD !!!");
		return NULL;
	}
	if (this->detached_or_joined)
	{
		this->mutex->unlock(this->mutex);
		DBG1("!!! CANNOT JOIN DETACHED THREAD !!!");
		return NULL;
	}
	thread_id = this->thread_id;
	this->detached_or_joined = TRUE;
	if (this->terminated)
	{
		/* thread has terminated before the call to join */
		thread_destroy(this);
	}
	else
	{
		/* thread_destroy is called when the thread terminates normally */
		this->mutex->unlock(this->mutex);
	}
	pthread_join(thread_id, &val);
	return val;
}

/**
 * Create an internal thread object.
 */
static private_thread_t *thread_create_internal()
{
	private_thread_t *this = malloc_thing(private_thread_t);
	this->public.cancel = (void(*)(thread_t*))cancel;
	this->public.kill = (void(*)(thread_t*,int))_kill;
	this->public.detach = (void(*)(thread_t*))detach;
	this->public.join = (void*(*)(thread_t*))join;

	this->id = 0;
	this->thread_id = 0;
	this->main = NULL;
	this->arg = NULL;
	this->cleanup_handlers = linked_list_create();
	this->mutex = mutex_create(MUTEX_TYPE_DEFAULT);
	sem_init(&this->created, FALSE, 0);
	this->detached_or_joined = FALSE;
	this->terminated = FALSE;

	return this;
}

/**
 * Main cleanup function for threads.
 */
static void thread_cleanup(private_thread_t *this)
{
	cleanup_handler_t *handler;
	this->mutex->lock(this->mutex);
	while (this->cleanup_handlers->remove_last(this->cleanup_handlers,
											   (void**)&handler) == SUCCESS)
	{
		handler->cleanup(handler->arg);
		free(handler);
	}
	this->terminated = TRUE;
	thread_destroy(this);
}

/**
 * Main function wrapper for threads.
 */
static void *thread_main(private_thread_t *this)
{
	void *res;
	sem_wait(&this->created);
	current_thread->set(current_thread, this);
	pthread_cleanup_push((thread_cleanup_t)thread_cleanup, this);
	res = this->main(this->arg);
	pthread_cleanup_pop(TRUE);
	return res;
}

/**
 * Described in header.
 */
thread_t *thread_create(thread_main_t main, void *arg)
{
	private_thread_t *this = thread_create_internal();
	this->main = main;
	this->arg = arg;
	if (pthread_create(&this->thread_id, NULL, (void*)thread_main, this) != 0)
	{
		DBG1("failed to create thread!");
		thread_destroy(this);
		return NULL;
	}
	id_mutex->lock(id_mutex);
	this->id = next_id++;
	id_mutex->unlock(id_mutex);
	sem_post(&this->created);
	return &this->public;
}

/**
 * Described in header.
 */
thread_t *thread_current()
{
	return current_thread->get(current_thread);
}

/**
 * Described in header.
 */
u_int thread_current_id()
{
	private_thread_t *this = (private_thread_t*)thread_current();
	return this->id;
}

/**
 * Described in header.
 */
void thread_cleanup_push(thread_cleanup_t cleanup, void *arg)
{
	private_thread_t *this = (private_thread_t*)thread_current();
	cleanup_handler_t *handler;
	this->mutex->lock(this->mutex);
	handler = malloc_thing(cleanup_handler_t);
	handler->cleanup = cleanup;
	handler->arg = arg;
	this->cleanup_handlers->insert_last(this->cleanup_handlers, handler);
	this->mutex->unlock(this->mutex);
}

/**
 * Described in header.
 */
void thread_cleanup_pop(bool execute)
{
	private_thread_t *this = (private_thread_t*)thread_current();
	cleanup_handler_t *handler;
	this->mutex->lock(this->mutex);
	if (this->cleanup_handlers->remove_last(this->cleanup_handlers,
											(void**)&handler) != SUCCESS)
	{
		this->mutex->unlock(this->mutex);
		DBG1("!!! THREAD CLEANUP ERROR !!!");
		return;
	}
	this->mutex->unlock(this->mutex);

	if (execute)
	{
		handler->cleanup(handler->arg);
	}
	free(handler);
}

/**
 * Described in header.
 */
bool thread_cancelability(bool enable)
{
#ifdef HAVE_PTHREAD_CANCEL
	int old;
	pthread_setcancelstate(enable ? PTHREAD_CANCEL_ENABLE
								  : PTHREAD_CANCEL_DISABLE, &old);
	return old == PTHREAD_CANCEL_ENABLE;
#else
	sigset_t new, old;
	sigemptyset(&new);
	sigaddset(&new, SIG_CANCEL);
	pthread_sigmask(enable ? SIG_UNBLOCK : SIG_BLOCK, &new, &old);
	return sigismember(&old, SIG_CANCEL) == 0;
#endif /* HAVE_PTHREAD_CANCEL */
}

/**
 * Described in header.
 */
void thread_cancellation_point()
{
	bool old = thread_cancelability(TRUE);
#ifdef HAVE_PTHREAD_CANCEL
	pthread_testcancel();
#endif /* HAVE_PTHREAD_CANCEL */
	thread_cancelability(old);
}

/**
 * Described in header.
 */
void thread_exit(void *val)
{
	pthread_exit(val);
}

/**
 * Described in header.
 */
void threads_init()
{
	private_thread_t *main_thread = thread_create_internal();
	main_thread->id = 0;
	main_thread->thread_id = pthread_self();
	current_thread = thread_value_create(NULL);
	current_thread->set(current_thread, (void*)main_thread);
	id_mutex = mutex_create(MUTEX_TYPE_DEFAULT);

#ifndef HAVE_PTHREAD_CANCEL
	{	/* install a signal handler for our custom SIG_CANCEL */
		struct sigaction action = {
			.sa_handler = cancel_signal_handler
		};
		sigaction(SIG_CANCEL, &action, NULL);
	}
#endif /* HAVE_PTHREAD_CANCEL */
}

/**
 * Described in header.
 */
void threads_deinit()
{
	private_thread_t *main_thread = (private_thread_t*)thread_current();
	thread_destroy(main_thread);
	current_thread->destroy(current_thread);
	id_mutex->destroy(id_mutex);
}

