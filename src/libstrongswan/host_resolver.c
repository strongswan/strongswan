/*
 * Copyright (C) 2012 Tobias Brunner
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

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "host_resolver.h"

#include <debug.h>
#include <processing/jobs/callback_job.h>
#include <threading/condvar.h>
#include <threading/mutex.h>
#include <threading/thread.h>
#include <utils/hashtable.h>
#include <utils/linked_list.h>

typedef struct private_host_resolver_t private_host_resolver_t;

/**
 * Private data of host_resolver_t
 */
struct private_host_resolver_t {

	/**
	 * Public interface
	 */
	host_resolver_t public;

	/**
	 * Hashtable to check for queued queries, query_t*
	 */
	hashtable_t *queries;

	/**
	 * Queue for queries, query_t*
	 */
	linked_list_t *queue;

	/**
	 * Mutex to safely access private data
	 */
	mutex_t *mutex;

	/**
	 * Condvar to signal arrival of new queries
	 */
	condvar_t *new_query;

	/**
	 * Maximum number of resolver threads
	 */
	u_int max_threads;

	/**
	 * Current number of threads
	 */
	u_int threads;

	/**
	 * TRUE if no new queries are accepted
	 */
	bool disabled;

};

typedef struct {
	/** DNS name we are looking for */
	char *name;
	/** address family we request */
	int family;
	/** Condvar to signal completion of a query */
	condvar_t *done;
	/** refcount */
	refcount_t refcount;
	/** the result if successful */
	host_t *result;
} query_t;

/**
 * Destroy the given query_t object if refcount is zero
 */
static void query_destroy(query_t *this)
{
	if (ref_put(&this->refcount))
	{
		DESTROY_IF(this->result);
		this->done->destroy(this->done);
		free(this->name);
		free(this);
	}
}

/**
 * Signals all waiting threads and destroys the query
 */
static void query_signal_and_destroy(query_t *this)
{
	this->done->broadcast(this->done);
	query_destroy(this);
}

/**
 * Hash a queued query
 */
static u_int query_hash(query_t *this)
{
	return chunk_hash_inc(chunk_create(this->name, strlen(this->name)),
						  chunk_hash(chunk_from_thing(this->family)));
}

/**
 * Compare two queued queries
 */
static bool query_equals(query_t *this, query_t *other)
{
	return this->family == other->family && streq(this->name, other->name);
}

/**
 * Main function of resolver threads
 */
static job_requeue_t resolve_hosts(private_host_resolver_t *this)
{
	struct addrinfo hints, *result;
	query_t *query;
	int error;
	bool old;

	this->mutex->lock(this->mutex);
	while (this->queue->remove_first(this->queue, (void**)&query) != SUCCESS)
	{
		thread_cleanup_push((thread_cleanup_t)this->mutex->unlock, this->mutex);
		old = thread_cancelability(TRUE);
		this->new_query->wait(this->new_query, this->mutex);
		thread_cancelability(old);
		thread_cleanup_pop(FALSE);
	}
	this->mutex->unlock(this->mutex);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = query->family;

	thread_cleanup_push((thread_cleanup_t)query_signal_and_destroy, query);
	old = thread_cancelability(TRUE);
	error = getaddrinfo(query->name, NULL, &hints, &result);
	thread_cancelability(old);
	thread_cleanup_pop(FALSE);

	this->mutex->lock(this->mutex);
	if (error != 0)
	{
		DBG1(DBG_LIB, "resolving '%s' failed: %s", query->name,
			 gai_strerror(error));
	}
	else
	{	/* result is a linked list, but we use only the first address */
		query->result = host_create_from_sockaddr(result->ai_addr);
		freeaddrinfo(result);
	}
	this->queries->remove(this->queries, query);
	query->done->broadcast(query->done);
	this->mutex->unlock(this->mutex);
	query_destroy(query);
	return JOB_REQUEUE_DIRECT;
}

METHOD(host_resolver_t, resolve, host_t*,
	private_host_resolver_t *this, char *name, int family)
{
	query_t *query, lookup = {
		.name = name,
		.family = family,
	};
	host_t *result;

	if (streq(name, "%any") || streq(name, "0.0.0.0"))
	{
		return host_create_any(family ? family : AF_INET);
	}
	if (streq(name, "%any6") || streq(name, "::"))
	{
		return host_create_any(family ? family : AF_INET6);
	}
	if (family == AF_INET && strchr(name, ':'))
	{	/* do not try to convert v6 addresses for v4 family */
		return NULL;
	}
	this->mutex->lock(this->mutex);
	if (this->disabled)
	{
		this->mutex->unlock(this->mutex);
		return NULL;
	}
	query = this->queries->get(this->queries, &lookup);
	if (!query)
	{
		INIT(query,
			.name = strdup(name),
			.family = family,
			.done = condvar_create(CONDVAR_TYPE_DEFAULT),
			.refcount = 1,
		);
		this->queries->put(this->queries, query, query);
		this->queue->insert_last(this->queue, query);
		this->new_query->signal(this->new_query);
	}
	ref_get(&query->refcount);
	if (this->threads < this->max_threads)
	{
		this->threads++;
		lib->processor->queue_job(lib->processor,
			(job_t*)callback_job_create_with_prio(
				(callback_job_cb_t)resolve_hosts, this,	NULL,
				(callback_job_cancel_t)return_false, JOB_PRIO_CRITICAL));
	}
	query->done->wait(query->done, this->mutex);
	this->mutex->unlock(this->mutex);

	result = query->result ? query->result->clone(query->result) : NULL;
	query_destroy(query);
	return result;
}

METHOD(host_resolver_t, flush, void,
	private_host_resolver_t *this)
{
	enumerator_t *enumerator;
	query_t *query;

	this->mutex->lock(this->mutex);
	enumerator = this->queries->create_enumerator(this->queries);
	while (enumerator->enumerate(enumerator, &query, NULL))
	{	/* use the hashtable here as we also want to signal dequeued queries */
		this->queries->remove_at(this->queries, enumerator);
		query->done->broadcast(query->done);
	}
	enumerator->destroy(enumerator);
	this->queue->destroy_function(this->queue, (void*)query_destroy);
	this->queue = linked_list_create();
	this->disabled = TRUE;
	this->mutex->unlock(this->mutex);
}

METHOD(host_resolver_t, destroy, void,
	private_host_resolver_t *this)
{
	this->queue->destroy_function(this->queue, (void*)query_signal_and_destroy);
	this->queries->destroy(this->queries);
	this->new_query->destroy(this->new_query);
	this->mutex->destroy(this->mutex);
	free(this);
}

/*
 * Described in header
 */
host_resolver_t *host_resolver_create(u_int max_threads)
{
	private_host_resolver_t *this;

	INIT(this,
		.public = {
			.resolve = _resolve,
			.flush = _flush,
			.destroy = _destroy,
		},
		.queries = hashtable_create((hashtable_hash_t)query_hash,
									(hashtable_equals_t)query_equals, 8),
		.queue = linked_list_create(),
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
		.new_query = condvar_create(CONDVAR_TYPE_DEFAULT),
		.max_threads = max_threads,
	);

	return &this->public;
}
