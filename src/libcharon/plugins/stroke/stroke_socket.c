/*
 * Copyright (C) 2011-2012 Tobias Brunner
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

#include "stroke_socket.h"

#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>

#include <hydra.h>
#include <daemon.h>
#include <threading/mutex.h>
#include <threading/thread.h>
#include <threading/condvar.h>
#include <utils/linked_list.h>
#include <processing/jobs/callback_job.h>

#include "stroke_config.h"
#include "stroke_control.h"
#include "stroke_cred.h"
#include "stroke_ca.h"
#include "stroke_attribute.h"
#include "stroke_list.h"

/**
 * To avoid clogging the thread pool with (blocking) jobs, we limit the number
 * of concurrently handled stroke commands.
 */
#define MAX_CONCURRENT_DEFAULT 4

typedef struct stroke_job_context_t stroke_job_context_t;
typedef struct private_stroke_socket_t private_stroke_socket_t;

/**
 * private data of stroke_socket
 */
struct private_stroke_socket_t {

	/**
	 * public functions
	 */
	stroke_socket_t public;

	/**
	 * Unix socket to listen for strokes
	 */
	int socket;

	/**
	 * job accepting stroke messages
	 */
	callback_job_t *receiver;

	/**
	 * job handling stroke messages
	 */
	callback_job_t *handler;

	/**
	 * queued stroke commands
	 */
	linked_list_t *commands;

	/**
	 * lock for command list
	 */
	mutex_t *mutex;

	/**
	 * condvar to signal the arrival or completion of commands
	 */
	condvar_t *condvar;

	/**
	 * the number of currently handled commands
	 */
	u_int handling;

	/**
	 * the maximum number of concurrently handled commands
	 */
	u_int max_concurrent;

	/**
	 * configuration backend
	 */
	stroke_config_t *config;

	/**
	 * attribute provider
	 */
	stroke_attribute_t *attribute;

	/**
	 * controller to control daemon
	 */
	stroke_control_t *control;

	/**
	 * credential set
	 */
	stroke_cred_t *cred;

	/**
	 * CA sections
	 */
	stroke_ca_t *ca;

	/**
	 * status information logging
	 */
	stroke_list_t *list;
};

/**
 * job context to pass to processing thread
 */
struct stroke_job_context_t {

	/**
	 * file descriptor to read from
	 */
	int fd;

	/**
	 * global stroke interface
	 */
	private_stroke_socket_t *this;
};

/**
 * Helper function which corrects the string pointers
 * in a stroke_msg_t. Strings in a stroke_msg sent over "wire"
 * contains RELATIVE addresses (relative to the beginning of the
 * stroke_msg). They must be corrected if they reach our address
 * space...
 */
static void pop_string(stroke_msg_t *msg, char **string)
{
	if (*string == NULL)
	{
		return;
	}

	/* check for sanity of string pointer and string */
	if (string < (char**)msg ||
		string > (char**)((char*)msg + sizeof(stroke_msg_t)) ||
		(unsigned long)*string < (unsigned long)((char*)msg->buffer - (char*)msg) ||
		(unsigned long)*string > msg->length)
	{
		*string = "(invalid pointer in stroke msg)";
	}
	else
	{
		*string = (char*)msg + (unsigned long)*string;
	}
}

/**
 * Pop the strings of a stroke_end_t struct and log them for debugging purposes
 */
static void pop_end(stroke_msg_t *msg, const char* label, stroke_end_t *end)
{
	pop_string(msg, &end->address);
	pop_string(msg, &end->subnets);
	pop_string(msg, &end->sourceip);
	pop_string(msg, &end->auth);
	pop_string(msg, &end->auth2);
	pop_string(msg, &end->id);
	pop_string(msg, &end->id2);
	pop_string(msg, &end->rsakey);
	pop_string(msg, &end->cert);
	pop_string(msg, &end->cert2);
	pop_string(msg, &end->ca);
	pop_string(msg, &end->ca2);
	pop_string(msg, &end->groups);
	pop_string(msg, &end->cert_policy);
	pop_string(msg, &end->updown);

	DBG2(DBG_CFG, "  %s=%s", label, end->address);
	DBG2(DBG_CFG, "  %ssubnet=%s", label, end->subnets);
	DBG2(DBG_CFG, "  %ssourceip=%s", label, end->sourceip);
	DBG2(DBG_CFG, "  %sauth=%s", label, end->auth);
	DBG2(DBG_CFG, "  %sauth2=%s", label, end->auth2);
	DBG2(DBG_CFG, "  %sid=%s", label, end->id);
	DBG2(DBG_CFG, "  %sid2=%s", label, end->id2);
	DBG2(DBG_CFG, "  %srsakey=%s", label, end->rsakey);
	DBG2(DBG_CFG, "  %scert=%s", label, end->cert);
	DBG2(DBG_CFG, "  %scert2=%s", label, end->cert2);
	DBG2(DBG_CFG, "  %sca=%s", label, end->ca);
	DBG2(DBG_CFG, "  %sca2=%s", label, end->ca2);
	DBG2(DBG_CFG, "  %sgroups=%s", label, end->groups);
	DBG2(DBG_CFG, "  %supdown=%s", label, end->updown);
}

/**
 * Add a connection to the configuration list
 */
static void stroke_add_conn(private_stroke_socket_t *this, stroke_msg_t *msg)
{
	pop_string(msg, &msg->add_conn.name);
	DBG1(DBG_CFG, "received stroke: add connection '%s'", msg->add_conn.name);

	DBG2(DBG_CFG, "conn %s", msg->add_conn.name);
	pop_end(msg, "left", &msg->add_conn.me);
	pop_end(msg, "right", &msg->add_conn.other);
	pop_string(msg, &msg->add_conn.eap_identity);
	pop_string(msg, &msg->add_conn.aaa_identity);
	pop_string(msg, &msg->add_conn.algorithms.ike);
	pop_string(msg, &msg->add_conn.algorithms.esp);
	pop_string(msg, &msg->add_conn.ikeme.mediated_by);
	pop_string(msg, &msg->add_conn.ikeme.peerid);
	DBG2(DBG_CFG, "  eap_identity=%s", msg->add_conn.eap_identity);
	DBG2(DBG_CFG, "  aaa_identity=%s", msg->add_conn.aaa_identity);
	DBG2(DBG_CFG, "  ike=%s", msg->add_conn.algorithms.ike);
	DBG2(DBG_CFG, "  esp=%s", msg->add_conn.algorithms.esp);
	DBG2(DBG_CFG, "  dpddelay=%d", msg->add_conn.dpd.delay);
	DBG2(DBG_CFG, "  dpdaction=%d", msg->add_conn.dpd.action);
	DBG2(DBG_CFG, "  closeaction=%d", msg->add_conn.close_action);
	DBG2(DBG_CFG, "  mediation=%s", msg->add_conn.ikeme.mediation ? "yes" : "no");
	DBG2(DBG_CFG, "  mediated_by=%s", msg->add_conn.ikeme.mediated_by);
	DBG2(DBG_CFG, "  me_peerid=%s", msg->add_conn.ikeme.peerid);

	this->config->add(this->config, msg);
	this->attribute->add_pool(this->attribute, msg);
}

/**
 * Delete a connection from the list
 */
static void stroke_del_conn(private_stroke_socket_t *this, stroke_msg_t *msg)
{
	pop_string(msg, &msg->del_conn.name);
	DBG1(DBG_CFG, "received stroke: delete connection '%s'", msg->del_conn.name);

	this->config->del(this->config, msg);
	this->attribute->del_pool(this->attribute, msg);
}

/**
 * initiate a connection by name
 */
static void stroke_initiate(private_stroke_socket_t *this, stroke_msg_t *msg, FILE *out)
{
	pop_string(msg, &msg->initiate.name);
	DBG1(DBG_CFG, "received stroke: initiate '%s'", msg->initiate.name);

	this->control->initiate(this->control, msg, out);
}

/**
 * terminate a connection by name
 */
static void stroke_terminate(private_stroke_socket_t *this, stroke_msg_t *msg, FILE *out)
{
	pop_string(msg, &msg->terminate.name);
	DBG1(DBG_CFG, "received stroke: terminate '%s'", msg->terminate.name);

	this->control->terminate(this->control, msg, out);
}

/**
 * terminate a connection by peers virtual IP
 */
static void stroke_terminate_srcip(private_stroke_socket_t *this,
								   stroke_msg_t *msg, FILE *out)
{
	pop_string(msg, &msg->terminate_srcip.start);
	pop_string(msg, &msg->terminate_srcip.end);
	DBG1(DBG_CFG, "received stroke: terminate-srcip %s-%s",
		 msg->terminate_srcip.start, msg->terminate_srcip.end);

	this->control->terminate_srcip(this->control, msg, out);
}

/**
 * rekey a connection by name/id
 */
static void stroke_rekey(private_stroke_socket_t *this, stroke_msg_t *msg, FILE *out)
{
	pop_string(msg, &msg->terminate.name);
	DBG1(DBG_CFG, "received stroke: rekey '%s'", msg->rekey.name);

	this->control->rekey(this->control, msg, out);
}

/**
 * route a policy (install SPD entries)
 */
static void stroke_route(private_stroke_socket_t *this, stroke_msg_t *msg, FILE *out)
{
	pop_string(msg, &msg->route.name);
	DBG1(DBG_CFG, "received stroke: route '%s'", msg->route.name);

	this->control->route(this->control, msg, out);
}

/**
 * unroute a policy
 */
static void stroke_unroute(private_stroke_socket_t *this, stroke_msg_t *msg, FILE *out)
{
	pop_string(msg, &msg->terminate.name);
	DBG1(DBG_CFG, "received stroke: unroute '%s'", msg->route.name);

	this->control->unroute(this->control, msg, out);
}

/**
 * Add a ca information record to the cainfo list
 */
static void stroke_add_ca(private_stroke_socket_t *this,
						  stroke_msg_t *msg, FILE *out)
{
	pop_string(msg, &msg->add_ca.name);
	DBG1(DBG_CFG, "received stroke: add ca '%s'", msg->add_ca.name);

	pop_string(msg, &msg->add_ca.cacert);
	pop_string(msg, &msg->add_ca.crluri);
	pop_string(msg, &msg->add_ca.crluri2);
	pop_string(msg, &msg->add_ca.ocspuri);
	pop_string(msg, &msg->add_ca.ocspuri2);
	pop_string(msg, &msg->add_ca.certuribase);
	DBG2(DBG_CFG, "ca %s",            msg->add_ca.name);
	DBG2(DBG_CFG, "  cacert=%s",      msg->add_ca.cacert);
	DBG2(DBG_CFG, "  crluri=%s",      msg->add_ca.crluri);
	DBG2(DBG_CFG, "  crluri2=%s",     msg->add_ca.crluri2);
	DBG2(DBG_CFG, "  ocspuri=%s",     msg->add_ca.ocspuri);
	DBG2(DBG_CFG, "  ocspuri2=%s",    msg->add_ca.ocspuri2);
	DBG2(DBG_CFG, "  certuribase=%s", msg->add_ca.certuribase);

	this->ca->add(this->ca, msg);
}

/**
 * Delete a ca information record from the cainfo list
 */
static void stroke_del_ca(private_stroke_socket_t *this,
						  stroke_msg_t *msg, FILE *out)
{
	pop_string(msg, &msg->del_ca.name);
	DBG1(DBG_CFG, "received stroke: delete ca '%s'", msg->del_ca.name);

	this->ca->del(this->ca, msg);
}


/**
 * show status of daemon
 */
static void stroke_status(private_stroke_socket_t *this,
						  stroke_msg_t *msg, FILE *out, bool all, bool wait)
{
	pop_string(msg, &(msg->status.name));

	this->list->status(this->list, msg, out, all, wait);
}

/**
 * list various information
 */
static void stroke_list(private_stroke_socket_t *this, stroke_msg_t *msg, FILE *out)
{
	if (msg->list.flags & LIST_CAINFOS)
	{
		this->ca->list(this->ca, msg, out);
	}
	this->list->list(this->list, msg, out);
}

/**
 * reread various information
 */
static void stroke_reread(private_stroke_socket_t *this,
						  stroke_msg_t *msg, FILE *out)
{
	this->cred->reread(this->cred, msg, out);
}

/**
 * purge various information
 */
static void stroke_purge(private_stroke_socket_t *this,
						 stroke_msg_t *msg, FILE *out)
{
	if (msg->purge.flags & PURGE_OCSP)
	{
		lib->credmgr->flush_cache(lib->credmgr, CERT_X509_OCSP_RESPONSE);
	}
	if (msg->purge.flags & PURGE_CRLS)
	{
		lib->credmgr->flush_cache(lib->credmgr, CERT_X509_CRL);
	}
	if (msg->purge.flags & PURGE_CERTS)
	{
		lib->credmgr->flush_cache(lib->credmgr, CERT_X509);
	}
	if (msg->purge.flags & PURGE_IKE)
	{
		this->control->purge_ike(this->control, msg, out);
	}
}

/**
 * Export in-memory credentials
 */
static void stroke_export(private_stroke_socket_t *this,
						  stroke_msg_t *msg, FILE *out)
{
	pop_string(msg, &msg->export.selector);

	if (msg->export.flags & EXPORT_X509)
	{
		enumerator_t *enumerator;
		identification_t *id;
		certificate_t *cert;
		chunk_t encoded;

		id = identification_create_from_string(msg->export.selector);
		enumerator = lib->credmgr->create_cert_enumerator(lib->credmgr,
												CERT_X509, KEY_ANY, id, FALSE);
		while (enumerator->enumerate(enumerator, &cert))
		{
			if (cert->get_encoding(cert, CERT_PEM, &encoded))
			{
				fprintf(out, "%.*s", (int)encoded.len, encoded.ptr);
				free(encoded.ptr);
			}
		}
		enumerator->destroy(enumerator);
		id->destroy(id);
	}
}

/**
 * list pool leases
 */
static void stroke_leases(private_stroke_socket_t *this,
						  stroke_msg_t *msg, FILE *out)
{
	pop_string(msg, &msg->leases.pool);
	pop_string(msg, &msg->leases.address);

	this->list->leases(this->list, msg, out);
}

/**
 * Show memory usage
 */
static void stroke_memusage(private_stroke_socket_t *this,
							stroke_msg_t *msg, FILE *out)
{
	if (lib->leak_detective)
	{
		lib->leak_detective->usage(lib->leak_detective, out);
	}
}

/**
 * Set username and password for a connection
 */
static void stroke_user_creds(private_stroke_socket_t *this,
							  stroke_msg_t *msg, FILE *out)
{
	pop_string(msg, &msg->user_creds.name);
	pop_string(msg, &msg->user_creds.username);
	pop_string(msg, &msg->user_creds.password);

	DBG1(DBG_CFG, "received stroke: user-creds '%s'", msg->user_creds.name);

	this->config->set_user_credentials(this->config, msg, out);
}

/**
 * set the verbosity debug output
 */
static void stroke_loglevel(private_stroke_socket_t *this,
							stroke_msg_t *msg, FILE *out)
{
	enumerator_t *enumerator;
	sys_logger_t *sys_logger;
	file_logger_t *file_logger;
	debug_t group;

	pop_string(msg, &(msg->loglevel.type));
	DBG1(DBG_CFG, "received stroke: loglevel %d for %s",
		 msg->loglevel.level, msg->loglevel.type);

	group = enum_from_name(debug_names, msg->loglevel.type);
	if ((int)group < 0)
	{
		fprintf(out, "invalid type (%s)!\n", msg->loglevel.type);
		return;
	}
	/* we set the loglevel on ALL sys- and file-loggers */
	enumerator = charon->sys_loggers->create_enumerator(charon->sys_loggers);
	while (enumerator->enumerate(enumerator, &sys_logger))
	{
		sys_logger->set_level(sys_logger, group, msg->loglevel.level);
	}
	enumerator->destroy(enumerator);
	enumerator = charon->file_loggers->create_enumerator(charon->file_loggers);
	while (enumerator->enumerate(enumerator, &file_logger))
	{
		file_logger->set_level(file_logger, group, msg->loglevel.level);
	}
	enumerator->destroy(enumerator);
}

/**
 * set various config options
 */
static void stroke_config(private_stroke_socket_t *this,
						  stroke_msg_t *msg, FILE *out)
{
	this->cred->cachecrl(this->cred, msg->config.cachecrl);
}

/**
 * destroy a job context
 */
static void stroke_job_context_destroy(stroke_job_context_t *this)
{
	if (this->fd)
	{
		close(this->fd);
	}
	free(this);
}

/**
 * called to signal the completion of a command
 */
static inline job_requeue_t job_processed(private_stroke_socket_t *this)
{
	this->mutex->lock(this->mutex);
	this->handling--;
	this->condvar->signal(this->condvar);
	this->mutex->unlock(this->mutex);
	return JOB_REQUEUE_NONE;
}

/**
 * process a stroke request from the socket pointed by "fd"
 */
static job_requeue_t process(stroke_job_context_t *ctx)
{
	stroke_msg_t *msg;
	u_int16_t msg_length;
	ssize_t bytes_read;
	FILE *out;
	private_stroke_socket_t *this = ctx->this;
	int strokefd = ctx->fd;

	/* peek the length */
	bytes_read = recv(strokefd, &msg_length, sizeof(msg_length), MSG_PEEK);
	if (bytes_read != sizeof(msg_length))
	{
		DBG1(DBG_CFG, "reading length of stroke message failed: %s",
			 strerror(errno));
		return job_processed(this);
	}

	/* read message */
	msg = alloca(msg_length);
	bytes_read = recv(strokefd, msg, msg_length, 0);
	if (bytes_read != msg_length)
	{
		DBG1(DBG_CFG, "reading stroke message failed: %s", strerror(errno));
		return job_processed(this);
	}

	out = fdopen(strokefd, "w+");
	if (out == NULL)
	{
		DBG1(DBG_CFG, "opening stroke output channel failed: %s", strerror(errno));
		return job_processed(this);
	}

	DBG3(DBG_CFG, "stroke message %b", (void*)msg, msg_length);

	switch (msg->type)
	{
		case STR_INITIATE:
			stroke_initiate(this, msg, out);
			break;
		case STR_ROUTE:
			stroke_route(this, msg, out);
			break;
		case STR_UNROUTE:
			stroke_unroute(this, msg, out);
			break;
		case STR_TERMINATE:
			stroke_terminate(this, msg, out);
			break;
		case STR_TERMINATE_SRCIP:
			stroke_terminate_srcip(this, msg, out);
			break;
		case STR_REKEY:
			stroke_rekey(this, msg, out);
			break;
		case STR_STATUS:
			stroke_status(this, msg, out, FALSE, TRUE);
			break;
		case STR_STATUS_ALL:
			stroke_status(this, msg, out, TRUE, TRUE);
			break;
		case STR_STATUS_ALL_NOBLK:
			stroke_status(this, msg, out, TRUE, FALSE);
			break;
		case STR_ADD_CONN:
			stroke_add_conn(this, msg);
			break;
		case STR_DEL_CONN:
			stroke_del_conn(this, msg);
			break;
		case STR_ADD_CA:
			stroke_add_ca(this, msg, out);
			break;
		case STR_DEL_CA:
			stroke_del_ca(this, msg, out);
			break;
		case STR_LOGLEVEL:
			stroke_loglevel(this, msg, out);
			break;
		case STR_CONFIG:
			stroke_config(this, msg, out);
			break;
		case STR_LIST:
			stroke_list(this, msg, out);
			break;
		case STR_REREAD:
			stroke_reread(this, msg, out);
			break;
		case STR_PURGE:
			stroke_purge(this, msg, out);
			break;
		case STR_EXPORT:
			stroke_export(this, msg, out);
			break;
		case STR_LEASES:
			stroke_leases(this, msg, out);
			break;
		case STR_MEMUSAGE:
			stroke_memusage(this, msg, out);
			break;
		case STR_USER_CREDS:
			stroke_user_creds(this, msg, out);
			break;
		default:
			DBG1(DBG_CFG, "received unknown stroke");
			break;
	}
	fclose(out);
	/* fclose() closes underlying FD */
	ctx->fd = 0;
	return job_processed(this);
}

/**
 * Handle queued stroke commands
 */
static job_requeue_t handle(private_stroke_socket_t *this)
{
	stroke_job_context_t *ctx;
	callback_job_t *job;
	bool oldstate;

	this->mutex->lock(this->mutex);
	thread_cleanup_push((thread_cleanup_t)this->mutex->unlock, this->mutex);
	oldstate = thread_cancelability(TRUE);
	while (this->commands->get_count(this->commands) == 0 ||
		   this->handling >= this->max_concurrent)
	{
		this->condvar->wait(this->condvar, this->mutex);
	}
	thread_cancelability(oldstate);
	this->commands->remove_first(this->commands, (void**)&ctx);
	this->handling++;
	thread_cleanup_pop(TRUE);
	job = callback_job_create_with_prio((callback_job_cb_t)process, ctx,
			(void*)stroke_job_context_destroy, this->handler, JOB_PRIO_HIGH);
	lib->processor->queue_job(lib->processor, (job_t*)job);
	return JOB_REQUEUE_DIRECT;
}

/**
 * Accept stroke commands and queue them to be handled
 */
static job_requeue_t receive(private_stroke_socket_t *this)
{
	struct sockaddr_un strokeaddr;
	int strokeaddrlen = sizeof(strokeaddr);
	int strokefd;
	bool oldstate;
	stroke_job_context_t *ctx;

	oldstate = thread_cancelability(TRUE);
	strokefd = accept(this->socket, (struct sockaddr *)&strokeaddr, &strokeaddrlen);
	thread_cancelability(oldstate);

	if (strokefd < 0)
	{
		DBG1(DBG_CFG, "accepting stroke connection failed: %s", strerror(errno));
		return JOB_REQUEUE_FAIR;
	}

	INIT(ctx,
		.fd = strokefd,
		.this = this,
	);
	this->mutex->lock(this->mutex);
	this->commands->insert_last(this->commands, ctx);
	this->condvar->signal(this->condvar);
	this->mutex->unlock(this->mutex);

	return JOB_REQUEUE_FAIR;
}

/**
 * initialize and open stroke socket
 */
static bool open_socket(private_stroke_socket_t *this)
{
	struct sockaddr_un socket_addr;
	mode_t old;

	socket_addr.sun_family = AF_UNIX;
	strcpy(socket_addr.sun_path, STROKE_SOCKET);

	/* set up unix socket */
	this->socket = socket(AF_UNIX, SOCK_STREAM, 0);
	if (this->socket == -1)
	{
		DBG1(DBG_CFG, "could not create stroke socket");
		return FALSE;
	}

	unlink(socket_addr.sun_path);
	old = umask(~(S_IRWXU | S_IRWXG));
	if (bind(this->socket, (struct sockaddr *)&socket_addr, sizeof(socket_addr)) < 0)
	{
		DBG1(DBG_CFG, "could not bind stroke socket: %s", strerror(errno));
		close(this->socket);
		return FALSE;
	}
	umask(old);
	if (chown(socket_addr.sun_path, charon->uid, charon->gid) != 0)
	{
		DBG1(DBG_CFG, "changing stroke socket permissions failed: %s",
			 strerror(errno));
	}

	if (listen(this->socket, 10) < 0)
	{
		DBG1(DBG_CFG, "could not listen on stroke socket: %s", strerror(errno));
		close(this->socket);
		unlink(socket_addr.sun_path);
		return FALSE;
	}
	return TRUE;
}

METHOD(stroke_socket_t, destroy, void,
	private_stroke_socket_t *this)
{
	this->handler->cancel(this->handler);
	this->receiver->cancel(this->receiver);
	this->commands->destroy_function(this->commands, (void*)stroke_job_context_destroy);
	this->condvar->destroy(this->condvar);
	this->mutex->destroy(this->mutex);
	lib->credmgr->remove_set(lib->credmgr, &this->ca->set);
	lib->credmgr->remove_set(lib->credmgr, &this->cred->set);
	charon->backends->remove_backend(charon->backends, &this->config->backend);
	hydra->attributes->remove_provider(hydra->attributes, &this->attribute->provider);
	this->cred->destroy(this->cred);
	this->ca->destroy(this->ca);
	this->config->destroy(this->config);
	this->attribute->destroy(this->attribute);
	this->control->destroy(this->control);
	this->list->destroy(this->list);
	free(this);
}

/*
 * see header file
 */
stroke_socket_t *stroke_socket_create()
{
	private_stroke_socket_t *this;

	INIT(this,
		.public = {
			.destroy = _destroy,
		},
	);

	if (!open_socket(this))
	{
		free(this);
		return NULL;
	}

	this->cred = stroke_cred_create();
	this->attribute = stroke_attribute_create();
	this->ca = stroke_ca_create(this->cred);
	this->config = stroke_config_create(this->ca, this->cred);
	this->control = stroke_control_create();
	this->list = stroke_list_create(this->attribute);

	this->mutex = mutex_create(MUTEX_TYPE_DEFAULT);
	this->condvar = condvar_create(CONDVAR_TYPE_DEFAULT);
	this->commands = linked_list_create();
	this->max_concurrent = lib->settings->get_int(lib->settings,
				"charon.plugins.stroke.max_concurrent", MAX_CONCURRENT_DEFAULT);

	lib->credmgr->add_set(lib->credmgr, &this->ca->set);
	lib->credmgr->add_set(lib->credmgr, &this->cred->set);
	charon->backends->add_backend(charon->backends, &this->config->backend);
	hydra->attributes->add_provider(hydra->attributes, &this->attribute->provider);

	this->receiver = callback_job_create_with_prio((callback_job_cb_t)receive,
										this, NULL, NULL, JOB_PRIO_CRITICAL);
	lib->processor->queue_job(lib->processor, (job_t*)this->receiver);

	this->handler = callback_job_create_with_prio((callback_job_cb_t)handle,
										this, NULL, NULL, JOB_PRIO_CRITICAL);
	lib->processor->queue_job(lib->processor, (job_t*)this->handler);

	return &this->public;
}

