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

#include "stroke_socket.h"

#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/fcntl.h>
#include <unistd.h>
#include <errno.h>

#include <processing/jobs/callback_job.h>
#include <daemon.h>

#include "stroke_config.h"
#include "stroke_control.h"
#include "stroke_cred.h"
#include "stroke_ca.h"
#include "stroke_list.h"

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
	callback_job_t *job;
	
	/**
	 * configuration backend
	 */
	stroke_config_t *config;
	
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
	 * Status information logging
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
		string > (char**)msg + sizeof(stroke_msg_t) ||
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
	pop_string(msg, &end->subnet);
	pop_string(msg, &end->sourceip);
	pop_string(msg, &end->id);
	pop_string(msg, &end->cert);
	pop_string(msg, &end->ca);
	pop_string(msg, &end->groups);
	pop_string(msg, &end->updown);
	
	DBG2(DBG_CFG, "  %s=%s", label, end->address);
	DBG2(DBG_CFG, "  %ssubnet=%s", label, end->subnet);
	DBG2(DBG_CFG, "  %ssourceip=%s", label, end->sourceip);
	DBG2(DBG_CFG, "  %sid=%s", label, end->id);
	DBG2(DBG_CFG, "  %scert=%s", label, end->cert);
	DBG2(DBG_CFG, "  %sca=%s", label, end->ca);
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
	pop_string(msg, &msg->add_conn.algorithms.ike);
	pop_string(msg, &msg->add_conn.algorithms.esp);
	DBG2(DBG_CFG, "  ike=%s", msg->add_conn.algorithms.ike);
	DBG2(DBG_CFG, "  esp=%s", msg->add_conn.algorithms.esp);
	pop_string(msg, &msg->add_conn.ikeme.mediated_by);
	pop_string(msg, &msg->add_conn.ikeme.peerid);
	DBG2(DBG_CFG, "  mediation=%s", msg->add_conn.ikeme.mediation ? "yes" : "no");
	DBG2(DBG_CFG, "  mediated_by=%s", msg->add_conn.ikeme.mediated_by);
	DBG2(DBG_CFG, "  me_peerid=%s", msg->add_conn.ikeme.peerid);

	this->config->add(this->config, msg);
}

/**
 * Delete a connection from the list
 */
static void stroke_del_conn(private_stroke_socket_t *this, stroke_msg_t *msg)
{
	pop_string(msg, &msg->del_conn.name);
	DBG1(DBG_CFG, "received stroke: delete connection '%s'", msg->del_conn.name);
	
	this->config->del(this->config, msg);
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
	pop_string(msg, &msg->add_ca.cacert);
	pop_string(msg, &msg->add_ca.crluri);
	pop_string(msg, &msg->add_ca.crluri2);
	pop_string(msg, &msg->add_ca.ocspuri);
	pop_string(msg, &msg->add_ca.ocspuri2);

	DBG2(DBG_CFG, "ca %s",        msg->add_ca.name);
	DBG2(DBG_CFG, "  cacert=%s",  msg->add_ca.cacert);
	DBG2(DBG_CFG, "  crluri=%s",  msg->add_ca.crluri);
	DBG2(DBG_CFG, "  crluri2=%s", msg->add_ca.crluri2);
	DBG2(DBG_CFG, "  ocspuri=%s", msg->add_ca.ocspuri);
	DBG2(DBG_CFG, "  ocspuri2=%s", msg->add_ca.ocspuri2);
	
	DBG1(DBG_CFG, "received stroke: add ca '%s'", msg->add_ca.name);
	
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
						  stroke_msg_t *msg, FILE *out, bool all)
{
	pop_string(msg, &(msg->status.name));
	
	this->list->status(this->list, msg, out, all);
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
	this->cred->reread(this->cred, msg);
}

/**
 * purge various information
 */
static void stroke_purge(private_stroke_socket_t *this,
						 stroke_msg_t *msg, FILE *out)
{
	charon->credentials->flush_cache(charon->credentials,
									 CERT_X509_OCSP_RESPONSE);
}

signal_t get_signal_from_logtype(char *type)
{
	if      (strcasecmp(type, "any") == 0) return SIG_ANY;
	else if (strcasecmp(type, "mgr") == 0) return DBG_MGR;
	else if (strcasecmp(type, "ike") == 0) return DBG_IKE;
	else if (strcasecmp(type, "chd") == 0) return DBG_CHD;
	else if (strcasecmp(type, "job") == 0) return DBG_JOB;
	else if (strcasecmp(type, "cfg") == 0) return DBG_CFG;
	else if (strcasecmp(type, "knl") == 0) return DBG_KNL;
	else if (strcasecmp(type, "net") == 0) return DBG_NET;
	else if (strcasecmp(type, "enc") == 0) return DBG_ENC;
	else if (strcasecmp(type, "lib") == 0) return DBG_LIB;
	else return -1;
}

/**
 * set the verbosity debug output
 */
static void stroke_loglevel(private_stroke_socket_t *this, stroke_msg_t *msg, FILE *out)
{
	signal_t signal;
	
	pop_string(msg, &(msg->loglevel.type));
	DBG1(DBG_CFG, "received stroke: loglevel %d for %s",
		 msg->loglevel.level, msg->loglevel.type);
	
	signal = get_signal_from_logtype(msg->loglevel.type);
	if (signal < 0)
	{
		fprintf(out, "invalid type (%s)!\n", msg->loglevel.type);
		return;
	}
	
	charon->outlog->set_level(charon->outlog, signal, msg->loglevel.level);
	charon->syslog->set_level(charon->syslog, signal, msg->loglevel.level);
}


/**
 * destroy a job context
 */
static void stroke_job_context_destroy(stroke_job_context_t *this)
{
	close(this->fd);
	free(this);
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
		close(strokefd);
		return JOB_REQUEUE_NONE;
	}
	
	/* read message */
	msg = malloc(msg_length);
	bytes_read = recv(strokefd, msg, msg_length, 0);
	if (bytes_read != msg_length)
	{
		DBG1(DBG_CFG, "reading stroke message failed: %s", strerror(errno));
		close(strokefd);
		return JOB_REQUEUE_NONE;
	}
	
	out = fdopen(strokefd, "w");
	if (out == NULL)
	{
		DBG1(DBG_CFG, "opening stroke output channel failed: %s", strerror(errno));
		close(strokefd);
		free(msg);
		return JOB_REQUEUE_NONE;
	}
	
	DBG3(DBG_CFG, "stroke message %b", (void*)msg, msg_length);
	
	/* the stroke_* functions are blocking, as they listen on the bus. Add
	 * cancellation handlers. */
	pthread_cleanup_push((void*)fclose, out);
	pthread_cleanup_push(free, msg);
	
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
		case STR_STATUS:
			stroke_status(this, msg, out, FALSE);
			break;
		case STR_STATUS_ALL:
			stroke_status(this, msg, out, TRUE);
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
		case STR_LIST:
			stroke_list(this, msg, out);
			break;
		case STR_REREAD:
			stroke_reread(this, msg, out);
			break;
		case STR_PURGE:
			stroke_purge(this, msg, out);
			break;
		default:
			DBG1(DBG_CFG, "received unknown stroke");
	}
	/* remove and execute cancellation handlers */
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	
	return JOB_REQUEUE_NONE;
}

/**
 * Implementation of private_stroke_socket_t.stroke_receive.
 */
static job_requeue_t receive(private_stroke_socket_t *this)
{
	struct sockaddr_un strokeaddr;
	int strokeaddrlen = sizeof(strokeaddr);
	int strokefd;
	int oldstate;
	callback_job_t *job;
	stroke_job_context_t *ctx;
	
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &oldstate);
	strokefd = accept(this->socket, (struct sockaddr *)&strokeaddr, &strokeaddrlen);
	pthread_setcancelstate(oldstate, NULL);
	
	if (strokefd < 0)
	{
		DBG1(DBG_CFG, "accepting stroke connection failed: %s", strerror(errno));
		return JOB_REQUEUE_FAIR;
	}
	
	ctx = malloc_thing(stroke_job_context_t);
	ctx->fd = strokefd;
	ctx->this = this;
	job = callback_job_create((callback_job_cb_t)process,
							  ctx, (void*)stroke_job_context_destroy, this->job);
	charon->processor->queue_job(charon->processor, (job_t*)job);
	
	return JOB_REQUEUE_FAIR;
}


/**
 * initialize and open stroke socket
 */
static bool open_socket(private_stroke_socket_t *this)
{
	struct sockaddr_un socket_addr = { AF_UNIX, STROKE_SOCKET};
	mode_t old;
	
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
	if (chown(socket_addr.sun_path, IPSEC_UID, IPSEC_GID) != 0)
	{
		DBG1(DBG_CFG, "changing stroke socket permissions failed: %s",
			 strerror(errno));
	}
	
	if (listen(this->socket, 0) < 0)
	{
		DBG1(DBG_CFG, "could not listen on stroke socket: %s", strerror(errno));
		close(this->socket);
		unlink(socket_addr.sun_path);
		return FALSE;
	}
	return TRUE;
}

/**
 * Implementation of stroke_socket_t.destroy
 */
static void destroy(private_stroke_socket_t *this)
{
	this->job->cancel(this->job);
	charon->credentials->remove_set(charon->credentials, &this->ca->set);
	charon->credentials->remove_set(charon->credentials, &this->cred->set);
	charon->backends->remove_backend(charon->backends, &this->config->backend);
	this->cred->destroy(this->cred);
	this->ca->destroy(this->ca);
	this->config->destroy(this->config);
	this->control->destroy(this->control);
	this->list->destroy(this->list);
	free(this);
}

/*
 * see header file
 */
stroke_socket_t *stroke_socket_create()
{
	private_stroke_socket_t *this = malloc_thing(private_stroke_socket_t);
	
	this->public.destroy = (void(*)(stroke_socket_t*))destroy;
	
	if (!open_socket(this))
	{
		free(this);
		return NULL;
	}
	
	this->cred = stroke_cred_create();
	this->ca = stroke_ca_create(this->cred);
	this->config = stroke_config_create(this->cred);
	this->control = stroke_control_create();
	this->list = stroke_list_create();
	
	charon->credentials->add_set(charon->credentials, &this->ca->set);
	charon->credentials->add_set(charon->credentials, &this->cred->set);
	charon->backends->add_backend(charon->backends, &this->config->backend);
	
	this->job = callback_job_create((callback_job_cb_t)receive,
									this, NULL, NULL);
	charon->processor->queue_job(charon->processor, (job_t*)this->job);
	
	return &this->public;
}

