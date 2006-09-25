/**
 * @file stroke.c
 * 
 * @brief Implementation of stroke_t.
 * 
 */

/*
 * Copyright (C) 2006 Martin Willi
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

#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <pthread.h>

#include "stroke_interface.h"

#include <stroke.h>
#include <types.h>
#include <daemon.h>
#include <crypto/x509.h>
#include <queues/jobs/initiate_job.h>
#include <queues/jobs/route_job.h>
#include <utils/leak_detective.h>

#define IKE_PORT	500
#define PATH_BUF	256


struct sockaddr_un socket_addr = { AF_UNIX, STROKE_SOCKET};


typedef struct private_stroke_t private_stroke_t;

/**
 * Private data of an stroke_t object.
 */
struct private_stroke_t {

	/**
	 * Public part of stroke_t object.
	 */
	stroke_t public;

	/**
	 * Assigned logger_t object in charon.
	 */
	logger_t *logger;
	
	/**
	 * Logger which logs to stroke
	 */
	logger_t *stroke_logger;
		
	/**
	 * Unix socket to listen for strokes
	 */
	int socket;
	
	/**
	 * Thread which reads from the ocket
	 */
	pthread_t assigned_thread;

	/**
	 * Read from the socket and handle stroke messages
	 */
	void (*stroke_receive) (private_stroke_t *this);
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
		return;

	/* check for sanity of string pointer and string */
	if (string < (char**)msg
	||	string > (char**)msg + sizeof(stroke_msg_t)
	|| (u_int)*string < (u_int)((char*)msg->buffer - (char*)msg)
	|| (u_int)*string > msg->length)
	{
		*string = "(invalid pointer in stroke msg)";
	}
	else
	{
		*string = (char*)msg + (u_int)*string;
	}
}

/**
 * Load end entitity certificate
 */
static x509_t* load_end_certificate(const char *filename, identification_t **idp, logger_t *logger)
{
	char path[PATH_BUF];
	x509_t *cert;

	if (*filename == '/')
	{
		/* absolute path name */
		snprintf(path, sizeof(path), "%s", filename);
	}
	else
	{
		/* relative path name */
		snprintf(path, sizeof(path), "%s/%s", CERTIFICATE_DIR, filename);
	}

	cert = x509_create_from_file(path, "end entity certificate");

	if (cert)
	{
		identification_t *id = *idp;
		identification_t *subject = cert->get_subject(cert);

		err_t ugh = cert->is_valid(cert, NULL);

		if (ugh != NULL)	
		{
			logger->log(logger, ERROR, "warning: certificate %s", ugh);
		}
		if (!id->equals(id, subject) && !cert->equals_subjectAltName(cert, id))
		{
			id->destroy(id);
			id = subject;
			*idp = id->clone(id);
		}
		return charon->credentials->add_end_certificate(charon->credentials, cert);
	}
	return NULL;
}

/**
 * Add a connection to the configuration list
 */
static void stroke_add_conn(private_stroke_t *this, stroke_msg_t *msg)
{
	connection_t *connection;
	policy_t *policy;
	identification_t *my_id, *other_id;
	identification_t *my_ca = NULL;
	identification_t *other_ca = NULL;
	bool my_ca_same = FALSE;
    bool other_ca_same =FALSE;
	host_t *my_host, *other_host, *my_subnet, *other_subnet;
	proposal_t *proposal;
	traffic_selector_t *my_ts, *other_ts;
				
	pop_string(msg, &msg->add_conn.name);
	pop_string(msg, &msg->add_conn.me.address);
	pop_string(msg, &msg->add_conn.other.address);
	pop_string(msg, &msg->add_conn.me.subnet);
	pop_string(msg, &msg->add_conn.other.subnet);
	pop_string(msg, &msg->add_conn.me.id);
	pop_string(msg, &msg->add_conn.other.id);
	pop_string(msg, &msg->add_conn.me.cert);
	pop_string(msg, &msg->add_conn.other.cert);
	pop_string(msg, &msg->add_conn.me.ca);
	pop_string(msg, &msg->add_conn.other.ca);
	pop_string(msg, &msg->add_conn.me.updown);
	pop_string(msg, &msg->add_conn.other.updown);
	pop_string(msg, &msg->add_conn.algorithms.ike);
	pop_string(msg, &msg->add_conn.algorithms.esp);
	
	this->logger->log(this->logger, CONTROL, 
					  "received stroke: add connection \"%s\"", msg->add_conn.name);
	
	this->logger->log(this->logger, CONTROL|LEVEL2, "conn %s", msg->add_conn.name);
	this->logger->log(this->logger, CONTROL|LEVEL2, "  right=%s", msg->add_conn.me.address);
	this->logger->log(this->logger, CONTROL|LEVEL2, "  left=%s", msg->add_conn.other.address);
	this->logger->log(this->logger, CONTROL|LEVEL2, "  rightsubnet=%s", msg->add_conn.me.subnet);
	this->logger->log(this->logger, CONTROL|LEVEL2, "  leftsubnet=%s", msg->add_conn.other.subnet);
	this->logger->log(this->logger, CONTROL|LEVEL2, "  rightid=%s", msg->add_conn.me.id);
	this->logger->log(this->logger, CONTROL|LEVEL2, "  leftid=%s", msg->add_conn.other.id);
	this->logger->log(this->logger, CONTROL|LEVEL2, "  rightcert=%s", msg->add_conn.me.cert);
	this->logger->log(this->logger, CONTROL|LEVEL2, "  leftcert=%s", msg->add_conn.other.cert);
	this->logger->log(this->logger, CONTROL|LEVEL2, "  rightca=%s", msg->add_conn.me.ca);
	this->logger->log(this->logger, CONTROL|LEVEL2, "  leftca=%s", msg->add_conn.other.ca);
	this->logger->log(this->logger, CONTROL|LEVEL2, "  ike=%s", msg->add_conn.algorithms.ike);
	this->logger->log(this->logger, CONTROL|LEVEL2, "  esp=%s", msg->add_conn.algorithms.esp);
	
	my_host = msg->add_conn.me.address?
			  host_create_from_string(msg->add_conn.me.address, IKE_PORT) : NULL;
	if (my_host == NULL)
	{
		this->stroke_logger->log(this->stroke_logger, ERROR, 
								 "invalid host: %s", msg->add_conn.me.address);
		return;
	}

	other_host = msg->add_conn.other.address ?
			host_create_from_string(msg->add_conn.other.address, IKE_PORT) : NULL;
	if (other_host == NULL)
	{
		this->stroke_logger->log(this->stroke_logger, ERROR, 
								 "invalid host: %s", msg->add_conn.other.address);
		my_host->destroy(my_host);
		return;
	}

	if (charon->socket->is_local_address(charon->socket, other_host, NULL))
	{
		stroke_end_t tmp_end;
		host_t *tmp_host;

		this->stroke_logger->log(this->stroke_logger, CONTROL|LEVEL1, 
								 "left is other host, swapping ends");

		tmp_host = my_host;
		my_host = other_host;
		other_host = tmp_host;

		tmp_end = msg->add_conn.me;
		msg->add_conn.me = msg->add_conn.other;
		msg->add_conn.other = tmp_end;
	}
	else if (!charon->socket->is_local_address(charon->socket, my_host, NULL))
	{
		this->stroke_logger->log(this->stroke_logger, ERROR, 
								 "left nor right host is our side, aborting");
		goto destroy_hosts;
	}

	my_id = identification_create_from_string(msg->add_conn.me.id ?
						msg->add_conn.me.id : msg->add_conn.me.address);
	if (my_id == NULL)
	{
		this->stroke_logger->log(this->stroke_logger, ERROR, 
								 "invalid id: %s", msg->add_conn.me.id);
		goto destroy_hosts;
	}

	other_id = identification_create_from_string(msg->add_conn.other.id ?
						msg->add_conn.other.id : msg->add_conn.other.address);
	if (other_id == NULL)
	{
		this->stroke_logger->log(this->stroke_logger, ERROR, 
								 "invalid id: %s", msg->add_conn.other.id);
		my_id->destroy(my_id);
		goto destroy_hosts;
	}
	
	my_subnet = host_create_from_string(msg->add_conn.me.subnet ?
					msg->add_conn.me.subnet : msg->add_conn.me.address, IKE_PORT);
	if (my_subnet == NULL)
	{
		this->stroke_logger->log(this->stroke_logger, ERROR, 
								 "invalid subnet: %s", msg->add_conn.me.subnet);
		goto destroy_ids;
	}
	
	other_subnet = host_create_from_string(msg->add_conn.other.subnet ?
					msg->add_conn.other.subnet : msg->add_conn.other.address, IKE_PORT);
	if (other_subnet == NULL)
	{
		this->stroke_logger->log(this->stroke_logger, ERROR, 
								 "invalid subnet: %s", msg->add_conn.me.subnet);
		my_subnet->destroy(my_subnet);
		goto destroy_ids;
	}
				
	my_ts = traffic_selector_create_from_subnet(my_subnet,
				msg->add_conn.me.subnet ?  msg->add_conn.me.subnet_mask : 0,
				msg->add_conn.me.protocol, msg->add_conn.me.port);
	my_subnet->destroy(my_subnet);

	other_ts = traffic_selector_create_from_subnet(other_subnet, 
			msg->add_conn.other.subnet ?  msg->add_conn.other.subnet_mask : 0,
			msg->add_conn.other.protocol, msg->add_conn.other.port);
	other_subnet->destroy(other_subnet);

	if (msg->add_conn.me.ca)
	{
		if (streq(msg->add_conn.me.ca, "%same"))
		{
			my_ca_same = TRUE;
		}
		else
		{
			my_ca = identification_create_from_string(msg->add_conn.me.ca);
		}
	}
	if (msg->add_conn.other.ca)
	{
		if (streq(msg->add_conn.other.ca, "%same"))
		{
			other_ca_same = TRUE;
		}
		else
		{
			other_ca = identification_create_from_string(msg->add_conn.other.ca);
		}
	}
	if (msg->add_conn.me.cert)
	{
		x509_t *cert = load_end_certificate(msg->add_conn.me.cert, &my_id, this->logger);

		if (my_ca == NULL && !my_ca_same && cert)
		{
			identification_t *issuer = cert->get_issuer(cert);

			my_ca = issuer->clone(issuer);
		}
	}
	if (msg->add_conn.other.cert)
	{
		x509_t *cert = load_end_certificate(msg->add_conn.other.cert, &other_id, this->logger);

		if (other_ca == NULL && !other_ca_same && cert)
		{
			identification_t *issuer = cert->get_issuer(cert);

			other_ca = issuer->clone(issuer);
		}
	}
	if (other_ca_same && my_ca)
	{
		other_ca = my_ca->clone(my_ca);
	}
	else if (my_ca_same && other_ca)
	{
		my_ca = other_ca->clone(other_ca);
	}
	if (my_ca == NULL)
	{
		my_ca = identification_create_from_string("%any");
	}
	if (other_ca == NULL)
	{
		other_ca = identification_create_from_string("%any");
	}
	this->logger->log(this->logger, CONTROL|LEVEL2, "  my ca:   '%s'", my_ca->get_string(my_ca));
	this->logger->log(this->logger, CONTROL|LEVEL2, "  other ca:'%s'", other_ca->get_string(other_ca));
	this->logger->log(this->logger, CONTROL|LEVEL2, "  updown:'%s'", msg->add_conn.me.updown);

	connection = connection_create(msg->add_conn.name,
								   msg->add_conn.ikev2,
								   msg->add_conn.me.sendcert,
								   msg->add_conn.other.sendcert,
								   my_host, other_host,
								   msg->add_conn.dpd.delay,
								   msg->add_conn.rekey.tries,
								   msg->add_conn.rekey.ike_lifetime,
								   msg->add_conn.rekey.ike_lifetime - msg->add_conn.rekey.margin,
								   msg->add_conn.rekey.margin * msg->add_conn.rekey.fuzz / 100);

	if (msg->add_conn.algorithms.ike)
	{
		char *proposal_string;
		char *strict = msg->add_conn.algorithms.ike + strlen(msg->add_conn.algorithms.ike) - 1;

		if (*strict == '!')
			*strict = '\0';
		else
			strict = NULL;

		while ((proposal_string = strsep(&msg->add_conn.algorithms.ike, ",")))
		{
			proposal = proposal_create_from_string(PROTO_IKE, proposal_string);
			if (proposal == NULL)
			{
				this->logger->log(this->logger, ERROR, 
								  "invalid IKE proposal string: %s", proposal_string);
				my_id->destroy(my_id);
				other_id->destroy(other_id);
				my_ts->destroy(my_ts);
				other_ts->destroy(other_ts);
				my_ca->destroy(my_ca);
				other_ca->destroy(other_ca);
				connection->destroy(connection);
				return;
			}
			connection->add_proposal(connection, proposal);
		}
		if (!strict)
		{
			proposal = proposal_create_default(PROTO_IKE);
			connection->add_proposal(connection, proposal);
		}
	}
	else
	{
		proposal = proposal_create_default(PROTO_IKE);
		connection->add_proposal(connection, proposal);
	}
	
	policy = policy_create(msg->add_conn.name, my_id, other_id,
						   msg->add_conn.auth_method,
						   msg->add_conn.rekey.ipsec_lifetime,
						   msg->add_conn.rekey.ipsec_lifetime - msg->add_conn.rekey.margin,
						   msg->add_conn.rekey.margin * msg->add_conn.rekey.fuzz / 100, 
						   msg->add_conn.me.updown, msg->add_conn.me.hostaccess,
						   msg->add_conn.dpd.action);
	policy->add_my_traffic_selector(policy, my_ts);
	policy->add_other_traffic_selector(policy, other_ts);
	policy->add_authorities(policy, my_ca, other_ca);
	
	if (msg->add_conn.algorithms.esp)
	{
		char *proposal_string;
		char *strict = msg->add_conn.algorithms.esp + strlen(msg->add_conn.algorithms.esp) - 1;

		if (*strict == '!')
			*strict = '\0';
		else
			strict = NULL;
		
		while ((proposal_string = strsep(&msg->add_conn.algorithms.esp, ",")))
		{
			proposal = proposal_create_from_string(PROTO_ESP, proposal_string);
			if (proposal == NULL)
			{
				this->logger->log(this->logger, ERROR,
								  "invalid ESP proposal string: %s", proposal_string);
				policy->destroy(policy);
				connection->destroy(connection);
				return;
			}
			policy->add_proposal(policy, proposal);
		}
		if (!strict)
		{
			proposal = proposal_create_default(PROTO_ESP);
			policy->add_proposal(policy, proposal);
		}
	}
	else
	{
		proposal = proposal_create_default(PROTO_ESP);
		policy->add_proposal(policy, proposal);
	}
	
	/* add to global connection list */
	charon->connections->add_connection(charon->connections, connection);
	this->logger->log(this->logger, CONTROL, "added connection \"%s\": %s[%s]...%s[%s]",
					  msg->add_conn.name,
					  my_host->get_string(my_host),
					  my_id->get_string(my_id),
					  other_host->get_string(other_host),
					  other_id->get_string(other_id));
	/* add to global policy list */
	charon->policies->add_policy(charon->policies, policy);
	return;

	/* mopping up after parsing errors */

destroy_ids:
	my_id->destroy(my_id);
	other_id->destroy(other_id);

destroy_hosts:
	my_host->destroy(my_host);
	other_host->destroy(other_host);
}

/**
 * Delete a connection from the list
 */
static void stroke_del_conn(private_stroke_t *this, stroke_msg_t *msg)
{
	status_t status;
	
	pop_string(msg, &(msg->del_conn.name));
	this->logger->log(this->logger, CONTROL, "received stroke: delete \"%s\"", msg->del_conn.name);
	
	status = charon->connections->delete_connection(charon->connections, 
													msg->del_conn.name);
	charon->policies->delete_policy(charon->policies, msg->del_conn.name);
	if (status == SUCCESS)
	{
		this->stroke_logger->log(this->stroke_logger, CONTROL,
								 "Deleted connection '%s'", msg->del_conn.name);
	}
	else
	{
		this->stroke_logger->log(this->stroke_logger, ERROR,
								 "No connection named '%s'", msg->del_conn.name);
	}
}

/**
 * initiate a connection by name
 */
static void stroke_initiate(private_stroke_t *this, stroke_msg_t *msg)
{
	initiate_job_t *job;
	connection_t *connection;
	policy_t *policy;
	
	pop_string(msg, &(msg->initiate.name));
	this->logger->log(this->logger, CONTROL,
					  "received stroke: initiate \"%s\"",
					  msg->initiate.name);
	
	connection = charon->connections->get_connection_by_name(charon->connections,
															 msg->initiate.name);
	if (connection == NULL)
	{
		this->stroke_logger->log(this->stroke_logger, ERROR, 
								 "no connection named \"%s\"", 
								 msg->initiate.name);
		return;
	}
	if (!connection->is_ikev2(connection))
	{
		connection->destroy(connection);
		return;
	}
		
	policy = charon->policies->get_policy_by_name(charon->policies, 
												  msg->initiate.name);
	if (policy == NULL)
	{
		this->stroke_logger->log(this->stroke_logger, ERROR,
								 "no policy named \"%s\"",
								 msg->initiate.name);
		connection->destroy(connection);
		return;
	}
	this->stroke_logger->log(this->stroke_logger, CONTROL,
							 "initiating connection \"%s\" (see log)...", 
							 msg->initiate.name);
	job = initiate_job_create(connection, policy);
	charon->job_queue->add(charon->job_queue, (job_t*)job);
}

/**
 * route/unroute a policy (install SPD entries)
 */
static void stroke_route(private_stroke_t *this, stroke_msg_t *msg, bool route)
{
	route_job_t *job;
	connection_t *connection;
	policy_t *policy;
	
	pop_string(msg, &(msg->route.name));
	this->logger->log(this->logger, CONTROL,
					  "received stroke: %s \"%s\"",
					  route ? "route" : "unroute",
					  msg->route.name);
	
	/* we wouldn't need a connection, but we only want to route policies
	 * whose connections are keyexchange=ikev2. */
	connection = charon->connections->get_connection_by_name(charon->connections,
															 msg->route.name);
	if (connection == NULL)
	{
		this->stroke_logger->log(this->stroke_logger, ERROR, 
								 "no connection named \"%s\"", 
								 msg->route.name);
		return;
	}
	if (!connection->is_ikev2(connection))
	{
		connection->destroy(connection);
		return;
	}
		
	policy = charon->policies->get_policy_by_name(charon->policies, 
												  msg->route.name);
	if (policy == NULL)
	{
		this->stroke_logger->log(this->stroke_logger, ERROR,
								 "no policy named \"%s\"",
								 msg->route.name);
		connection->destroy(connection);
		return;
	}
	this->stroke_logger->log(this->stroke_logger, CONTROL,
							 "%s policy \"%s\"", 
							 route ? "routing" : "unrouting",
							 msg->route.name);
	job = route_job_create(connection, policy, route);
	charon->job_queue->add(charon->job_queue, (job_t*)job);
}

/**
 * terminate a connection by name
 */
static void stroke_terminate(private_stroke_t *this, stroke_msg_t *msg)
{
	pop_string(msg, &(msg->terminate.name));
	this->logger->log(this->logger, CONTROL, "received stroke: terminate \"%s\"", msg->terminate.name);
	
	charon->ike_sa_manager->delete_by_name(charon->ike_sa_manager, msg->terminate.name);
}

/**
 * show status of (established) connections
 */
static void stroke_status(private_stroke_t *this, stroke_msg_t *msg)
{
	linked_list_t *list;
	host_t *host;
	
	leak_detective_status(this->stroke_logger);
	
	this->stroke_logger->log(this->stroke_logger, CONTROL|LEVEL1,
							 "job queue load: %d",
							 charon->job_queue->get_count(charon->job_queue));
	this->stroke_logger->log(this->stroke_logger, CONTROL|LEVEL1,
							 "scheduled events: %d",
							 charon->event_queue->get_count(charon->event_queue));
	list = charon->socket->create_local_address_list(charon->socket);
	this->stroke_logger->log(this->stroke_logger, CONTROL|LEVEL1,
							 "listening on %d addresses:",
							 list->get_count(list));
	while (list->remove_first(list, (void**)&host) == SUCCESS)
	{
		this->stroke_logger->log(this->stroke_logger, CONTROL|LEVEL1,
								 "  %s", host->get_string(host));
		host->destroy(host);
		
	}
	list->destroy(list);
	
	if (msg->status.name)
	{
		pop_string(msg, &(msg->status.name));
	}
	charon->connections->log_connections(charon->connections,
										 this->stroke_logger, msg->status.name);
	charon->ike_sa_manager->log_status(charon->ike_sa_manager,
									   this->stroke_logger, msg->status.name);
}

/**
 * list various information
 */
static void stroke_list(private_stroke_t *this, stroke_msg_t *msg)
{
	if (msg->list.flags & LIST_CERTS)
	{
		charon->credentials->log_certificates(charon->credentials, this->stroke_logger, msg->list.utc);
	}
	if (msg->list.flags & LIST_CACERTS)
	{
		charon->credentials->log_ca_certificates(charon->credentials, this->stroke_logger, msg->list.utc);
	}
	if (msg->list.flags & LIST_CRLS)
	{
		charon->credentials->log_crls(charon->credentials, this->stroke_logger, msg->list.utc);
	}
}

/**
 * reread various information
 */
static void stroke_reread(private_stroke_t *this, stroke_msg_t *msg)
{
	if (msg->reread.flags & REREAD_CACERTS)
	{
		charon->credentials->load_ca_certificates(charon->credentials);
	}
	if (msg->reread.flags & REREAD_CRLS)
	{
		charon->credentials->load_crls(charon->credentials);
	}
}

logger_context_t get_context(char *context)
{
	if      (strcasecmp(context, "ALL") == 0) return ALL_LOGGERS;
	else if (strcasecmp(context, "PARSR") == 0) return PARSER;
	else if (strcasecmp(context, "GNRAT") == 0) return GENERATOR;
	else if (strcasecmp(context, "IKESA") == 0) return IKE_SA;
	else if (strcasecmp(context, "SAMGR") == 0) return IKE_SA_MANAGER;
	else if (strcasecmp(context, "CHDSA") == 0) return CHILD_SA;
	else if (strcasecmp(context, "MESSG") == 0) return MESSAGE;
	else if (strcasecmp(context, "TPOOL") == 0) return THREAD_POOL;
	else if (strcasecmp(context, "WORKR") == 0) return WORKER;
	else if (strcasecmp(context, "SCHED") == 0) return SCHEDULER;
	else if (strcasecmp(context, "SENDR") == 0) return SENDER;
	else if (strcasecmp(context, "RECVR") == 0) return RECEIVER;
	else if (strcasecmp(context, "SOCKT") == 0) return SOCKET;
	else if (strcasecmp(context, "TESTR") == 0) return TESTER;
	else if (strcasecmp(context, "DAEMN") == 0) return DAEMON;
	else if (strcasecmp(context, "CONFG") == 0) return CONFIG;
	else if (strcasecmp(context, "ENCPL") == 0) return ENCRYPTION_PAYLOAD;
	else if (strcasecmp(context, "PAYLD") == 0) return PAYLOAD;
	else if (strcasecmp(context, "XFRM") == 0) return XFRM;
	else return -2;
}

/**
 * set the type of logged messages in a context
 */
static void stroke_logtype(private_stroke_t *this, stroke_msg_t *msg)
{
	pop_string(msg, &(msg->logtype.context));
	pop_string(msg, &(msg->logtype.type));
	
	this->logger->log(this->logger, CONTROL, "received stroke: logtype for %s", msg->logtype.context);
	
	log_level_t level;
	logger_context_t context = get_context(msg->logtype.context);
	if (context == -2)
	{
		this->stroke_logger->log(this->stroke_logger, ERROR, "invalid context (%s)!", msg->logtype.context);
		return;
	}
	
	if      (strcasecmp(msg->logtype.type, "CONTROL") == 0)
		level = CONTROL;
	else if (strcasecmp(msg->logtype.type, "ERROR") == 0)
		level = ERROR;
	else if (strcasecmp(msg->logtype.type, "AUDIT") == 0)
		level = AUDIT;
	else if (strcasecmp(msg->logtype.type, "RAW") == 0)
		level = RAW;
	else if (strcasecmp(msg->logtype.type, "PRIVATE") == 0)
		level = PRIVATE;
	else
	{
		this->stroke_logger->log(this->stroke_logger, ERROR, "invalid type (%s)!", msg->logtype.type);
		return;
	}
	
	if (msg->logtype.enable)
	{
		logger_manager->enable_log_level(logger_manager, context, level);
	}
	else
	{
		logger_manager->disable_log_level(logger_manager, context, level);
	}
}

/**
 * set the verbosity of a logger
 */
static void stroke_loglevel(private_stroke_t *this, stroke_msg_t *msg)
{
	log_level_t level;
	logger_context_t context;

	pop_string(msg, &(msg->loglevel.context));
	this->logger->log(this->logger, CONTROL, "received stroke: loglevel for %s", msg->loglevel.context);
	
	context = get_context(msg->loglevel.context);
	if (context == -2)
	{
		this->stroke_logger->log(this->stroke_logger, ERROR, "invalid context (%s)!", msg->loglevel.context);
		return;
	}
	
	if (msg->loglevel.level == 0)
		level = LEVEL0;
	else if (msg->loglevel.level == 1)
		level = LEVEL1;
	else if (msg->loglevel.level == 2)
		level = LEVEL2;
	else if (msg->loglevel.level == 3)
		level = LEVEL3;
	else 
	{
		this->stroke_logger->log(this->stroke_logger, ERROR, "invalid level (%d)!", msg->loglevel.level);
		return;
	}
	
	logger_manager->enable_log_level(logger_manager, context, level);
}

/**
 * Implementation of private_stroke_t.stroke_receive.
 */
static void stroke_receive(private_stroke_t *this)
{
	stroke_msg_t *msg;
	u_int16_t msg_length;
	struct sockaddr_un strokeaddr;
	int strokeaddrlen = sizeof(strokeaddr);
	ssize_t bytes_read;
	int strokefd;
	FILE *strokefile;
	int oldstate;
	
	/* disable cancellation by default */
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
	
	while (1)
	{
		/* wait for connections, but allow thread to terminate */
		pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &oldstate);
		strokefd = accept(this->socket, (struct sockaddr *)&strokeaddr, &strokeaddrlen);
		pthread_setcancelstate(oldstate, NULL);
		
		if (strokefd < 0)
		{
			this->logger->log(this->logger, ERROR, "accepting stroke connection failed: %s", strerror(errno));
			continue;
		}
		
		/* peek the length */
		bytes_read = recv(strokefd, &msg_length, sizeof(msg_length), MSG_PEEK);
		if (bytes_read != sizeof(msg_length))
		{
			this->logger->log(this->logger, ERROR, "reading lenght of stroke message failed");
			close(strokefd);
			continue;
		}
		
		/* read message */
		msg = malloc(msg_length);
		bytes_read = recv(strokefd, msg, msg_length, 0);
		if (bytes_read != msg_length)
		{
			this->logger->log(this->logger, ERROR, "reading stroke message failed: %s");
			close(strokefd);
			continue;
		}
		
		strokefile = fdopen(dup(strokefd), "w");
		if (strokefile == NULL)
		{
			this->logger->log(this->logger, ERROR, "opening stroke output channel failed:", strerror(errno));
			close(strokefd);
			free(msg);
			continue;
		}
		
		/* setup a logger which writes status to the unix socket */
		this->stroke_logger = logger_create("", CONTROL|ERROR, FALSE, strokefile);
		
		this->logger->log_bytes(this->logger, RAW, "stroke message", (void*)msg, msg_length);
		
		switch (msg->type)
		{
			case STR_INITIATE:
				stroke_initiate(this, msg);
				break;
			case STR_ROUTE:
				stroke_route(this, msg, TRUE);
				break;
			case STR_UNROUTE:
				stroke_route(this, msg, FALSE);
				break;
			case STR_TERMINATE:
				stroke_terminate(this, msg);
				break;
			case STR_STATUS:
				stroke_status(this, msg);
				break;
			case STR_STATUS_ALL:
				this->stroke_logger->enable_level(this->stroke_logger, LEVEL1);
				stroke_status(this, msg);
				break;
			case STR_ADD_CONN:
				stroke_add_conn(this, msg);
				break;
			case STR_DEL_CONN:
				stroke_del_conn(this, msg);
				break;
			case STR_LOGTYPE:
				stroke_logtype(this, msg);
				break;
			case STR_LOGLEVEL:
				stroke_loglevel(this, msg);
				break;
			case STR_LIST:
				stroke_list(this, msg);
				break;
			case STR_REREAD:
				stroke_reread(this, msg);
				break;
			default:
				this->logger->log(this->logger, ERROR, "received invalid stroke");
		}
		this->stroke_logger->destroy(this->stroke_logger);
		fclose(strokefile);
		close(strokefd);
		free(msg);
	}
}

/**
 * Implementation of stroke_t.destroy.
 */
static void destroy(private_stroke_t *this)
{
	
	pthread_cancel(this->assigned_thread);
	pthread_join(this->assigned_thread, NULL);

	close(this->socket);
	unlink(socket_addr.sun_path);
	free(this);
}


/*
 * Described in header-file
 */
stroke_t *stroke_create()
{
	private_stroke_t *this = malloc_thing(private_stroke_t);
	mode_t old;

	/* public functions */
	this->public.destroy = (void (*)(stroke_t*))destroy;
	
	/* private functions */
	this->stroke_receive = stroke_receive;
	
	this->logger = logger_manager->get_logger(logger_manager, CONFIG);
	
	/* set up unix socket */
	this->socket = socket(AF_UNIX, SOCK_STREAM, 0);
	if (this->socket == -1)
	{
		this->logger->log(this->logger, ERROR, "could not create whack socket");
		free(this);
		return NULL;
	}
	
	old = umask(~S_IRWXU);
	if (bind(this->socket, (struct sockaddr *)&socket_addr, sizeof(socket_addr)) < 0)
	{
		this->logger->log(this->logger, ERROR, "could not bind stroke socket: %s", strerror(errno));
		close(this->socket);
		free(this);
		return NULL;
	}
	umask(old);
	
	if (listen(this->socket, 0) < 0)
	{
		this->logger->log(this->logger, ERROR, "could not listen on stroke socket: %s", strerror(errno));
		close(this->socket);
		unlink(socket_addr.sun_path);
		free(this);
		return NULL;
	}
	
	/* start a thread reading from the socket */
	if (pthread_create(&(this->assigned_thread), NULL, (void*(*)(void*))this->stroke_receive, this) != 0)
	{
		this->logger->log(this->logger, ERROR, "Could not spawn stroke thread");
		close(this->socket);
		unlink(socket_addr.sun_path);
		free(this);
		return NULL;
	}
	
	return (&this->public);
}
