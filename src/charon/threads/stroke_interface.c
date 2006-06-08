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
#include <queues/jobs/initiate_ike_sa_job.h>

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
	 * Thread which reads from the socket
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
static void load_end_certificate(const char *filename, identification_t **idp)
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

		if (!id->equals(id, subject) && !cert->equals_subjectAltName(cert, id))
		{
			id->destroy(id);
			id = subject;
			*idp = id->clone(id);
		}
		charon->credentials->add_certificate(charon->credentials, cert);
	}
}

/**
 * Add a connection to the configuration list
 */
static void stroke_add_conn(private_stroke_t *this, stroke_msg_t *msg)
{
	connection_t *connection;
	policy_t *policy;
	identification_t *my_id, *other_id;
	host_t *my_host, *other_host, *my_subnet, *other_subnet;
	proposal_t *proposal;
	traffic_selector_t *my_ts, *other_ts;
				
	pop_string(msg, &msg->add_conn.name);
	pop_string(msg, &msg->add_conn.me.address);
	pop_string(msg, &msg->add_conn.other.address);
	pop_string(msg, &msg->add_conn.me.id);
	pop_string(msg, &msg->add_conn.other.id);
	pop_string(msg, &msg->add_conn.me.cert);
	pop_string(msg, &msg->add_conn.other.cert);
	pop_string(msg, &msg->add_conn.me.subnet);
	pop_string(msg, &msg->add_conn.other.subnet);
				
	this->logger->log(this->logger, CONTROL, "received stroke: add connection \"%s\"", msg->add_conn.name);
				
	my_host = msg->add_conn.me.address?
			  host_create(AF_INET, msg->add_conn.me.address, IKE_PORT) : NULL;
	if (my_host == NULL)
	{
		this->stroke_logger->log(this->stroke_logger, ERROR, "invalid host: %s", msg->add_conn.me.address);
		return;
	}

	other_host = msg->add_conn.other.address ?
				 host_create(AF_INET, msg->add_conn.other.address, IKE_PORT) : NULL;
	if (other_host == NULL)
	{
		this->stroke_logger->log(this->stroke_logger, ERROR, "invalid host: %s", msg->add_conn.other.address);
		my_host->destroy(my_host);
		return;
	}

	my_id = identification_create_from_string(msg->add_conn.me.id ?
											  msg->add_conn.me.id : msg->add_conn.me.address);
	if (my_id == NULL)
	{
		this->stroke_logger->log(this->stroke_logger, ERROR, "invalid id: %s", msg->add_conn.me.id);
		my_host->destroy(my_host);
		other_host->destroy(other_host);
		return;
	}

	other_id = identification_create_from_string(msg->add_conn.other.id ?
												 msg->add_conn.other.id : msg->add_conn.other.address);
	if (other_id == NULL)
	{
		my_host->destroy(my_host);
		other_host->destroy(other_host);
		my_id->destroy(my_id);
		this->stroke_logger->log(this->stroke_logger, ERROR, "invalid id: %s", msg->add_conn.other.id);
		return;
	}
	
	my_subnet = host_create(AF_INET, msg->add_conn.me.subnet ?
									 msg->add_conn.me.subnet : msg->add_conn.me.address, IKE_PORT);
	if (my_subnet == NULL)
	{
		my_host->destroy(my_host);
		other_host->destroy(other_host);
		my_id->destroy(my_id);
		other_id->destroy(other_id);
		this->stroke_logger->log(this->stroke_logger, ERROR, "invalid subnet: %s", msg->add_conn.me.subnet);
		return;
	}
	
	other_subnet = host_create(AF_INET, msg->add_conn.other.subnet ?
										msg->add_conn.other.subnet : msg->add_conn.other.address, IKE_PORT);
	if (other_subnet == NULL)
	{
		my_host->destroy(my_host);
		other_host->destroy(other_host);
		my_id->destroy(my_id);
		other_id->destroy(other_id);
		my_subnet->destroy(my_subnet);
		this->stroke_logger->log(this->stroke_logger, ERROR, "invalid subnet: %s", msg->add_conn.me.subnet);
		return;
	}
				
	my_ts = traffic_selector_create_from_subnet(my_subnet, msg->add_conn.me.subnet ?
														   msg->add_conn.me.subnet_mask : 32);
	my_subnet->destroy(my_subnet);

	other_ts = traffic_selector_create_from_subnet(other_subnet, msg->add_conn.other.subnet ?
																 msg->add_conn.other.subnet_mask : 32);
	other_subnet->destroy(other_subnet);
				
	if (charon->socket->is_listening_on(charon->socket, other_host))
	{
		this->stroke_logger->log(this->stroke_logger, CONTROL|LEVEL1, "left is other host, switching");
		
		host_t *tmp_host;
		identification_t *tmp_id;
		traffic_selector_t *tmp_ts;
		char *tmp_cert;
		
		tmp_host   = my_host;
		my_host    = other_host;
		other_host = tmp_host;

		tmp_id   = my_id;
		my_id    = other_id;
		other_id = tmp_id;

		tmp_ts   = my_ts;
		my_ts    = other_ts;
		other_ts = tmp_ts;

        tmp_cert                 = msg->add_conn.me.cert;
		msg->add_conn.me.cert    = msg->add_conn.other.cert;
		msg->add_conn.other.cert = tmp_cert;
	}
	else if (charon->socket->is_listening_on(charon->socket, my_host))
	{
		this->stroke_logger->log(this->stroke_logger, CONTROL|LEVEL1, "left is own host, not switching");
	}
	else
	{
		this->stroke_logger->log(this->stroke_logger, ERROR, "left nor right host is our, aborting");
		
		my_host->destroy(my_host);
		other_host->destroy(other_host);
		my_id->destroy(my_id);
		other_id->destroy(other_id);
		my_ts->destroy(my_ts);
		other_ts->destroy(other_ts);
		return;
	}
	
	if (msg->add_conn.me.cert)
	{
		load_end_certificate(msg->add_conn.me.cert, &my_id);
	}
	if (msg->add_conn.other.cert)
	{
		load_end_certificate(msg->add_conn.other.cert, &other_id);
	}
	
	connection = connection_create(msg->add_conn.name, msg->add_conn.ikev2,
								   my_host, other_host,
								   RSA_DIGITAL_SIGNATURE);
	proposal = proposal_create(PROTO_IKE);
	proposal->add_algorithm(proposal, ENCRYPTION_ALGORITHM, ENCR_AES_CBC, 16);
	proposal->add_algorithm(proposal, INTEGRITY_ALGORITHM, AUTH_HMAC_SHA1_96, 0);
	proposal->add_algorithm(proposal, INTEGRITY_ALGORITHM, AUTH_HMAC_MD5_96, 0);
	proposal->add_algorithm(proposal, PSEUDO_RANDOM_FUNCTION, PRF_HMAC_SHA1, 0);
	proposal->add_algorithm(proposal, PSEUDO_RANDOM_FUNCTION, PRF_HMAC_MD5, 0);
	proposal->add_algorithm(proposal, DIFFIE_HELLMAN_GROUP, MODP_2048_BIT, 0);
	proposal->add_algorithm(proposal, DIFFIE_HELLMAN_GROUP, MODP_1536_BIT, 0);
	proposal->add_algorithm(proposal, DIFFIE_HELLMAN_GROUP, MODP_1024_BIT, 0);
	proposal->add_algorithm(proposal, DIFFIE_HELLMAN_GROUP, MODP_4096_BIT, 0);
	proposal->add_algorithm(proposal, DIFFIE_HELLMAN_GROUP, MODP_8192_BIT, 0);
	connection->add_proposal(connection, proposal);
	
	/* add to global connection list */
	charon->connections->add_connection(charon->connections, connection);
	this->logger->log(this->logger, CONTROL, "added connection \"%s\": %s[%s]...%s[%s]",
					  msg->add_conn.name,
					  my_host->get_address(my_host),
					  my_id->get_string(my_id),
					  other_host->get_address(other_host),
					  other_id->get_string(other_id));
	
	policy = policy_create(msg->add_conn.name, my_id, other_id);
	proposal = proposal_create(PROTO_ESP);
	proposal->add_algorithm(proposal, ENCRYPTION_ALGORITHM, ENCR_AES_CBC, 16);
	proposal->add_algorithm(proposal, INTEGRITY_ALGORITHM, AUTH_HMAC_SHA1_96, 0);
	policy->add_proposal(policy, proposal);
	policy->add_my_traffic_selector(policy, my_ts);
	policy->add_other_traffic_selector(policy, other_ts);

	/* add to global policy list */
	charon->policies->add_policy(charon->policies, policy);
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
	initiate_ike_sa_job_t *job;
	connection_t *connection;
	linked_list_t *ike_sas;
	ike_sa_id_t *ike_sa_id;
	
	pop_string(msg, &(msg->initiate.name));
	this->logger->log(this->logger, CONTROL, "received stroke: initiate \"%s\"", msg->initiate.name);
	connection = charon->connections->get_connection_by_name(charon->connections, msg->initiate.name);
	if (connection == NULL)
	{
		this->stroke_logger->log(this->stroke_logger, ERROR, "no connection named \"%s\"", msg->initiate.name);
	}
	/* only initiate if it is an IKEv2 connection, ignore IKEv1 */
	else if (connection->is_ikev2(connection))
	{
		/* check for already set up IKE_SAs befor initiating */
		ike_sas = charon->ike_sa_manager->get_ike_sa_list_by_name(charon->ike_sa_manager, msg->initiate.name);
		if (ike_sas->get_count(ike_sas) == 0)
		{
			this->stroke_logger->log(this->stroke_logger, CONTROL, "initiating connection \"%s\" (see log)...", msg->initiate.name);
			job = initiate_ike_sa_job_create(connection);
			charon->job_queue->add(charon->job_queue, (job_t*)job);
		}
		else
		{
			this->stroke_logger->log(this->stroke_logger, CONTROL, "connection \"%s\" already up", msg->initiate.name);
		}
		while (ike_sas->remove_last(ike_sas, (void**)&ike_sa_id) == SUCCESS)
		{
			ike_sa_id->destroy(ike_sa_id);
		}
		ike_sas->destroy(ike_sas);
	}
}

/**
 * terminate a connection by name
 */
static void stroke_terminate(private_stroke_t *this, stroke_msg_t *msg)
{
	linked_list_t *ike_sas;
	iterator_t *iterator;
	int instances = 0;
	connection_t *conn;
	
	pop_string(msg, &(msg->terminate.name));
	this->logger->log(this->logger, CONTROL, "received stroke: terminate \"%s\"", msg->terminate.name);
	
	/* we have to do tricky tricks to give the most comprehensive output to the user.
	 * There are different cases:
	 * 1. Connection is available, but IKEv1:
	 *    => just ignore it, let pluto print it
	 * 2. Connection is not available, but instances of a deleted connection template:
	 *    => terminate them, and print their termination
	 * 3. Connection is not available, and and no instances are there:
	 *    => show error about bad connection name
	 * 4. An IKEv2 connection is available, and may contain instances:
	 *    => terminate and print, simple
	 */
	conn = charon->connections->get_connection_by_name(charon->connections, msg->terminate.name);
	if (conn == NULL || conn->is_ikev2(conn))
	{
		ike_sas = charon->ike_sa_manager->get_ike_sa_list_by_name(charon->ike_sa_manager, msg->terminate.name);
		
		iterator = ike_sas->create_iterator(ike_sas, TRUE);
		while (iterator->has_next(iterator))
		{
			ike_sa_id_t *ike_sa_id;
			iterator->current(iterator, (void**)&ike_sa_id);
			charon->ike_sa_manager->delete(charon->ike_sa_manager, ike_sa_id);
			ike_sa_id->destroy(ike_sa_id);
			instances++;
		}
		iterator->destroy(iterator);
		ike_sas->destroy(ike_sas);
		if (conn == NULL && instances == 0)
		{
			this->stroke_logger->log(this->stroke_logger, CONTROL, 
									 "no connection named \"%s\"", 
									 msg->terminate.name);
		}
		else
		{
			this->stroke_logger->log(this->stroke_logger, CONTROL, 
									 "terminated %d instances of \"%s\"", 
									 instances, msg->terminate.name);
		}
	}
	if (conn)
	{
		conn->destroy(conn);
	}
}

/**
 * show status of (established) connections
 */
static void stroke_status(private_stroke_t *this, stroke_msg_t *msg)
{
	if (msg->status.name)
	{
		pop_string(msg, &(msg->status.name));
	}
	charon->connections->log_connections(charon->connections, this->stroke_logger, msg->status.name);
	charon->ike_sa_manager->log_status(charon->ike_sa_manager, this->stroke_logger, msg->status.name);
}

/**
 * list various information
 */
static void stroke_list(private_stroke_t *this, stroke_msg_t *msg, bool utc)
{
	if (msg->type == STR_LIST_CERTS)
	{
		charon->credentials->log_certificates(charon->credentials, this->stroke_logger, utc);
		charon->credentials->log_ca_certificates(charon->credentials, this->stroke_logger, utc);
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
			case STR_LIST_CERTS:
				stroke_list(this, msg, FALSE);
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
