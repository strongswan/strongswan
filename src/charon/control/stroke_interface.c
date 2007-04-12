/**
 * @file stroke_interface.c
 * 
 * @brief Implementation of stroke_interface_t.
 * 
 */

/*
 * Copyright (C) 2006-2007 Martin Willi
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
#include <signal.h>

#include "stroke_interface.h"

#include <library.h>
#include <stroke.h>
#include <daemon.h>
#include <crypto/x509.h>
#include <crypto/ca.h>
#include <crypto/crl.h>
#include <processing/jobs/initiate_job.h>
#include <processing/jobs/route_job.h>
#include <utils/leak_detective.h>

#define IKE_PORT	500
#define PATH_BUF	256
#define STROKE_THREADS 3

struct sockaddr_un socket_addr = { AF_UNIX, STROKE_SOCKET};


typedef struct private_stroke_interface_t private_stroke_interface_t;

/**
 * Private data of an stroke_t object.
 */
struct private_stroke_interface_t {

	/**
	 * Public part of stroke_t object.
	 */
	stroke_t public;
	
	/**
	 * backend to store configurations
	 */
	local_backend_t *backend;
		
	/**
	 * Unix socket to listen for strokes
	 */
	int socket;
	
	/**
	 * Thread which reads from the Socket
	 */
	pthread_t threads[STROKE_THREADS];
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
	|| (unsigned long)*string < (unsigned long)((char*)msg->buffer - (char*)msg)
	|| (unsigned long)*string > msg->length)
	{
		*string = "(invalid pointer in stroke msg)";
	}
	else
	{
		*string = (char*)msg + (unsigned long)*string;
	}
}

/**
 * Load end entitity certificate
 */
static x509_t* load_end_certificate(const char *filename, identification_t **idp)
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

	cert = x509_create_from_file(path, "end entity");

	if (cert)
	{
		identification_t *id = *idp;
		identification_t *subject = cert->get_subject(cert);

		err_t ugh = cert->is_valid(cert, NULL);

		if (ugh != NULL)	
		{
			DBG1(DBG_CFG, "warning: certificate %s", ugh);
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
 * Load ca certificate
 */
static x509_t* load_ca_certificate(const char *filename)
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
		snprintf(path, sizeof(path), "%s/%s", CA_CERTIFICATE_DIR, filename);
	}

	cert = x509_create_from_file(path, "ca");

	if (cert)
	{
		if (cert->is_ca(cert))
		{
			return charon->credentials->add_auth_certificate(charon->credentials, cert, AUTH_CA);
		}
		else
		{
			DBG1(DBG_CFG, "  CA basic constraints flag not set, cert discarded");
			cert->destroy(cert);
		}
	}
	return NULL;
}

/**
 * Add a connection to the configuration list
 */
static void stroke_add_conn(private_stroke_interface_t *this,
							stroke_msg_t *msg, FILE *out)
{
	ike_cfg_t *ike_cfg;
	peer_cfg_t *peer_cfg;
	child_cfg_t *child_cfg;
	identification_t *my_id, *other_id;
	identification_t *my_ca = NULL;
	identification_t *other_ca = NULL;
	bool my_ca_same = FALSE;
	bool other_ca_same =FALSE;
	host_t *my_host, *other_host, *my_subnet, *other_subnet;
	host_t *my_vip = NULL, *other_vip = NULL;
	proposal_t *proposal;
	traffic_selector_t *my_ts, *other_ts;
	char *interface;
	bool use_existing = FALSE;
	iterator_t *iterator;
	
	pop_string(msg, &msg->add_conn.name);
	pop_string(msg, &msg->add_conn.me.address);
	pop_string(msg, &msg->add_conn.other.address);
	pop_string(msg, &msg->add_conn.me.subnet);
	pop_string(msg, &msg->add_conn.other.subnet);
	pop_string(msg, &msg->add_conn.me.sourceip);
	pop_string(msg, &msg->add_conn.other.sourceip);
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
	
	DBG1(DBG_CFG, "received stroke: add connection '%s'", msg->add_conn.name);
	
	DBG2(DBG_CFG, "conn %s", msg->add_conn.name);
	DBG2(DBG_CFG, "  left=%s", msg->add_conn.me.address);
	DBG2(DBG_CFG, "  right=%s", msg->add_conn.other.address);
	DBG2(DBG_CFG, "  leftsubnet=%s", msg->add_conn.me.subnet);
	DBG2(DBG_CFG, "  rightsubnet=%s", msg->add_conn.other.subnet);
	DBG2(DBG_CFG, "  leftsourceip=%s", msg->add_conn.me.sourceip);
	DBG2(DBG_CFG, "  rightsourceip=%s", msg->add_conn.other.sourceip);
	DBG2(DBG_CFG, "  leftid=%s", msg->add_conn.me.id);
	DBG2(DBG_CFG, "  rightid=%s", msg->add_conn.other.id);
	DBG2(DBG_CFG, "  leftcert=%s", msg->add_conn.me.cert);
	DBG2(DBG_CFG, "  rightcert=%s", msg->add_conn.other.cert);
	DBG2(DBG_CFG, "  leftca=%s", msg->add_conn.me.ca);
	DBG2(DBG_CFG, "  rightca=%s", msg->add_conn.other.ca);
	DBG2(DBG_CFG, "  ike=%s", msg->add_conn.algorithms.ike);
	DBG2(DBG_CFG, "  esp=%s", msg->add_conn.algorithms.esp);
	
	my_host = msg->add_conn.me.address?
			  host_create_from_string(msg->add_conn.me.address, IKE_PORT) : NULL;
	if (my_host == NULL)
	{
		DBG1(DBG_CFG, "invalid host: %s\n", msg->add_conn.me.address);
		return;
	}

	other_host = msg->add_conn.other.address ?
			host_create_from_string(msg->add_conn.other.address, IKE_PORT) : NULL;
	if (other_host == NULL)
	{
		DBG1(DBG_CFG, "invalid host: %s\n", msg->add_conn.other.address);
		my_host->destroy(my_host);
		return;
	}
	
	interface = charon->kernel_interface->get_interface(charon->kernel_interface, 
														other_host);
	if (interface)
	{
		stroke_end_t tmp_end;
		host_t *tmp_host;

		DBG2(DBG_CFG, "left is other host, swapping ends\n");

		tmp_host = my_host;
		my_host = other_host;
		other_host = tmp_host;

		tmp_end = msg->add_conn.me;
		msg->add_conn.me = msg->add_conn.other;
		msg->add_conn.other = tmp_end;
		free(interface);
	}
	if (!interface)
	{
		interface = charon->kernel_interface->get_interface(
											charon->kernel_interface, my_host);
		if (!interface)
		{
			DBG1(DBG_CFG, "left nor right host is our side, aborting\n");
			goto destroy_hosts;
		}
		free(interface);
	}

	my_id = identification_create_from_string(msg->add_conn.me.id ?
						msg->add_conn.me.id : msg->add_conn.me.address);
	if (my_id == NULL)
	{
		DBG1(DBG_CFG, "invalid ID: %s\n", msg->add_conn.me.id);
		goto destroy_hosts;
	}

	other_id = identification_create_from_string(msg->add_conn.other.id ?
						msg->add_conn.other.id : msg->add_conn.other.address);
	if (other_id == NULL)
	{
		DBG1(DBG_CFG, "invalid ID: %s\n", msg->add_conn.other.id);
		my_id->destroy(my_id);
		goto destroy_hosts;
	}
	
	my_subnet = host_create_from_string(msg->add_conn.me.subnet ?
					msg->add_conn.me.subnet : msg->add_conn.me.address, IKE_PORT);
	if (my_subnet == NULL)
	{
		DBG1(DBG_CFG, "invalid subnet: %s\n", msg->add_conn.me.subnet);
		goto destroy_ids;
	}
	
	other_subnet = host_create_from_string(msg->add_conn.other.subnet ?
					msg->add_conn.other.subnet : msg->add_conn.other.address, IKE_PORT);
	if (other_subnet == NULL)
	{
		DBG1(DBG_CFG, "invalid subnet: %s\n", msg->add_conn.me.subnet);
		my_subnet->destroy(my_subnet);
		goto destroy_ids;
	}
	
	if (msg->add_conn.me.virtual_ip)
	{
		my_vip = host_create_from_string(msg->add_conn.me.sourceip, 0);
	}
	other_vip = host_create_from_string(msg->add_conn.other.sourceip, 0);
	
	if (msg->add_conn.me.tohost)
	{
		my_ts = traffic_selector_create_dynamic(msg->add_conn.me.protocol,
					my_host->get_family(my_host) == AF_INET ?
						TS_IPV4_ADDR_RANGE : TS_IPV6_ADDR_RANGE,
					msg->add_conn.me.port ? msg->add_conn.me.port : 0,
					msg->add_conn.me.port ? msg->add_conn.me.port : 65535);
	}
	else
	{
		my_ts = traffic_selector_create_from_subnet(my_subnet,
				msg->add_conn.me.subnet ?  msg->add_conn.me.subnet_mask : 0,
				msg->add_conn.me.protocol, msg->add_conn.me.port);
	}
	my_subnet->destroy(my_subnet);
	
	if (msg->add_conn.other.tohost)
	{
		other_ts = traffic_selector_create_dynamic(msg->add_conn.other.protocol,
					other_host->get_family(other_host) == AF_INET ?
						TS_IPV4_ADDR_RANGE : TS_IPV6_ADDR_RANGE,
					msg->add_conn.other.port ? msg->add_conn.other.port : 0,
					msg->add_conn.other.port ? msg->add_conn.other.port : 65535);
	}
	else
	{
		other_ts = traffic_selector_create_from_subnet(other_subnet, 
				msg->add_conn.other.subnet ?  msg->add_conn.other.subnet_mask : 0,
				msg->add_conn.other.protocol, msg->add_conn.other.port);
	}
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
		x509_t *cert = load_end_certificate(msg->add_conn.me.cert, &my_id);

		if (my_ca == NULL && !my_ca_same && cert)
		{
			identification_t *issuer = cert->get_issuer(cert);

			my_ca = issuer->clone(issuer);
		}
	}
	if (msg->add_conn.other.cert)
	{
		x509_t *cert = load_end_certificate(msg->add_conn.other.cert, &other_id);

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
	DBG2(DBG_CFG, "  my ca:   '%D'", my_ca);
	DBG2(DBG_CFG, "  other ca:'%D'", other_ca);
	DBG2(DBG_CFG, "  updown: '%s'", msg->add_conn.me.updown);

	/* have a look for an (almost) identical peer config to reuse */
	iterator = this->backend->create_peer_cfg_iterator(this->backend);
	while (iterator->iterate(iterator, (void**)&peer_cfg))
	{
		ike_cfg = peer_cfg->get_ike_cfg(peer_cfg);
		if (my_id->equals(my_id, peer_cfg->get_my_id(peer_cfg)) &&
			other_id->equals(other_id, peer_cfg->get_other_id(peer_cfg)) &&
			my_host->equals(my_host, ike_cfg->get_my_host(ike_cfg)) &&
			other_host->equals(other_host, ike_cfg->get_other_host(ike_cfg)) &&
			peer_cfg->get_ike_version(peer_cfg) == (msg->add_conn.ikev2 ? 2 : 1) &&
			peer_cfg->get_auth_method(peer_cfg) == msg->add_conn.auth_method &&
			peer_cfg->get_eap_type(peer_cfg) == msg->add_conn.eap_type)
		{
			DBG1(DBG_CFG, "reusing existing configuration '%s'",
				 peer_cfg->get_name(peer_cfg));
			use_existing = TRUE;
			break;
		}
	}
	iterator->destroy(iterator);

	if (use_existing)
	{
		DESTROY_IF(my_vip);
		DESTROY_IF(other_vip);
		my_host->destroy(my_host);
		my_id->destroy(my_id);
		my_ca->destroy(my_ca);
		other_host->destroy(other_host);
		other_id->destroy(other_id);
		other_ca->destroy(other_ca);
	}
	else
	{
		ike_cfg = ike_cfg_create(msg->add_conn.other.sendcert != CERT_NEVER_SEND,
								 my_host, other_host);

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
					DBG1(DBG_CFG, "invalid IKE proposal string: %s", proposal_string);
					my_id->destroy(my_id);
					other_id->destroy(other_id);
					my_ts->destroy(my_ts);
					other_ts->destroy(other_ts);
					my_ca->destroy(my_ca);
					other_ca->destroy(other_ca);
					ike_cfg->destroy(ike_cfg);
					return;
				}
				ike_cfg->add_proposal(ike_cfg, proposal);
			}
			if (!strict)
			{
				proposal = proposal_create_default(PROTO_IKE);
				ike_cfg->add_proposal(ike_cfg, proposal);
			}
		}
		else
		{
			proposal = proposal_create_default(PROTO_IKE);
			ike_cfg->add_proposal(ike_cfg, proposal);
		}
		
		
		peer_cfg = peer_cfg_create(msg->add_conn.name, msg->add_conn.ikev2 ? 2 : 1,
					ike_cfg, my_id, other_id, my_ca, other_ca, msg->add_conn.me.sendcert, 
					msg->add_conn.auth_method, msg->add_conn.eap_type,
					msg->add_conn.rekey.tries, msg->add_conn.rekey.ike_lifetime,
					msg->add_conn.rekey.ike_lifetime - msg->add_conn.rekey.margin,
					msg->add_conn.rekey.margin * msg->add_conn.rekey.fuzz / 100, 
					msg->add_conn.rekey.reauth, msg->add_conn.dpd.delay,
					msg->add_conn.dpd.action,my_vip, other_vip);
	}
	
	child_cfg = child_cfg_create(
				msg->add_conn.name, msg->add_conn.rekey.ipsec_lifetime,
				msg->add_conn.rekey.ipsec_lifetime - msg->add_conn.rekey.margin,
				msg->add_conn.rekey.margin * msg->add_conn.rekey.fuzz / 100, 
				msg->add_conn.me.updown, msg->add_conn.me.hostaccess,
				msg->add_conn.mode);
	
	peer_cfg->add_child_cfg(peer_cfg, child_cfg);
	
	child_cfg->add_traffic_selector(child_cfg, TRUE, my_ts);
	child_cfg->add_traffic_selector(child_cfg, FALSE, other_ts);
	
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
				DBG1(DBG_CFG, "invalid ESP proposal string: %s", proposal_string);
				peer_cfg->destroy(peer_cfg);
				return;
			}
			child_cfg->add_proposal(child_cfg, proposal);
		}
		if (!strict)
		{
			proposal = proposal_create_default(PROTO_ESP);
			child_cfg->add_proposal(child_cfg, proposal);
		}
	}
	else
	{
		proposal = proposal_create_default(PROTO_ESP);
		child_cfg->add_proposal(child_cfg, proposal);
	}
	
	if (!use_existing)
	{
		/* add config to backend */
		this->backend->add_peer_cfg(this->backend, peer_cfg);
		DBG1(DBG_CFG, "added configuration '%s': %H[%D]...%H[%D]",
			 msg->add_conn.name, my_host, my_id, other_host, other_id);
	}
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
static void stroke_del_conn(private_stroke_interface_t *this,
							stroke_msg_t *msg, FILE *out)
{
	iterator_t *peer_iter, *child_iter;
	peer_cfg_t *peer, *child;
	
	pop_string(msg, &(msg->del_conn.name));
	DBG1(DBG_CFG, "received stroke: delete connection '%s'", msg->del_conn.name);
	
	peer_iter = this->backend->create_peer_cfg_iterator(this->backend);
	while (peer_iter->iterate(peer_iter, (void**)&peer))
	{
		/* remove peer config with such a name */
		if (streq(peer->get_name(peer), msg->del_conn.name))
		{
			peer_iter->remove(peer_iter);
			peer->destroy(peer);
			continue;
		}
		/* remove any child with such a name */
		child_iter = peer->create_child_cfg_iterator(peer);
		while (child_iter->iterate(child_iter, (void**)&child))
		{
			if (streq(child->get_name(child), msg->del_conn.name))
			{
				child_iter->remove(child_iter);
				child->destroy(child);
			}
		}
		child_iter->destroy(child_iter);
	}
	peer_iter->destroy(peer_iter);
	
	fprintf(out, "deleted connection '%s'\n", msg->del_conn.name);
}

/**
 * get the child_cfg with the same name as the peer cfg
 */
static child_cfg_t* get_child_from_peer(peer_cfg_t *peer_cfg, char *name)
{
	child_cfg_t *current, *found = NULL;
	iterator_t *iterator;
	
	iterator = peer_cfg->create_child_cfg_iterator(peer_cfg);
	while (iterator->iterate(iterator, (void**)&current))
	{
		if (streq(current->get_name(current), name))
		{
			found = current;
			found->get_ref(found);
			break;
		}
	}
	iterator->destroy(iterator);
	return found;
}

/**
 * initiate a connection by name
 */
static void stroke_initiate(private_stroke_interface_t *this,
							stroke_msg_t *msg, FILE *out)
{
	initiate_job_t *job;
	peer_cfg_t *peer_cfg;
	child_cfg_t *child_cfg;
	ike_sa_t *init_ike_sa = NULL;
	signal_t signal;
	
	pop_string(msg, &(msg->initiate.name));
	DBG1(DBG_CFG, "received stroke: initiate '%s'", msg->initiate.name);
	
	peer_cfg = this->backend->get_peer_cfg_by_name(this->backend,
												   msg->initiate.name);
	if (peer_cfg == NULL)
	{
		if (msg->output_verbosity >= 0)
		{
			fprintf(out, "no config named '%s'\n", msg->initiate.name);
		}
		return;
	}
	if (peer_cfg->get_ike_version(peer_cfg) != 2)
	{
		DBG1(DBG_CFG, "ignoring initiation request for IKEv%d config",
			 peer_cfg->get_ike_version(peer_cfg));
		peer_cfg->destroy(peer_cfg);
		return;
	}
	
	child_cfg = get_child_from_peer(peer_cfg, msg->initiate.name);
	if (child_cfg == NULL)
	{
		if (msg->output_verbosity >= 0)
		{
			fprintf(out, "no child config named '%s'\n", msg->initiate.name);
		}
		peer_cfg->destroy(peer_cfg);
		return;
	}
	
	job = initiate_job_create(peer_cfg, child_cfg);
	charon->bus->set_listen_state(charon->bus, TRUE);
	charon->job_queue->add(charon->job_queue, (job_t*)job);
	while (TRUE)
	{
		level_t level;
		int thread;
		ike_sa_t *ike_sa;
		char* format;
		va_list args;
		
		signal = charon->bus->listen(charon->bus, &level, &thread, &ike_sa, &format, &args);
		
		if ((init_ike_sa == NULL || ike_sa == init_ike_sa) &&
			level <= msg->output_verbosity)
		{
			if (vfprintf(out, format, args) < 0 ||
				fprintf(out, "\n") < 0 ||
				fflush(out))
			{
				charon->bus->set_listen_state(charon->bus, FALSE);
				break;
			}
		}
		
		switch (signal)
		{
			case CHILD_UP_SUCCESS:
			case CHILD_UP_FAILED:
			case IKE_UP_FAILED:
				if (ike_sa == init_ike_sa)
				{
					charon->bus->set_listen_state(charon->bus, FALSE);
					return;
				}
				continue;
			case CHILD_UP_START:
			case IKE_UP_START:
				if (init_ike_sa == NULL)
				{
					init_ike_sa = ike_sa;
				}
				continue;
			default:
				continue;
		}
	}
}

/**
 * route/unroute a policy (install SPD entries)
 */
static void stroke_route(private_stroke_interface_t *this,
						 stroke_msg_t *msg, FILE *out, bool route)
{
	route_job_t *job;
	peer_cfg_t *peer_cfg;
	child_cfg_t *child_cfg;
	
	pop_string(msg, &(msg->route.name));
	DBG1(DBG_CFG, "received stroke: %s '%s'",
		 route ? "route" : "unroute", msg->route.name);
	
	peer_cfg = this->backend->get_peer_cfg_by_name(this->backend, msg->route.name);
	if (peer_cfg == NULL)
	{
		fprintf(out, "no config named '%s'\n", msg->route.name);
		return;
	}
	if (peer_cfg->get_ike_version(peer_cfg) != 2)
	{
		peer_cfg->destroy(peer_cfg);
		return;
	}
	
	child_cfg = get_child_from_peer(peer_cfg, msg->route.name);
	if (child_cfg == NULL)
	{
		fprintf(out, "no child config named '%s'\n", msg->route.name);
		peer_cfg->destroy(peer_cfg);
		return;
	}
	fprintf(out, "%s policy '%s'\n",
			route ? "routing" : "unrouting", msg->route.name);
	job = route_job_create(peer_cfg, child_cfg, route);
	charon->job_queue->add(charon->job_queue, (job_t*)job);
}

/**
 * terminate a connection by name
 */
static void stroke_terminate(private_stroke_interface_t *this,
							 stroke_msg_t *msg, FILE *out)
{
	char *string, *pos = NULL, *name = NULL;
	u_int32_t id = 0;
	bool child;
	int len;
	status_t status = SUCCESS;;
	ike_sa_t *ike_sa;
	
	pop_string(msg, &(msg->terminate.name));
	string = msg->terminate.name;
	DBG1(DBG_CFG, "received stroke: terminate '%s'", string);
	
	len = strlen(string);
	if (len < 1)
	{
		DBG1(DBG_CFG, "error parsing string");
		return;
	}
	switch (string[len-1])
	{
		case '}':
			child = TRUE;
			pos = strchr(string, '{');
			break;
		case ']':
			child = FALSE;
			pos = strchr(string, '[');
			break;
		default:
			name = string;
			child = FALSE;
			break;
	}
	
	if (name)
	{	/* must be a single name */
		DBG1(DBG_CFG, "check out by single name '%s'", name);
		ike_sa = charon->ike_sa_manager->checkout_by_name(charon->ike_sa_manager,
														  name, child);
	}
	else if (pos == string + len - 2)
	{	/* must be name[] or name{} */
		string[len-2] = '\0';
		DBG1(DBG_CFG, "check out by name '%s'", string);
		ike_sa = charon->ike_sa_manager->checkout_by_name(charon->ike_sa_manager,
														  string, child);
	}
	else
	{	/* must be name[123] or name{23} */
		string[len-1] = '\0';
		id = atoi(pos + 1);
		if (id == 0)
		{
			DBG1(DBG_CFG, "error parsing string");
			return;
		}
		DBG1(DBG_CFG, "check out by id '%d'", id);
		ike_sa = charon->ike_sa_manager->checkout_by_id(charon->ike_sa_manager,
														id, child);
	}
	if (ike_sa == NULL)
	{
		DBG1(DBG_CFG, "no such IKE_SA found");
		return;
	}
	
	if (!child)
	{
		status = ike_sa->delete(ike_sa);
	}
	else
	{
		child_sa_t *child_sa;
		iterator_t *iterator = ike_sa->create_child_sa_iterator(ike_sa);
		while (iterator->iterate(iterator, (void**)&child_sa))
		{
			if ((id && id == child_sa->get_reqid(child_sa)) ||
				(string && streq(string, child_sa->get_name(child_sa))))
			{
				u_int32_t spi = child_sa->get_spi(child_sa, TRUE);
				protocol_id_t proto = child_sa->get_protocol(child_sa);
				
				status = ike_sa->delete_child_sa(ike_sa, proto, spi);
				break;
			}
		}
		iterator->destroy(iterator);
	}
	if (status == DESTROY_ME)
	{
		charon->ike_sa_manager->checkin_and_destroy(charon->ike_sa_manager,
													ike_sa);
		return;
	}
	charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);
}

/**
 * Add a ca information record to the cainfo list
 */
static void stroke_add_ca(private_stroke_interface_t *this,
						  stroke_msg_t *msg, FILE *out)
{
	x509_t *cacert;
	ca_info_t *ca_info;

	pop_string(msg, &msg->add_ca.name);
	pop_string(msg, &msg->add_ca.cacert);
	pop_string(msg, &msg->add_ca.crluri);
	pop_string(msg, &msg->add_ca.crluri2);
	pop_string(msg, &msg->add_ca.ocspuri);
	pop_string(msg, &msg->add_ca.ocspuri2);
	
	DBG1(DBG_CFG, "received stroke: add ca '%s'", msg->add_ca.name);
	
	DBG2(DBG_CFG, "ca %s",        msg->add_ca.name);
	DBG2(DBG_CFG, "  cacert=%s",  msg->add_ca.cacert);
	DBG2(DBG_CFG, "  crluri=%s",  msg->add_ca.crluri);
	DBG2(DBG_CFG, "  crluri2=%s", msg->add_ca.crluri2);
	DBG2(DBG_CFG, "  ocspuri=%s", msg->add_ca.ocspuri);
	DBG2(DBG_CFG, "  ocspuri2=%s", msg->add_ca.ocspuri2);

	if (msg->add_ca.cacert == NULL)
	{
		DBG1(DBG_CFG, "missing cacert parameter\n");
		return;
	}

	cacert = load_ca_certificate(msg->add_ca.cacert);

	if (cacert == NULL)
	{
		return;
	}
	ca_info = ca_info_create(msg->add_ca.name, cacert);

	if (msg->add_ca.crluri)
	{
		chunk_t uri = { msg->add_ca.crluri, strlen(msg->add_ca.crluri) };
		
		ca_info->add_crluri(ca_info, uri);
	}
	if (msg->add_ca.crluri2)
	{
		chunk_t uri = { msg->add_ca.crluri2, strlen(msg->add_ca.crluri2) };
		
		ca_info->add_crluri(ca_info, uri);
	}
	if (msg->add_ca.ocspuri)
	{
		chunk_t uri = { msg->add_ca.ocspuri, strlen(msg->add_ca.ocspuri) };
		
		ca_info->add_ocspuri(ca_info, uri);
	}
	if (msg->add_ca.ocspuri2)
	{
		chunk_t uri = { msg->add_ca.ocspuri2, strlen(msg->add_ca.ocspuri2) };
		
		ca_info->add_ocspuri(ca_info, uri);
	}
	charon->credentials->add_ca_info(charon->credentials, ca_info);
	DBG1(DBG_CFG, "added ca '%s'", msg->add_ca.name);

}

/**
 * Delete a ca information record from the cainfo list
 */
static void stroke_del_ca(private_stroke_interface_t *this,
						  stroke_msg_t *msg, FILE *out)
{
	status_t status;
	
	pop_string(msg, &(msg->del_ca.name));
	DBG1(DBG_CFG, "received stroke: delete ca '%s'", msg->del_ca.name);
	
	status = charon->credentials->release_ca_info(charon->credentials,
												  msg->del_ca.name);

	if (status == SUCCESS)
	{
		fprintf(out, "deleted ca '%s'\n", msg->del_ca.name);
	}
	else
	{
		fprintf(out, "no ca named '%s'\n", msg->del_ca.name);
	}
}

/**
 * log an IKE_SA to out
 */
static void log_ike_sa(FILE *out, ike_sa_t *ike_sa, bool all)
{
	peer_cfg_t *cfg = ike_sa->get_peer_cfg(ike_sa);
	ike_sa_id_t *id = ike_sa->get_id(ike_sa);
	u_int32_t next, now = time(NULL);

	fprintf(out, "%12s[%d]: %N, %H[%D]...%H[%D]\n",
			ike_sa->get_name(ike_sa), ike_sa->get_unique_id(ike_sa),
			ike_sa_state_names, ike_sa->get_state(ike_sa),
			ike_sa->get_my_host(ike_sa), ike_sa->get_my_id(ike_sa),
			ike_sa->get_other_host(ike_sa), ike_sa->get_other_id(ike_sa));
	
	if (all)
	{
		fprintf(out, "%12s[%d]: IKE SPIs: 0x%0llx_i%s 0x%0llx_r%s, ",
				ike_sa->get_name(ike_sa), ike_sa->get_unique_id(ike_sa),
				id->get_initiator_spi(id), id->is_initiator(id) ? "*" : "",
				id->get_responder_spi(id), id->is_initiator(id) ? "" : "");
	
		ike_sa->get_stats(ike_sa, &next);
		if (next)
		{
			fprintf(out, "%s in %V\n", cfg->use_reauth(cfg) ?
					"reauthentication" : "rekeying", &now, &next);
		}
		else
		{
			fprintf(out, "rekeying disabled\n");
		}
	}
}

/**
 * log an CHILD_SA to out
 */
static void log_child_sa(FILE *out, child_sa_t *child_sa, bool all)
{
	u_int32_t rekey, now = time(NULL);
	u_int32_t use_in, use_out, use_fwd;
	encryption_algorithm_t encr_alg;
	integrity_algorithm_t int_alg;
	size_t encr_len, int_len;
	mode_t mode;
	
	child_sa->get_stats(child_sa, &mode, &encr_alg, &encr_len,
						&int_alg, &int_len, &rekey, &use_in, &use_out,
						&use_fwd);
	
	fprintf(out, "%12s{%d}:  %N, %N", 
			child_sa->get_name(child_sa), child_sa->get_reqid(child_sa),
			child_sa_state_names, child_sa->get_state(child_sa),
			mode_names, mode);
	
	if (child_sa->get_state(child_sa) == CHILD_INSTALLED)
	{
		fprintf(out, ", %N SPIs: 0x%0x_i 0x%0x_o",
				protocol_id_names, child_sa->get_protocol(child_sa),
				htonl(child_sa->get_spi(child_sa, TRUE)),
				htonl(child_sa->get_spi(child_sa, FALSE)));
		
		if (all)
		{
			fprintf(out, "\n%12s{%d}:  ", child_sa->get_name(child_sa), 
					child_sa->get_reqid(child_sa));
			
			
			if (child_sa->get_protocol(child_sa) == PROTO_ESP)
			{
				fprintf(out, "%N", encryption_algorithm_names, encr_alg);
				
				if (encr_len)
				{
					fprintf(out, "-%d", encr_len);
				}
				fprintf(out, "/");
			}
			
			fprintf(out, "%N", integrity_algorithm_names, int_alg);
			if (int_len)
			{
				fprintf(out, "-%d", int_len);
			}
			fprintf(out, ", rekeying ");
			
			if (rekey)
			{
				fprintf(out, "in %V", &now, &rekey);
			}
			else
			{
				fprintf(out, "disabled");
			}
			
			fprintf(out, ", last use: ");
			use_in = max(use_in, use_fwd);
			if (use_in)
			{
				fprintf(out, "%ds_i ", now - use_in);
			}
			else
			{
				fprintf(out, "no_i ");
			}
			if (use_out)
			{
				fprintf(out, "%ds_o ", now - use_out);
			}
			else
			{
				fprintf(out, "no_o ");
			}
		}
	}
	
	fprintf(out, "\n%12s{%d}:   %#R=== %#R\n",
			child_sa->get_name(child_sa), child_sa->get_reqid(child_sa),
			child_sa->get_traffic_selectors(child_sa, TRUE),
			child_sa->get_traffic_selectors(child_sa, FALSE));
}

/**
 * show status of daemon
 */
static void stroke_status(private_stroke_interface_t *this,
						  stroke_msg_t *msg, FILE *out, bool all)
{
	iterator_t *iterator, *children;
	linked_list_t *list;
	host_t *host;
	peer_cfg_t *peer_cfg;
	ike_cfg_t *ike_cfg;
	child_cfg_t *child_cfg;
	ike_sa_t *ike_sa;
	char *name = NULL;
	
	if (msg->status.name)
	{
		pop_string(msg, &(msg->status.name));
		name = msg->status.name;
	}
	
	if (all)
	{
		leak_detective_status(out);
	
		fprintf(out, "Performance:\n");
		fprintf(out, "  worker threads: %d idle of %d,",
				charon->thread_pool->get_idle_threads(charon->thread_pool),
				charon->thread_pool->get_pool_size(charon->thread_pool));
		fprintf(out, " job queue load: %d,",
				charon->job_queue->get_count(charon->job_queue));
		fprintf(out, " scheduled events: %d\n",
				charon->event_queue->get_count(charon->event_queue));
		list = charon->kernel_interface->create_address_list(charon->kernel_interface);

		fprintf(out, "Listening on %d IP addresses:\n", list->get_count(list));
		while (list->remove_first(list, (void**)&host) == SUCCESS)
		{
			fprintf(out, "  %H\n", host);
			host->destroy(host);
		}
		list->destroy(list);
	
		fprintf(out, "Connections:\n");
		iterator = this->backend->create_peer_cfg_iterator(this->backend);
		while (iterator->iterate(iterator, (void**)&peer_cfg))
		{
			if (peer_cfg->get_ike_version(peer_cfg) != 2 ||
				(name && !streq(name, peer_cfg->get_name(peer_cfg))))
			{
				continue;
			}
			
			ike_cfg = peer_cfg->get_ike_cfg(peer_cfg);
			fprintf(out, "%12s:  %H[%D]...%H[%D]\n", peer_cfg->get_name(peer_cfg),
					ike_cfg->get_my_host(ike_cfg), peer_cfg->get_my_id(peer_cfg),
					ike_cfg->get_other_host(ike_cfg), peer_cfg->get_other_id(peer_cfg));
			children = peer_cfg->create_child_cfg_iterator(peer_cfg);
			while (children->iterate(children, (void**)&child_cfg))
			{
				linked_list_t *my_ts, *other_ts;
				my_ts = child_cfg->get_traffic_selectors(child_cfg, TRUE, NULL, NULL);
				other_ts = child_cfg->get_traffic_selectors(child_cfg, FALSE, NULL, NULL);
				fprintf(out, "%12s:    %#R=== %#R\n", child_cfg->get_name(child_cfg),
						my_ts, other_ts);
				my_ts->destroy_offset(my_ts, offsetof(traffic_selector_t, destroy));
				other_ts->destroy_offset(other_ts, offsetof(traffic_selector_t, destroy));
			}
			children->destroy(children);
		}
		iterator->destroy(iterator);
	}
	
	iterator = charon->ike_sa_manager->create_iterator(charon->ike_sa_manager);
	if (all && iterator->get_count(iterator) > 0)
	{
		fprintf(out, "Security Associations:\n");
	}
	while (iterator->iterate(iterator, (void**)&ike_sa))
	{
		bool ike_printed = FALSE;
		child_sa_t *child_sa;
		iterator_t *children = ike_sa->create_child_sa_iterator(ike_sa);

		if (name == NULL || streq(name, ike_sa->get_name(ike_sa)))
		{
			log_ike_sa(out, ike_sa, all);
			ike_printed = TRUE;
		}

		while (children->iterate(children, (void**)&child_sa))
		{
			if (name == NULL || streq(name, child_sa->get_name(child_sa)))
			{
				if (!ike_printed)
				{
					log_ike_sa(out, ike_sa, all);
					ike_printed = TRUE;
				}
				log_child_sa(out, child_sa, all);
			}	
		}
		children->destroy(children);
	}
	iterator->destroy(iterator);
}

/**
 * list all authority certificates matching a specified flag 
 */
static void list_auth_certificates(private_stroke_interface_t *this,  u_int flag,
								   const char *label, bool utc, FILE *out)
{
	bool first = TRUE;
	x509_t *cert;
	
	iterator_t *iterator = charon->credentials->create_auth_cert_iterator(charon->credentials);

	while (iterator->iterate(iterator, (void**)&cert))
	{
		if (cert->has_authority_flag(cert, flag))
		{
			if (first)
			{
				fprintf(out, "\n");
				fprintf(out, "List of X.509 %s Certificates:\n", label);
				fprintf(out, "\n");
				first = FALSE;
			}
			cert->list(cert, out, utc);
			fprintf(out, "\n");
		}
	}
	iterator->destroy(iterator);
}

/**
 * list various information
 */
static void stroke_list(private_stroke_interface_t *this, 
						stroke_msg_t *msg, FILE *out)
{
	iterator_t *iterator;
	
	if (msg->list.flags & LIST_CERTS)
	{
		x509_t *cert;
		
		iterator = charon->credentials->create_cert_iterator(charon->credentials);
		if (iterator->get_count(iterator))
		{
			fprintf(out, "\n");
			fprintf(out, "List of X.509 End Entity Certificates:\n");
			fprintf(out, "\n");
		}
		while (iterator->iterate(iterator, (void**)&cert))
		{
			cert->list(cert, out, msg->list.utc);
			if (charon->credentials->has_rsa_private_key(
					charon->credentials, cert->get_public_key(cert)))
			{
				fprintf(out, ", has private key");
			}
			fprintf(out, "\n");
			
		}
		iterator->destroy(iterator);
	}
	if (msg->list.flags & LIST_CACERTS)
	{
		list_auth_certificates(this, AUTH_CA, "CA", msg->list.utc, out);
	}
	if (msg->list.flags & LIST_CAINFOS)
	{
		ca_info_t *ca_info;

		iterator = charon->credentials->create_cainfo_iterator(charon->credentials);
		if (iterator->get_count(iterator))
		{
			fprintf(out, "\n");
			fprintf(out, "List of X.509 CA Information Records:\n");
			fprintf(out, "\n");
		}
		while (iterator->iterate(iterator, (void**)&ca_info))
		{
			ca_info->list(ca_info, out, msg->list.utc);
		}
		iterator->destroy(iterator);
	}
	if (msg->list.flags & LIST_CRLS)
	{
        ca_info_t *ca_info;
        bool first = TRUE;
        
        iterator = charon->credentials->create_cainfo_iterator(charon->credentials);
        while (iterator->iterate(iterator, (void **)&ca_info))
        {
            if (ca_info->has_crl(ca_info))
            {
                if (first)
                {
                    fprintf(out, "\n");
                    fprintf(out, "List of X.509 CRLs:\n");
                    fprintf(out, "\n");
                    first = FALSE;
                }
                ca_info->list_crl(ca_info, out, msg->list.utc);
            }
        }
        iterator->destroy(iterator);
	}
	if (msg->list.flags & LIST_OCSPCERTS)
	{
		list_auth_certificates(this, AUTH_OCSP, "OCSP", msg->list.utc, out);
	}
	if (msg->list.flags & LIST_OCSP)
	{
		ca_info_t *ca_info;
		bool first = TRUE;

        iterator = charon->credentials->create_cainfo_iterator(charon->credentials);
        while (iterator->iterate(iterator, (void **)&ca_info))
        {
            if (ca_info->has_certinfos(ca_info))
            {
                if (first)
                {
                    fprintf(out, "\n");
                    fprintf(out, "List of OCSP responses:\n");
                    first = FALSE;
                }
                fprintf(out, "\n");
                ca_info->list_certinfos(ca_info, out, msg->list.utc);
            }
        }
        iterator->destroy(iterator);
	}
}

/**
 * reread various information
 */
static void stroke_reread(private_stroke_interface_t *this,
						  stroke_msg_t *msg, FILE *out)
{
	if (msg->reread.flags & REREAD_CACERTS)
	{
		charon->credentials->load_ca_certificates(charon->credentials);
	}
	if (msg->reread.flags & REREAD_OCSPCERTS)
	{
		charon->credentials->load_ocsp_certificates(charon->credentials);
	}
	if (msg->reread.flags & REREAD_CRLS)
	{
		charon->credentials->load_crls(charon->credentials);
	}
}

/**
 * purge various information
 */
static void stroke_purge(private_stroke_interface_t *this,
						 stroke_msg_t *msg, FILE *out)
{
	if (msg->purge.flags & PURGE_OCSP)
	{
		iterator_t *iterator = charon->credentials->create_cainfo_iterator(charon->credentials);
		ca_info_t *ca_info;

		while (iterator->iterate(iterator, (void**)&ca_info))
		{
			ca_info->purge_ocsp(ca_info);
		}
		iterator->destroy(iterator);
	}
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
static void stroke_loglevel(private_stroke_interface_t *this,
							stroke_msg_t *msg, FILE *out)
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
 * process a stroke request from the socket pointed by "fd"
 */
static void stroke_process(private_stroke_interface_t *this, int strokefd)
{
	stroke_msg_t *msg;
	u_int16_t msg_length;
	ssize_t bytes_read;
	FILE *out;
	
	/* peek the length */
	bytes_read = recv(strokefd, &msg_length, sizeof(msg_length), MSG_PEEK);
	if (bytes_read != sizeof(msg_length))
	{
		DBG1(DBG_CFG, "reading length of stroke message failed");
		close(strokefd);
		return;
	}
	
	/* read message */
	msg = malloc(msg_length);
	bytes_read = recv(strokefd, msg, msg_length, 0);
	if (bytes_read != msg_length)
	{
		DBG1(DBG_CFG, "reading stroke message failed: %s", strerror(errno));
		close(strokefd);
		return;
	}
	
	out = fdopen(dup(strokefd), "w");
	if (out == NULL)
	{
		DBG1(DBG_CFG, "opening stroke output channel failed: %s", strerror(errno));
		close(strokefd);
		free(msg);
		return;
	}
	
	DBG3(DBG_CFG, "stroke message %b", (void*)msg, msg_length);
	
	switch (msg->type)
	{
		case STR_INITIATE:
			stroke_initiate(this, msg, out);
			break;
		case STR_ROUTE:
			stroke_route(this, msg, out, TRUE);
			break;
		case STR_UNROUTE:
			stroke_route(this, msg, out, FALSE);
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
			stroke_add_conn(this, msg, out);
			break;
		case STR_DEL_CONN:
			stroke_del_conn(this, msg, out);
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
	fclose(out);
	close(strokefd);
	free(msg);
}

/**
 * Implementation of private_stroke_interface_t.stroke_receive.
 */
static void stroke_receive(private_stroke_interface_t *this)
{
	struct sockaddr_un strokeaddr;
	int strokeaddrlen = sizeof(strokeaddr);
	int oldstate;
	int strokefd;
	
	/* ignore sigpipe. writing over the pipe back to the console
	 * only fails if SIGPIPE is ignored. */
	signal(SIGPIPE, SIG_IGN);
	
	/* disable cancellation by default */
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
	
	while (TRUE)
	{
		/* wait for connections, but allow thread to terminate */
		pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &oldstate);
		strokefd = accept(this->socket, (struct sockaddr *)&strokeaddr, &strokeaddrlen);
		pthread_setcancelstate(oldstate, NULL);
		
		if (strokefd < 0)
		{
			DBG1(DBG_CFG, "accepting stroke connection failed: %s", strerror(errno));
			continue;
		}
		stroke_process(this, strokefd);
	}
}

/**
 * Implementation of stroke_t.destroy.
 */
static void destroy(private_stroke_interface_t *this)
{
	int i;
	
	for (i = 0; i < STROKE_THREADS; i++)
	{
		pthread_cancel(this->threads[i]);
		pthread_join(this->threads[i], NULL);
	}

	close(this->socket);
	unlink(socket_addr.sun_path);
	free(this);
}

/*
 * Described in header-file
 */
stroke_t *stroke_create(local_backend_t *backend)
{
	private_stroke_interface_t *this = malloc_thing(private_stroke_interface_t);
	mode_t old;
	int i;

	/* public functions */
	this->public.destroy = (void (*)(stroke_t*))destroy;
	
	this->backend = backend;
	
	/* set up unix socket */
	this->socket = socket(AF_UNIX, SOCK_STREAM, 0);
	if (this->socket == -1)
	{
		DBG1(DBG_CFG, "could not create whack socket");
		free(this);
		return NULL;
	}
	
	old = umask(~S_IRWXU);
	if (bind(this->socket, (struct sockaddr *)&socket_addr, sizeof(socket_addr)) < 0)
	{
		DBG1(DBG_CFG, "could not bind stroke socket: %s", strerror(errno));
		close(this->socket);
		free(this);
		return NULL;
	}
	umask(old);
	
	if (listen(this->socket, 0) < 0)
	{
		DBG1(DBG_CFG, "could not listen on stroke socket: %s", strerror(errno));
		close(this->socket);
		unlink(socket_addr.sun_path);
		free(this);
		return NULL;
	}
	
	/* start threads reading from the socket */
	for (i = 0; i < STROKE_THREADS; i++)
	{
		if (pthread_create(&this->threads[i], NULL, (void*(*)(void*))stroke_receive, this) != 0)
		{
			charon->kill(charon, "unable to create stroke thread");
		}
	}
	
	return (&this->public);
}
