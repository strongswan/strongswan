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
#include <control/interface_manager.h>
#include <control/interfaces/interface.h>
#include <utils/leak_detective.h>
#include <processing/jobs/callback_job.h>

#define IKE_PORT	500
#define PATH_BUF	256
#define STROKE_THREADS 3

struct sockaddr_un socket_addr = { AF_UNIX, STROKE_SOCKET};


typedef struct private_stroke_interface_t private_stroke_interface_t;

/**
 * Private data of an stroke_interfacet object.
 */
struct private_stroke_interface_t {

	/**
	 * Public part of stroke_interfacet object.
	 */
	stroke_interface_t public;
		
	/**
	 * Unix socket to listen for strokes
	 */
	int socket;
	
	/**
	 * job accepting stroke messages
	 */
	callback_job_t *job;
};

typedef struct stroke_log_info_t stroke_log_info_t;

/**
 * helper struct to say what and where to log when using controller callback
 */
struct stroke_log_info_t {

	/**
	 * level to log up to
	 */
	level_t level;
	
	/**
	 * where to write log
	 */
	FILE* out;
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
static void stroke_add_conn(stroke_msg_t *msg, FILE *out)
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
	DBG1(DBG_CFG, "received stroke: add connection '%s'", msg->add_conn.name);
	DBG2(DBG_CFG, "conn %s", msg->add_conn.name);
	pop_end(msg, "left", &msg->add_conn.me);
	pop_end(msg, "right", &msg->add_conn.other);
	pop_string(msg, &msg->add_conn.algorithms.ike);
	pop_string(msg, &msg->add_conn.algorithms.esp);
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
	if (msg->add_conn.other.virtual_ip)
	{
		other_vip = host_create_from_string(msg->add_conn.other.sourceip, 0);
	}
	
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

		if (cert)
		{
			ca_info_t *ca_info;

			if (cert->is_self_signed(cert))
			{
				/* a self-signed certificate is its own ca */
				ca_info = ca_info_create(NULL, cert);
				ca_info = charon->credentials->add_ca_info(charon->credentials, ca_info);
				cert->set_ca_info(cert, ca_info);
			}
			else
			{
				/* get_issuer() automatically sets cert->ca_info */
				ca_info = charon->credentials->get_issuer(charon->credentials, cert);
			}
			if (my_ca == NULL && !my_ca_same)
			{
				identification_t *issuer = cert->get_issuer(cert);

				my_ca = issuer->clone(issuer);
			}
		}
	}
	if (msg->add_conn.other.cert)
	{
		x509_t *cert = load_end_certificate(msg->add_conn.other.cert, &other_id);

		if (cert)
		{
			ca_info_t *ca_info;

			if (cert->is_self_signed(cert))
			{
				/* a self-signed certificate is its own ca */
				ca_info = ca_info_create(NULL, cert);
				ca_info = charon->credentials->add_ca_info(charon->credentials, ca_info);
				cert->set_ca_info(cert, ca_info);
			}
			else
			{
				/* get_issuer() automatically sets cert->ca_info */
				ca_info = charon->credentials->get_issuer(charon->credentials, cert);
			}
			if (other_ca == NULL && !other_ca_same)
			{
				identification_t *issuer = cert->get_issuer(cert);

				other_ca = issuer->clone(issuer);
			}
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

	/* have a look for an (almost) identical peer config to reuse */
	iterator = charon->backends->create_iterator(charon->backends);
	while (iterator->iterate(iterator, (void**)&peer_cfg))
	{
		ike_cfg = peer_cfg->get_ike_cfg(peer_cfg);
		if (my_id->equals(my_id, peer_cfg->get_my_id(peer_cfg))
		&&	other_id->equals(other_id, peer_cfg->get_other_id(peer_cfg))
		&&	my_host->equals(my_host, ike_cfg->get_my_host(ike_cfg))
		&&	other_host->equals(other_host, ike_cfg->get_other_host(ike_cfg))
		&&	other_ca->equals(other_ca, peer_cfg->get_other_ca(peer_cfg))
		&&	peer_cfg->get_ike_version(peer_cfg) == (msg->add_conn.ikev2 ? 2 : 1)
		&&	peer_cfg->get_auth_method(peer_cfg) == msg->add_conn.auth_method
		&&	peer_cfg->get_eap_type(peer_cfg) == msg->add_conn.eap_type)
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
		charon->backends->add_peer_cfg(charon->backends, peer_cfg);
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
static void stroke_del_conn(stroke_msg_t *msg, FILE *out)
{
	iterator_t *peer_iter, *child_iter;
	peer_cfg_t *peer, *child;
	
	pop_string(msg, &(msg->del_conn.name));
	DBG1(DBG_CFG, "received stroke: delete connection '%s'", msg->del_conn.name);
	
	peer_iter = charon->backends->create_iterator(charon->backends);
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
 * logging to the stroke interface
 */
static bool stroke_log(stroke_log_info_t *info, signal_t signal, level_t level,
					   ike_sa_t *ike_sa, char *format, va_list args)
{
	if (level <= info->level)
	{
		if (vfprintf(info->out, format, args) < 0 ||
			fprintf(info->out, "\n") < 0 ||
			fflush(info->out) != 0)
		{
			return FALSE;
		}
	}
	return TRUE;
}

/**
 * get a peer configuration by its name, or a name of its children
 */
static peer_cfg_t *get_peer_cfg_by_name(char *name)
{
	iterator_t *i1, *i2;
	peer_cfg_t *current, *found = NULL;
	child_cfg_t *child;

	i1 = charon->backends->create_iterator(charon->backends);
	while (i1->iterate(i1, (void**)&current))
	{
	        /* compare peer_cfgs name first */
	        if (streq(current->get_name(current), name))
	        {
	                found = current;
	                found->get_ref(found);
	                break;
	        }
	        /* compare all child_cfg names otherwise */
	        i2 = current->create_child_cfg_iterator(current);
	        while (i2->iterate(i2, (void**)&child))
	        {
	                if (streq(child->get_name(child), name))
	                {
	                        found = current;
	                        found->get_ref(found);
	                        break;
	                }
	        }
	        i2->destroy(i2);
	        if (found)
	        {
	                break;
	        }
	}
	i1->destroy(i1);
	return found;
}

/**
 * initiate a connection by name
 */
static void stroke_initiate(stroke_msg_t *msg, FILE *out)
{
	peer_cfg_t *peer_cfg;
	child_cfg_t *child_cfg;
	stroke_log_info_t info;
	
	pop_string(msg, &(msg->initiate.name));
	DBG1(DBG_CFG, "received stroke: initiate '%s'", msg->initiate.name);
	
	peer_cfg = get_peer_cfg_by_name(msg->initiate.name);
	if (peer_cfg == NULL)
	{
		fprintf(out, "no config named '%s'\n", msg->initiate.name);
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
		fprintf(out, "no child config named '%s'\n", msg->initiate.name);
		peer_cfg->destroy(peer_cfg);
		return;
	}
	
	info.out = out;
	info.level = msg->output_verbosity;
	charon->interfaces->initiate(charon->interfaces, peer_cfg, child_cfg,
								 (interface_manager_cb_t)stroke_log, &info);
}

/**
 * route a policy (install SPD entries)
 */
static void stroke_route(stroke_msg_t *msg, FILE *out)
{
	peer_cfg_t *peer_cfg;
	child_cfg_t *child_cfg;
	stroke_log_info_t info;
	
	pop_string(msg, &(msg->route.name));
	DBG1(DBG_CFG, "received stroke: route '%s'", msg->route.name);
	
	peer_cfg = get_peer_cfg_by_name(msg->route.name);
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
	
	info.out = out;
	info.level = msg->output_verbosity;
	charon->interfaces->route(charon->interfaces, peer_cfg, child_cfg,
							  (interface_manager_cb_t)stroke_log, &info);
	peer_cfg->destroy(peer_cfg);
	child_cfg->destroy(child_cfg);
}

/**
 * unroute a policy
 */
static void stroke_unroute(stroke_msg_t *msg, FILE *out)
{
	char *name;
	ike_sa_t *ike_sa;
	iterator_t *iterator;
	stroke_log_info_t info;
	
	pop_string(msg, &(msg->terminate.name));
	name = msg->terminate.name;
	
	info.out = out;
	info.level = msg->output_verbosity;
	
	iterator = charon->interfaces->create_ike_sa_iterator(charon->interfaces);
	while (iterator->iterate(iterator, (void**)&ike_sa))
	{
		child_sa_t *child_sa;
		iterator_t *children;
		u_int32_t id;

		children = ike_sa->create_child_sa_iterator(ike_sa);
		while (children->iterate(children, (void**)&child_sa))
		{
			if (child_sa->get_state(child_sa) == CHILD_ROUTED &&
				streq(name, child_sa->get_name(child_sa)))
			{
				id = child_sa->get_reqid(child_sa);
				children->destroy(children);
				iterator->destroy(iterator);
				charon->interfaces->unroute(charon->interfaces, id,
								(interface_manager_cb_t)stroke_log, &info);
				return;
			}
		}
		children->destroy(children);
	}
	iterator->destroy(iterator);
	DBG1(DBG_CFG, "no such SA found");
}

/**
 * terminate a connection by name
 */
static void stroke_terminate(stroke_msg_t *msg, FILE *out)
{
	char *string, *pos = NULL, *name = NULL;
	u_int32_t id = 0;
	bool child;
	int len;
	ike_sa_t *ike_sa;
	iterator_t *iterator;
	stroke_log_info_t info;
	
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
	{
		/* is a single name */
	}
	else if (pos == string + len - 2)
	{	/* is name[] or name{} */
		string[len-2] = '\0';
		name = string;
	}
	else
	{	/* is name[123] or name{23} */
		string[len-1] = '\0';
		id = atoi(pos + 1);
		if (id == 0)
		{
			DBG1(DBG_CFG, "error parsing string");
			return;
		}
	}
	
	info.out = out;
	info.level = msg->output_verbosity;
	
	iterator = charon->interfaces->create_ike_sa_iterator(charon->interfaces);
	while (iterator->iterate(iterator, (void**)&ike_sa))
	{
		child_sa_t *child_sa;
		iterator_t *children;
		
		if (child)
		{
			children = ike_sa->create_child_sa_iterator(ike_sa);
			while (children->iterate(children, (void**)&child_sa))
			{
				if ((name && streq(name, child_sa->get_name(child_sa))) ||
					(id && id == child_sa->get_reqid(child_sa)))
				{
					id = child_sa->get_reqid(child_sa);
					children->destroy(children);
					iterator->destroy(iterator);
					
					charon->interfaces->terminate_child(charon->interfaces, id,
									(interface_manager_cb_t)stroke_log, &info);
					return;
				}
			}
			children->destroy(children);
		}
		else if ((name && streq(name, ike_sa->get_name(ike_sa))) ||
				 (id && id == ike_sa->get_unique_id(ike_sa)))
		{
			id = ike_sa->get_unique_id(ike_sa);
			/* unlock manager first */
			iterator->destroy(iterator);
			
			charon->interfaces->terminate_ike(charon->interfaces, id,
								 	(interface_manager_cb_t)stroke_log, &info);
			return;
		}
		
	}
	iterator->destroy(iterator);
	DBG1(DBG_CFG, "no such SA found");
}

/**
 * Add a ca information record to the cainfo list
 */
static void stroke_add_ca(stroke_msg_t *msg, FILE *out)
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
static void stroke_del_ca(stroke_msg_t *msg, FILE *out)
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
static void stroke_status(stroke_msg_t *msg, FILE *out, bool all)
{
	iterator_t *iterator, *children;
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
				charon->processor->get_idle_threads(charon->processor),
				charon->processor->get_total_threads(charon->processor));
		fprintf(out, " job queue load: %d,",
				charon->processor->get_job_load(charon->processor));
		fprintf(out, " scheduled events: %d\n",
				charon->scheduler->get_job_load(charon->scheduler));
		iterator = charon->kernel_interface->create_address_iterator(
													charon->kernel_interface);
		fprintf(out, "Listening on %d IP addresses:\n",
				iterator->get_count(iterator));
		while (iterator->iterate(iterator, (void**)&host))
		{
			fprintf(out, "  %H\n", host);
		}
		iterator->destroy(iterator);
	
		fprintf(out, "Connections:\n");
		iterator = charon->backends->create_iterator(charon->backends);
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
			{
				identification_t *my_ca = peer_cfg->get_my_ca(peer_cfg);
				identification_t *other_ca = peer_cfg->get_other_ca(peer_cfg);

				if (my_ca->get_type(my_ca) != ID_ANY
				||  other_ca->get_type(other_ca) != ID_ANY)
				{
					fprintf(out, "%12s:    CAs: '%D'...'%D'\n", peer_cfg->get_name(peer_cfg),
							my_ca, other_ca);
				}
			}
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
static void list_auth_certificates(u_int flag, const char *label,
								   bool utc, FILE *out)
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
static void stroke_list(stroke_msg_t *msg, FILE *out)
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
		list_auth_certificates(AUTH_CA, "CA", msg->list.utc, out);
	}
	if (msg->list.flags & LIST_OCSPCERTS)
	{
		list_auth_certificates(AUTH_OCSP, "OCSP", msg->list.utc, out);
	}
	if (msg->list.flags & LIST_AACERTS)
	{
		list_auth_certificates(AUTH_AA, "AA", msg->list.utc, out);
	}
	if (msg->list.flags & LIST_CAINFOS)
	{
		ca_info_t *ca_info;
		bool first = TRUE;

		iterator = charon->credentials->create_cainfo_iterator(charon->credentials);
		while (iterator->iterate(iterator, (void**)&ca_info))
		{
			if (ca_info->is_ca(ca_info))
			{
				if (first)
				{
					fprintf(out, "\n");
					fprintf(out, "List of X.509 CA Information Records:\n");
					fprintf(out, "\n");
					first = FALSE;
				}
				ca_info->list(ca_info, out, msg->list.utc);
			}
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
            if (ca_info->is_ca(ca_info) && ca_info->has_crl(ca_info))
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
	if (msg->list.flags & LIST_OCSP)
	{
		ca_info_t *ca_info;
		bool first = TRUE;

        iterator = charon->credentials->create_cainfo_iterator(charon->credentials);
        while (iterator->iterate(iterator, (void **)&ca_info))
        {
            if (ca_info->is_ca(ca_info) && ca_info->has_certinfos(ca_info))
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
static void stroke_reread(stroke_msg_t *msg, FILE *out)
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
static void stroke_purge(stroke_msg_t *msg, FILE *out)
{
	if (msg->purge.flags & PURGE_OCSP)
	{
		iterator_t *iterator = charon->credentials->create_cainfo_iterator(charon->credentials);
		ca_info_t *ca_info;

		while (iterator->iterate(iterator, (void**)&ca_info))
		{
			if (ca_info->is_ca(ca_info))
			{
				ca_info->purge_ocsp(ca_info);
			}
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
static void stroke_loglevel(stroke_msg_t *msg, FILE *out)
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
static job_requeue_t stroke_process(int *fdp)
{
	stroke_msg_t *msg;
	u_int16_t msg_length;
	ssize_t bytes_read;
	FILE *out;
	int strokefd = *fdp;
	
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
			stroke_initiate(msg, out);
			break;
		case STR_ROUTE:
			stroke_route(msg, out);
			break;
		case STR_UNROUTE:
			stroke_unroute(msg, out);
			break;
		case STR_TERMINATE:
			stroke_terminate(msg, out);
			break;
		case STR_STATUS:
			stroke_status(msg, out, FALSE);
			break;
		case STR_STATUS_ALL:
			stroke_status(msg, out, TRUE);
			break;
		case STR_ADD_CONN:
			stroke_add_conn(msg, out);
			break;
		case STR_DEL_CONN:
			stroke_del_conn(msg, out);
			break;
		case STR_ADD_CA:
			stroke_add_ca(msg, out);
			break;
		case STR_DEL_CA:
			stroke_del_ca(msg, out);
			break;
		case STR_LOGLEVEL:
			stroke_loglevel(msg, out);
			break;
		case STR_LIST:
			stroke_list(msg, out);
			break;
		case STR_REREAD:
			stroke_reread(msg, out);
			break;
		case STR_PURGE:
			stroke_purge(msg, out);
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
 * Implementation of private_stroke_interface_t.stroke_receive.
 */
static job_requeue_t stroke_receive(private_stroke_interface_t *this)
{
	struct sockaddr_un strokeaddr;
	int strokeaddrlen = sizeof(strokeaddr);
	int strokefd, *fdp;
	int oldstate;
	callback_job_t *job;
	
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &oldstate);
	strokefd = accept(this->socket, (struct sockaddr *)&strokeaddr, &strokeaddrlen);
	pthread_setcancelstate(oldstate, NULL);
	
	if (strokefd < 0)
	{
		DBG1(DBG_CFG, "accepting stroke connection failed: %s", strerror(errno));
		return JOB_REQUEUE_FAIR;
	}
	
	fdp = malloc_thing(int);
	*fdp = strokefd;
	job = callback_job_create((callback_job_cb_t)stroke_process, fdp, free, this->job);
	charon->processor->queue_job(charon->processor, (job_t*)job);
	
	return JOB_REQUEUE_FAIR;
}

/**
 * Implementation of interface_t.destroy.
 */
static void destroy(private_stroke_interface_t *this)
{
	this->job->cancel(this->job);
	free(this);
	unlink(socket_addr.sun_path);
}

/*
 * Described in header-file
 */
interface_t *interface_create()
{
	private_stroke_interface_t *this = malloc_thing(private_stroke_interface_t);
	mode_t old;

	/* public functions */
	this->public.interface.destroy = (void (*)(interface_t*))destroy;
	
	/* set up unix socket */
	this->socket = socket(AF_UNIX, SOCK_STREAM, 0);
	if (this->socket == -1)
	{
		DBG1(DBG_CFG, "could not create stroke socket");
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
	
	this->job = callback_job_create((callback_job_cb_t)stroke_receive,
									this, NULL, NULL);
	charon->processor->queue_job(charon->processor, (job_t*)this->job);
	
	return &this->public.interface;
}

