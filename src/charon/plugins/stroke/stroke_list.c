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

#include "stroke_list.h"

#include <daemon.h>
#include <utils/linked_list.h>
#include <credentials/certificates/x509.h>
#include <credentials/certificates/ac.h>
#include <credentials/certificates/crl.h>
#include <config/peer_cfg.h>

/* warning intervals for list functions */
#define CERT_WARNING_INTERVAL  30	/* days */
#define CRL_WARNING_INTERVAL	7	/* days */
#define AC_WARNING_INTERVAL		1	/* day */

typedef struct private_stroke_list_t private_stroke_list_t;

/**
 * private data of stroke_list
 */
struct private_stroke_list_t {

	/**
	 * public functions
	 */
	stroke_list_t public;
	
	/**
	 * timestamp of daemon start
	 */
	time_t uptime;
};

/**
 * get the authentication class of a config
 */
auth_class_t get_auth_class(peer_cfg_t *config)
{
	auth_class_t *class;
	auth_info_t *auth_info;
	
	auth_info = config->get_auth(config);
	if (auth_info->get_item(auth_info, AUTHN_AUTH_CLASS, (void**)&class))
	{
		return *class;
	}
	/* fallback to pubkey authentication */
	return AUTH_CLASS_PUBKEY;
}

/**
 * log an IKE_SA to out
 */
static void log_ike_sa(FILE *out, ike_sa_t *ike_sa, bool all)
{
	ike_sa_id_t *id = ike_sa->get_id(ike_sa);

	fprintf(out, "%12s[%d]: %N, %H[%D]...%H[%D]\n",
			ike_sa->get_name(ike_sa), ike_sa->get_unique_id(ike_sa),
			ike_sa_state_names, ike_sa->get_state(ike_sa),
			ike_sa->get_my_host(ike_sa), ike_sa->get_my_id(ike_sa),
			ike_sa->get_other_host(ike_sa), ike_sa->get_other_id(ike_sa));
	
	if (all)
	{
		char *ike_proposal = ike_sa->get_proposal(ike_sa);

		fprintf(out, "%12s[%d]: IKE SPIs: %.16llx_i%s %.16llx_r%s",
				ike_sa->get_name(ike_sa), ike_sa->get_unique_id(ike_sa),
				id->get_initiator_spi(id), id->is_initiator(id) ? "*" : "",
				id->get_responder_spi(id), id->is_initiator(id) ? "" : "*");
	

		if (ike_sa->get_state(ike_sa) == IKE_ESTABLISHED)
		{
			u_int32_t rekey = ike_sa->get_statistic(ike_sa, STAT_REKEY_TIME);
			u_int32_t reauth = ike_sa->get_statistic(ike_sa, STAT_REAUTH_TIME);

			if (rekey)
			{
				fprintf(out, ", rekeying in %V", &rekey);
			}
			if (reauth)
			{
				fprintf(out, ", %N reauthentication in %V", auth_class_names,
						get_auth_class(ike_sa->get_peer_cfg(ike_sa)), &reauth);
			}
			if (!rekey && !reauth)
			{
				fprintf(out, ", rekeying disabled");
			}
		}
		fprintf(out, "\n");

		if (ike_proposal)
		{
			fprintf(out, "%12s[%d]: IKE proposal: %s\n",
					ike_sa->get_name(ike_sa), ike_sa->get_unique_id(ike_sa),
					ike_proposal);
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
		u_int16_t my_cpi    = child_sa->get_cpi(child_sa, TRUE);
		u_int16_t other_cpi = child_sa->get_cpi(child_sa, FALSE);		

		fprintf(out, ", %N SPIs: %.8x_i %.8x_o",
				protocol_id_names, child_sa->get_protocol(child_sa),
				ntohl(child_sa->get_spi(child_sa, TRUE)),
				ntohl(child_sa->get_spi(child_sa, FALSE)));

		/* Is IPCOMP activated ? */
		if (my_cpi && other_cpi)
		{
			fprintf(out, ", IPCOMP CPIs: %.4x_i %.4x_o",
					ntohs(my_cpi), ntohs(other_cpi));
		}

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
				if (int_alg != AUTH_UNDEFINED)
				{
					fprintf(out, "/");
				}
			}
			
			if (int_alg != AUTH_UNDEFINED)
			{
				fprintf(out, "%N", integrity_algorithm_names, int_alg);
				if (int_len)
				{
					fprintf(out, "-%d", int_len);
				}
			}
			fprintf(out, ", rekeying ");
			
			if (rekey)
			{
				fprintf(out, "in %#V", &now, &rekey);
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
 * Implementation of stroke_list_t.status.
 */
static void status(private_stroke_list_t *this, stroke_msg_t *msg, FILE *out, bool all)
{
	enumerator_t *enumerator, *children;
	iterator_t *iterator;
	ike_cfg_t *ike_cfg;
	child_cfg_t *child_cfg;
	ike_sa_t *ike_sa;
	bool found = FALSE;
	char *name = msg->status.name;
	
	if (all)
	{
		peer_cfg_t *peer_cfg;
		char *plugin;
		host_t *host;
		u_int32_t dpd;
		time_t uptime = time(NULL) - this->uptime;

		fprintf(out, "Performance:\n");
		fprintf(out, "  uptime: %V, since %#T\n", &uptime, &this->uptime, FALSE);
		fprintf(out, "  worker threads: %d idle of %d,",
				charon->processor->get_idle_threads(charon->processor),
				charon->processor->get_total_threads(charon->processor));
		fprintf(out, " job queue load: %d,",
				charon->processor->get_job_load(charon->processor));
		fprintf(out, " scheduled events: %d\n",
				charon->scheduler->get_job_load(charon->scheduler));
		fprintf(out, "  loaded plugins: ");
		enumerator = lib->plugins->create_plugin_enumerator(lib->plugins);
		while (enumerator->enumerate(enumerator, &plugin))
		{
			fprintf(out, "%s ", plugin);
		}
		enumerator->destroy(enumerator);
		fprintf(out, "\n");
		
		iterator = charon->kernel_interface->create_address_iterator(
													charon->kernel_interface);
		fprintf(out, "Listening IP addresses:\n");
		while (iterator->iterate(iterator, (void**)&host))
		{
			fprintf(out, "  %H\n", host);
		}
		iterator->destroy(iterator);
	
		fprintf(out, "Connections:\n");
		enumerator = charon->backends->create_peer_cfg_enumerator(charon->backends);
		while (enumerator->enumerate(enumerator, (void**)&peer_cfg))
		{
			void *ptr;
			certificate_t *cert;
			auth_item_t item;
			auth_info_t *auth;
			enumerator_t *auth_enumerator;
			identification_t *my_ca = NULL, *other_ca = NULL;
			identification_t *eap_identity = NULL;
			u_int32_t *eap_type = NULL;

			if (peer_cfg->get_ike_version(peer_cfg) != 2 ||
				(name && !streq(name, peer_cfg->get_name(peer_cfg))))
			{
				continue;
			}
			
			/* determine any required CAs */
			auth = peer_cfg->get_auth(peer_cfg);
			auth_enumerator = auth->create_item_enumerator(auth);
			while (auth_enumerator->enumerate(auth_enumerator, &item, &ptr))
			{
				switch (item)
				{
					case AUTHN_EAP_TYPE:
						eap_type = (u_int32_t *)ptr;
						break;
					case AUTHN_EAP_IDENTITY:
						eap_identity = (identification_t *)ptr;
						break;
					case AUTHN_CA_CERT:
						cert = (certificate_t *)ptr;
						my_ca = cert->get_subject(cert);
						break;
					case AUTHN_CA_CERT_NAME:
						my_ca = (identification_t *)ptr;
						break;
					case AUTHZ_CA_CERT:
						cert = (certificate_t *)ptr;
						other_ca = cert->get_subject(cert);
						break;
					case AUTHZ_CA_CERT_NAME:
						other_ca = (identification_t *)ptr;
						break;
					default:
						break;
				}
			}
			auth_enumerator->destroy(auth_enumerator);

			ike_cfg = peer_cfg->get_ike_cfg(peer_cfg);
			fprintf(out, "%12s:  %s[%D]...%s[%D]\n", peer_cfg->get_name(peer_cfg),
					ike_cfg->get_my_addr(ike_cfg), peer_cfg->get_my_id(peer_cfg),
					ike_cfg->get_other_addr(ike_cfg), peer_cfg->get_other_id(peer_cfg));
			if (my_ca || other_ca)
			{
				fprintf(out, "%12s:  CAs: ", peer_cfg->get_name(peer_cfg));
				if (my_ca)
				{
					fprintf(out, "\"%D\"...", my_ca);
				}
				else
				{
					fprintf(out, "%%any...");
				}
				if (other_ca)
				{
					fprintf(out, "\"%D\"\n", other_ca);
				}
				else
				{
					fprintf(out, "%%any\n");
				}
			}

			fprintf(out, "%12s:  %N ",  peer_cfg->get_name(peer_cfg),
					auth_class_names, get_auth_class(peer_cfg));
			if (eap_type)
			{
				fprintf(out, "and %N ", eap_type_names, *eap_type);
			}
			fprintf(out, "authentication");
			if (eap_identity)
			{
				fprintf(out, ", EAP identity: '%D'", eap_identity);
			}
			dpd = peer_cfg->get_dpd(peer_cfg);
			if (dpd)
			{
				fprintf(out, ", dpddelay=%us", dpd);
			}
			fprintf(out, "\n");

			/* TODO: list groups */

			children = peer_cfg->create_child_cfg_enumerator(peer_cfg);
			while (children->enumerate(children, &child_cfg))
			{
				linked_list_t *my_ts, *other_ts;

				my_ts = child_cfg->get_traffic_selectors(child_cfg, TRUE, NULL, NULL);
				other_ts = child_cfg->get_traffic_selectors(child_cfg, FALSE, NULL, NULL);
				fprintf(out, "%12s:    %#R=== %#R", child_cfg->get_name(child_cfg),
						my_ts, other_ts);
				my_ts->destroy_offset(my_ts, offsetof(traffic_selector_t, destroy));
				other_ts->destroy_offset(other_ts, offsetof(traffic_selector_t, destroy));

				if (dpd)
				{
					fprintf(out, ", dpdaction=%N", action_names,
							child_cfg->get_dpd_action(child_cfg));
				}
				fprintf(out, "\n");
			}
			children->destroy(children);
		}
		enumerator->destroy(enumerator);
	}
	
	fprintf(out, "Security Associations:\n");
	enumerator = charon->controller->create_ike_sa_enumerator(charon->controller);
	while (enumerator->enumerate(enumerator, &ike_sa))
	{
		bool ike_printed = FALSE;
		child_sa_t *child_sa;
		iterator_t *children = ike_sa->create_child_sa_iterator(ike_sa);
		
		if (name == NULL || streq(name, ike_sa->get_name(ike_sa)))
		{
			log_ike_sa(out, ike_sa, all);
			found = TRUE;
			ike_printed = TRUE;
		}

		while (children->iterate(children, (void**)&child_sa))
		{
			if (name == NULL || streq(name, child_sa->get_name(child_sa)))
			{
				if (!ike_printed)
				{
					log_ike_sa(out, ike_sa, all);
					found = TRUE;
					ike_printed = TRUE;
				}
				log_child_sa(out, child_sa, all);
			}	
		}
		children->destroy(children);
	}
	enumerator->destroy(enumerator);
	
	if (!found)
	{
		if (name)
		{
			fprintf(out, "  no match\n");
		}
		else
		{
			fprintf(out, "  none\n");
		}
	}
}

/**
 * create a unique certificate list without duplicates
 * certicates having the same issuer are grouped together.
 */
static linked_list_t* create_unique_cert_list(certificate_type_t type)
{
	linked_list_t *list = linked_list_create();
	enumerator_t *enumerator = charon->credentials->create_cert_enumerator(
									charon->credentials, type, KEY_ANY,
									NULL, FALSE);
	certificate_t *cert;
	
	while (enumerator->enumerate(enumerator, (void**)&cert))
	{
		iterator_t *iterator = list->create_iterator(list, TRUE);
		identification_t *issuer = cert->get_issuer(cert);
		bool previous_same, same = FALSE, last = TRUE;
		certificate_t *list_cert;
		
		while (iterator->iterate(iterator, (void**)&list_cert))
		{
			/* exit if we have a duplicate? */
			if (list_cert->equals(list_cert, cert))
			{
				last = FALSE;
				break;
			}
			/* group certificates with same issuer */
			previous_same = same;
			same = list_cert->has_issuer(list_cert, issuer);
			if (previous_same && !same)
			{
				iterator->insert_before(iterator, (void *)cert->get_ref(cert));
				last = FALSE;
				break;
			}
		}
		iterator->destroy(iterator);

		if (last)
		{
			list->insert_last(list, (void *)cert->get_ref(cert));
		}
	}
	enumerator->destroy(enumerator);
	return list;
}

/**
 * list all X.509 certificates matching the flags
 */
static void stroke_list_certs(linked_list_t *list, char *label, 
							  x509_flag_t flags, bool utc, FILE *out)
{
	bool first = TRUE;
	time_t now = time(NULL);
	enumerator_t *enumerator = list->create_enumerator(list);
	certificate_t *cert;

	while (enumerator->enumerate(enumerator, (void**)&cert))
	{
		x509_t *x509 = (x509_t*)cert;
		x509_flag_t x509_flags = x509->get_flags(x509);

		/* list only if flag is set, or flags == 0 (ignoring self-signed) */
		if ((x509_flags & flags) || (flags == (x509_flags & ~X509_SELF_SIGNED)))
		{
			enumerator_t *enumerator;
			identification_t *altName;
			bool first_altName = TRUE;
			chunk_t serial = x509->get_serial(x509);
			identification_t *authkey = x509->get_authKeyIdentifier(x509);
			time_t notBefore, notAfter;
			public_key_t *public = cert->get_public_key(cert);

			if (first)
			{
				fprintf(out, "\n");
				fprintf(out, "List of %s:\n", label);
				first = FALSE;
			}
			fprintf(out, "\n");

			/* list subjectAltNames */
			enumerator = x509->create_subjectAltName_enumerator(x509);
			while (enumerator->enumerate(enumerator, (void**)&altName))
			{
				if (first_altName)
				{
					fprintf(out, "  altNames:  ");
					first_altName = FALSE;
				}
				else
				{
					fprintf(out, ", ");
				}
				fprintf(out, "%D", altName);
			}
			if (!first_altName)
			{
				fprintf(out, "\n");
			}
			enumerator->destroy(enumerator);

			fprintf(out, "  subject:  \"%D\"\n", cert->get_subject(cert));
			fprintf(out, "  issuer:   \"%D\"\n", cert->get_issuer(cert));
			fprintf(out, "  serial:    %#B\n", &serial);

			/* list validity */
			cert->get_validity(cert, &now, &notBefore, &notAfter);
			fprintf(out, "  validity:  not before %#T, ", &notBefore, utc);
			if (now < notBefore)
			{
				fprintf(out, "not valid yet (valid in %#V)\n", &now, &notBefore);
			}
			else
			{
				fprintf(out, "ok\n");
			}
			fprintf(out, "             not after  %#T, ", &notAfter, utc);
			if (now > notAfter)
			{
				fprintf(out, "expired (%#V ago)\n", &now, &notAfter);
			}
			else
			{
				fprintf(out, "ok");
				if (now > notAfter - CERT_WARNING_INTERVAL * 60 * 60 * 24)
				{
					fprintf(out, " (expires in %#V)", &now, &notAfter);
				}
				fprintf(out, " \n");
			}
	
			/* list public key information */
			if (public)
			{
				private_key_t *private = NULL;
				identification_t *id, *keyid;
			
				id    = public->get_id(public, ID_PUBKEY_SHA1);
				keyid = public->get_id(public, ID_PUBKEY_INFO_SHA1);

				private = charon->credentials->get_private(
									charon->credentials, 
									public->get_type(public), keyid, NULL);
				fprintf(out, "  pubkey:    %N %d bits%s\n",
						key_type_names, public->get_type(public),
						public->get_keysize(public) * 8,
						private ? ", has private key" : "");
				fprintf(out, "  keyid:     %D\n", keyid);
				fprintf(out, "  subjkey:   %D\n", id);
				DESTROY_IF(private);
				public->destroy(public);
			}
	
			/* list optional authorityKeyIdentifier */
			if (authkey)
			{
				fprintf(out, "  authkey:   %D\n", authkey);
			}
		}
	}
	enumerator->destroy(enumerator);
}

/**
 * list all X.509 attribute certificates
 */
static void stroke_list_acerts(linked_list_t *list, bool utc, FILE *out)
{
	bool first = TRUE;
	time_t thisUpdate, nextUpdate, now = time(NULL);
	enumerator_t *enumerator = list->create_enumerator(list);
	certificate_t *cert;

	while (enumerator->enumerate(enumerator, (void**)&cert))
	{
		ac_t *ac = (ac_t*)cert;
		chunk_t serial  = ac->get_serial(ac);
		chunk_t holderSerial = ac->get_holderSerial(ac);
		identification_t *holderIssuer = ac->get_holderIssuer(ac);
		identification_t *authkey = ac->get_authKeyIdentifier(ac);
		identification_t *entityName = cert->get_subject(cert);

		if (first)
		{
			fprintf(out, "\n");
			fprintf(out, "List of X.509 Attribute Certificates:\n");
			first = FALSE;
		}
		fprintf(out, "\n");

		if (entityName)
		{
			fprintf(out, "  holder:   \"%D\"\n", entityName);
		}
		if (holderIssuer)
		{
			fprintf(out, "  hissuer:  \"%D\"\n", holderIssuer);
		}
		if (holderSerial.ptr)
		{
			fprintf(out, "  hserial:   %#B\n", &holderSerial);
		}
		fprintf(out, "  issuer:   \"%D\"\n", cert->get_issuer(cert));
		fprintf(out, "  serial:    %#B\n", &serial);

		/* list validity */
		cert->get_validity(cert, &now, &thisUpdate, &nextUpdate);
		fprintf(out, "  updates:   this %#T\n",  &thisUpdate, utc);
		fprintf(out, "             next %#T, ", &nextUpdate, utc);
		if (now > nextUpdate)
		{
			fprintf(out, "expired (%#V ago)\n", &now, &nextUpdate);
		}
		else
		{
			fprintf(out, "ok");
			if (now > nextUpdate - AC_WARNING_INTERVAL * 60 * 60 * 24)
			{
				fprintf(out, " (expires in %#V)", &now, &nextUpdate);
			}
			fprintf(out, " \n");
		}

		/* list optional authorityKeyIdentifier */
		if (authkey)
		{
			fprintf(out, "  authkey:   %D\n", authkey);
		}
	}
	enumerator->destroy(enumerator);
}

/**
 * list all X.509 CRLs
 */
static void stroke_list_crls(linked_list_t *list, bool utc, FILE *out)
{
	bool first = TRUE;
	time_t thisUpdate, nextUpdate, now = time(NULL);
	enumerator_t *enumerator = list->create_enumerator(list);
	certificate_t *cert;
	
	while (enumerator->enumerate(enumerator, (void**)&cert))
	{
		crl_t *crl = (crl_t*)cert;
		chunk_t serial  = crl->get_serial(crl);
		identification_t *authkey = crl->get_authKeyIdentifier(crl);

		if (first)
		{
			fprintf(out, "\n");
			fprintf(out, "List of X.509 CRLs:\n");
			first = FALSE;
		}
		fprintf(out, "\n");

		fprintf(out, "  issuer:   \"%D\"\n", cert->get_issuer(cert));

		/* list optional crlNumber */
		if (serial.ptr)
		{
			fprintf(out, "  serial:    %#B\n", &serial);
		}

		/* count the number of revoked certificates */
		{
			int count = 0;
			enumerator_t *enumerator = crl->create_enumerator(crl);

			while (enumerator->enumerate(enumerator, NULL, NULL, NULL))
			{
				count++;
			}
			fprintf(out, "  revoked:   %d certificate%s\n", count,
							(count == 1)? "" : "s");
			enumerator->destroy(enumerator);
		}

		/* list validity */
		cert->get_validity(cert, &now, &thisUpdate, &nextUpdate);
		fprintf(out, "  updates:   this %#T\n",  &thisUpdate, utc);
		fprintf(out, "             next %#T, ", &nextUpdate, utc);
		if (now > nextUpdate)
		{
			fprintf(out, "expired (%#V ago)\n", &now, &nextUpdate);
		}
		else
		{
			fprintf(out, "ok");
			if (now > nextUpdate - CRL_WARNING_INTERVAL * 60 * 60 * 24)
			{
				fprintf(out, " (expires in %#V)", &now, &nextUpdate);
			}
			fprintf(out, " \n");
		}

		/* list optional authorityKeyIdentifier */
		if (authkey)
		{
			fprintf(out, "  authkey:   %D\n", authkey);
		}
	}
	enumerator->destroy(enumerator);
}

/**
 * list all OCSP responses
 */
static void stroke_list_ocsp(linked_list_t* list, bool utc, FILE *out)
{
	bool first = TRUE;
	enumerator_t *enumerator = list->create_enumerator(list);
	certificate_t *cert;
	
	while (enumerator->enumerate(enumerator, (void**)&cert))
	{
		if (first)
		{
			fprintf(out, "\n");
			fprintf(out, "List of OCSP responses:\n");
			fprintf(out, "\n");
			first = FALSE;
		}

		fprintf(out, "  signer:   \"%D\"\n", cert->get_issuer(cert));
	}
	enumerator->destroy(enumerator);
}

/**
 * List crypto algorithms available
 */
static void list_algs(FILE *out)
{
	enumerator_t *enumerator;
	encryption_algorithm_t encryption;
	integrity_algorithm_t integrity;
	hash_algorithm_t hash;
	pseudo_random_function_t prf;
	diffie_hellman_group_t group;
	
	fprintf(out, "Userland algorithms:");
	fprintf(out, "\n  encryption: ");
	enumerator = lib->crypto->create_crypter_enumerator(lib->crypto);
	while (enumerator->enumerate(enumerator, &encryption))
	{
		fprintf(out, "%N ", encryption_algorithm_names, encryption);
	}
	enumerator->destroy(enumerator);
	fprintf(out, "\n  integrity:  ");
	enumerator = lib->crypto->create_signer_enumerator(lib->crypto);
	while (enumerator->enumerate(enumerator, &integrity))
	{
		fprintf(out, "%N ", integrity_algorithm_names, integrity);
	}
	enumerator->destroy(enumerator);
	fprintf(out, "\n  hasher:     ");
	enumerator = lib->crypto->create_hasher_enumerator(lib->crypto);
	while (enumerator->enumerate(enumerator, &hash))
	{
		fprintf(out, "%N ", hash_algorithm_names, hash);
	}
	enumerator->destroy(enumerator);
	fprintf(out, "\n  prf:        ");
	enumerator = lib->crypto->create_prf_enumerator(lib->crypto);
	while (enumerator->enumerate(enumerator, &prf))
	{
		fprintf(out, "%N ", pseudo_random_function_names, prf);
	}
	enumerator->destroy(enumerator);
	fprintf(out, "\n  dh-group:   ");
	enumerator = lib->crypto->create_dh_enumerator(lib->crypto);
	while (enumerator->enumerate(enumerator, &group))
	{
		fprintf(out, "%N ", diffie_hellman_group_names, group);
	}
	enumerator->destroy(enumerator);
	fprintf(out, "\n");
}

/**
 * Implementation of stroke_list_t.list.
 */
static void list(private_stroke_list_t *this, stroke_msg_t *msg, FILE *out)
{
	linked_list_t *cert_list = NULL;

	if (msg->list.flags & (LIST_CERTS | LIST_CACERTS | LIST_OCSPCERTS | LIST_AACERTS))
	{
		cert_list = create_unique_cert_list(CERT_X509);
	}
	if (msg->list.flags & LIST_CERTS)
	{
		stroke_list_certs(cert_list, "X.509 End Entity Certificates",
						  0, msg->list.utc, out);
	}
	if (msg->list.flags & LIST_CACERTS)
	{
		stroke_list_certs(cert_list, "X.509 CA Certificates",
						  X509_CA, msg->list.utc, out);
	}
	if (msg->list.flags & LIST_OCSPCERTS)
	{
		stroke_list_certs(cert_list, "X.509 OCSP Signer Certificates",
						  X509_OCSP_SIGNER, msg->list.utc, out);
	}
	if (msg->list.flags & LIST_AACERTS)
	{
		stroke_list_certs(cert_list, "X.509 AA Certificates",
						  X509_AA, msg->list.utc, out);
	}
	if (msg->list.flags & LIST_ACERTS)
	{
		linked_list_t *ac_list = create_unique_cert_list(CERT_X509_AC);

		stroke_list_acerts(ac_list, msg->list.utc, out);
		ac_list->destroy_offset(ac_list, offsetof(certificate_t, destroy)); 
	}
	if (msg->list.flags & LIST_CRLS)
	{
		linked_list_t *crl_list = create_unique_cert_list(CERT_X509_CRL);

		stroke_list_crls(crl_list, msg->list.utc, out);
		crl_list->destroy_offset(crl_list, offsetof(certificate_t, destroy)); 
	}
	if (msg->list.flags & LIST_OCSP)
	{
		linked_list_t *ocsp_list = create_unique_cert_list(CERT_X509_OCSP_RESPONSE);

		stroke_list_ocsp(ocsp_list, msg->list.utc, out);
		
		ocsp_list->destroy_offset(ocsp_list, offsetof(certificate_t, destroy)); 
	}
	if (msg->list.flags & LIST_ALGS)
	{
		list_algs(out);
	}
	DESTROY_OFFSET_IF(cert_list, offsetof(certificate_t, destroy));
}

/**
 * Implementation of stroke_list_t.destroy
 */
static void destroy(private_stroke_list_t *this)
{
	free(this);
}

/*
 * see header file
 */
stroke_list_t *stroke_list_create()
{
	private_stroke_list_t *this = malloc_thing(private_stroke_list_t);
	
	this->public.list = (void(*)(stroke_list_t*, stroke_msg_t *msg, FILE *out))list;
	this->public.status = (void(*)(stroke_list_t*, stroke_msg_t *msg, FILE *out,bool))status;
	this->public.destroy = (void(*)(stroke_list_t*))destroy;
	
	this->uptime = time(NULL);
	
	return &this->public;
}

