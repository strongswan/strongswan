/**
 * @file ike_sa.c
 *
 * @brief Implementation of ike_sa_t.
 *
 */

/*
 * Copyright (C) 2006 Tobias Brunner, Daniel Roethlisberger
 * Copyright (C) 2005-2006 Martin Willi
 * Copyright (C) 2005 Jan Hutter
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

#include <sys/time.h>
#include <string.h>
#include <printf.h>
#include <sys/stat.h>
#include <errno.h>

#include "ike_sa.h"

#include <library.h>
#include <daemon.h>
#include <utils/linked_list.h>
#include <utils/lexparser.h>
#include <crypto/diffie_hellman.h>
#include <crypto/prf_plus.h>
#include <crypto/crypters/crypter.h>
#include <crypto/hashers/hasher.h>
#include <encoding/payloads/sa_payload.h>
#include <encoding/payloads/nonce_payload.h>
#include <encoding/payloads/ke_payload.h>
#include <encoding/payloads/delete_payload.h>
#include <encoding/payloads/transform_substructure.h>
#include <encoding/payloads/transform_attribute.h>
#include <encoding/payloads/ts_payload.h>
#include <sa/task_manager.h>
#include <sa/tasks/ike_init.h>
#include <sa/tasks/ike_natd.h>
#include <sa/tasks/ike_mobike.h>
#include <sa/tasks/ike_auth.h>
#include <sa/tasks/ike_config.h>
#include <sa/tasks/ike_cert.h>
#include <sa/tasks/ike_rekey.h>
#include <sa/tasks/ike_reauth.h>
#include <sa/tasks/ike_delete.h>
#include <sa/tasks/ike_dpd.h>
#include <sa/tasks/child_create.h>
#include <sa/tasks/child_delete.h>
#include <sa/tasks/child_rekey.h>
#include <processing/jobs/retransmit_job.h>
#include <processing/jobs/delete_ike_sa_job.h>
#include <processing/jobs/send_dpd_job.h>
#include <processing/jobs/send_keepalive_job.h>
#include <processing/jobs/rekey_ike_sa_job.h>


#ifndef RESOLV_CONF
#define RESOLV_CONF "/etc/resolv.conf"
#endif

ENUM(ike_sa_state_names, IKE_CREATED, IKE_DELETING,
	"CREATED",
	"CONNECTING",
	"ESTABLISHED",
	"REKEYING",
	"DELETING",
);

typedef struct private_ike_sa_t private_ike_sa_t;

/**
 * Private data of an ike_sa_t object.
 */
struct private_ike_sa_t {

	/**
	 * Public members
	 */
	ike_sa_t public;

	/**
	 * Identifier for the current IKE_SA.
	 */
	ike_sa_id_t *ike_sa_id;
	
	/**
	 * unique numerical ID for this IKE_SA.
	 */
	u_int32_t unique_id;
	
	/**
	 * Current state of the IKE_SA
	 */
	ike_sa_state_t state;	
	
	/**
	 * IKE configuration used to set up this IKE_SA
	 */
	ike_cfg_t *ike_cfg;
	
	/**
	 * Peer and authentication information to establish IKE_SA.
	 */
	peer_cfg_t *peer_cfg;
	
	/**
	 * Juggles tasks to process messages
	 */
	task_manager_t *task_manager;
	
	/**
	 * Address of local host
	 */
	host_t *my_host;
	
	/**
	 * Address of remote host
	 */
	host_t *other_host;
	
	/**
	 * Identification used for us
	 */
	identification_t *my_id;
	
	/**
	 * Identification used for other
	 */
	identification_t *other_id;
	
	/**
	 * CA that issued the certificate of other
	 */
	ca_info_t *other_ca;
	
	/**
	 * set of extensions the peer supports
	 */
	ike_extension_t extensions;
	
	/**
	 * set of condition flags currently enabled for this IKE_SA
	 */
	ike_condition_t conditions;

	/**
	 * Linked List containing the child sa's of the current IKE_SA.
	 */
	linked_list_t *child_sas;
	
	/**
	 * crypter for inbound traffic
	 */
	crypter_t *crypter_in;
	
	/**
	 * crypter for outbound traffic
	 */
	crypter_t *crypter_out;
	
	/**
	 * Signer for inbound traffic
	 */
	signer_t *signer_in;
	
	/**
	 * Signer for outbound traffic
	 */
	signer_t *signer_out;
	
	/**
	 * Multi purpose prf, set key, use it, forget it
	 */
	prf_t *prf;
	
	/**
	 * Prf function for derivating keymat child SAs
	 */
	prf_t *child_prf;
	
	/**
	 * Key to build outging authentication data (SKp)
	 */
	chunk_t skp_build;

	/**
	 * Key to verify incoming authentication data (SKp)
	 */
	chunk_t skp_verify;
	
	/**
	 * Virtual IP on local host, if any
	 */
	host_t *my_virtual_ip;
	
	/**
	 * Virtual IP on remote host, if any
	 */
	host_t *other_virtual_ip;
	
	/**
	 * List of DNS servers installed by us
	 */
	linked_list_t *dns_servers;
	
	/**
	 * list of peers additional addresses, transmitted via MOBIKE
	 */
	linked_list_t *additional_addresses;
	
	/**
	 * number pending UPDATE_SA_ADDRESS (MOBIKE)
	 */
	u_int32_t pending_updates;

	/**
	 * Timestamps for this IKE_SA
	 */
	struct {
		/** last IKE message received */
		u_int32_t inbound;
		/** last IKE message sent */
		u_int32_t outbound;
		/** when IKE_SA became established */
		u_int32_t established;
		/** when IKE_SA gets rekeyed */
		u_int32_t rekey;
		/** when IKE_SA gets deleted */
		u_int32_t delete;
	} time;
	
	/**
	 * how many times we have retried so far (keyingtries)
	 */
	u_int32_t keyingtry;
};

/**
 * get the time of the latest traffic processed by the kernel
 */
static time_t get_use_time(private_ike_sa_t* this, bool inbound)
{
	iterator_t *iterator;
	child_sa_t *child_sa;
	time_t latest = 0, use_time;
	
	iterator = this->child_sas->create_iterator(this->child_sas, TRUE);
	while (iterator->iterate(iterator, (void**)&child_sa))
	{
		if (child_sa->get_use_time(child_sa, inbound, &use_time) == SUCCESS)
		{
			latest = max(latest, use_time);
		}
	}
	iterator->destroy(iterator);
	
	if (inbound)
	{
		return max(this->time.inbound, latest);
	}
	else
	{
		return max(this->time.outbound, latest);
	}
}

/**
 * Implementation of ike_sa_t.get_unique_id
 */
static u_int32_t get_unique_id(private_ike_sa_t *this)
{
	return this->unique_id;
}

/**
 * Implementation of ike_sa_t.get_name.
 */
static char *get_name(private_ike_sa_t *this)
{
	if (this->peer_cfg)
	{
		return this->peer_cfg->get_name(this->peer_cfg);
	}
	return "(unnamed)";
}

	
/**
 * Implementation of ike_sa_t.get_stats.
 */
static void get_stats(private_ike_sa_t *this, u_int32_t *next_rekeying)
{
	if (next_rekeying)
	{
		*next_rekeying = this->time.rekey;
	}
}

/**
 * Implementation of ike_sa_t.get_my_host.
 */
static host_t *get_my_host(private_ike_sa_t *this)
{
	return this->my_host;
}

/**
 * Implementation of ike_sa_t.set_my_host.
 */
static void set_my_host(private_ike_sa_t *this, host_t *me)
{
	DESTROY_IF(this->my_host);
	this->my_host = me;
}

/**
 * Implementation of ike_sa_t.get_other_host.
 */
static host_t *get_other_host(private_ike_sa_t *this)
{
	return this->other_host;
}

/**
 * Implementation of ike_sa_t.set_other_host.
 */
static void set_other_host(private_ike_sa_t *this, host_t *other)
{
	DESTROY_IF(this->other_host);
	this->other_host = other;
}

/**
 * Implementation of ike_sa_t.get_peer_cfg
 */
static peer_cfg_t* get_peer_cfg(private_ike_sa_t *this)
{
	return this->peer_cfg;
}

/**
 * Implementation of ike_sa_t.set_peer_cfg
 */
static void set_peer_cfg(private_ike_sa_t *this, peer_cfg_t *peer_cfg)
{
	peer_cfg->get_ref(peer_cfg);
	this->peer_cfg = peer_cfg;

	if (this->ike_cfg == NULL)
	{
		this->ike_cfg = peer_cfg->get_ike_cfg(peer_cfg);
		this->ike_cfg->get_ref(this->ike_cfg);
	}
	
	/* apply values, so we are ready to initate/acquire */
	if (this->my_host->is_anyaddr(this->my_host))
	{
		host_t *me = this->ike_cfg->get_my_host(this->ike_cfg);
		set_my_host(this, me->clone(me));
	}
	if (this->other_host->is_anyaddr(this->other_host))
	{
		host_t *other = this->ike_cfg->get_other_host(this->ike_cfg);
		set_other_host(this, other->clone(other));
	}
	/* apply IDs if they are not already set */
	if (this->my_id->contains_wildcards(this->my_id))
	{
		DESTROY_IF(this->my_id);
		this->my_id = this->peer_cfg->get_my_id(this->peer_cfg);
		this->my_id = this->my_id->clone(this->my_id);
	}
	if (this->other_id->contains_wildcards(this->other_id))
	{
		DESTROY_IF(this->other_id);
		this->other_id = this->peer_cfg->get_other_id(this->peer_cfg);
		this->other_id = this->other_id->clone(this->other_id);
	}
}

/**
 * Implementation of ike_sa_t.send_keepalive
 */
static void send_keepalive(private_ike_sa_t *this)
{
	send_keepalive_job_t *job;
	time_t last_out, now, diff;
	
	if (!(this->conditions & COND_NAT_HERE))
	{	/* disable keep alives if we are not NATed anymore */
		return;
	}
	
	last_out = get_use_time(this, FALSE);
	now = time(NULL);
	
	diff = now - last_out;
	
	if (diff >= KEEPALIVE_INTERVAL)
	{
		packet_t *packet;
		chunk_t data;
		
		packet = packet_create();
		packet->set_source(packet, this->my_host->clone(this->my_host));
		packet->set_destination(packet, this->other_host->clone(this->other_host));
		data.ptr = malloc(1);
		data.ptr[0] = 0xFF;
		data.len = 1;
		packet->set_data(packet, data);
		DBG1(DBG_IKE, "sending keep alive");
		charon->sender->send(charon->sender, packet);
		diff = 0;
	}
	job = send_keepalive_job_create(this->ike_sa_id);
	charon->scheduler->schedule_job(charon->scheduler, (job_t*)job,
									(KEEPALIVE_INTERVAL - diff) * 1000);
}

/**
 * Implementation of ike_sa_t.get_ike_cfg
 */
static ike_cfg_t *get_ike_cfg(private_ike_sa_t *this)
{
	return this->ike_cfg;
}

/**
 * Implementation of ike_sa_t.set_ike_cfg
 */
static void set_ike_cfg(private_ike_sa_t *this, ike_cfg_t *ike_cfg)
{
	ike_cfg->get_ref(ike_cfg);
	this->ike_cfg = ike_cfg;
}
/**
 * Implementation of ike_sa_t.enable_extension.
 */
static void enable_extension(private_ike_sa_t *this, ike_extension_t extension)
{
	this->extensions |= extension;
}

/**
 * Implementation of ike_sa_t.has_extension.
 */
static bool supports_extension(private_ike_sa_t *this, ike_extension_t extension)
{
	return (this->extensions & extension) != FALSE;
}

/**
 * Implementation of ike_sa_t.has_condition.
 */
static bool has_condition(private_ike_sa_t *this, ike_condition_t condition)
{
	return (this->conditions & condition) != FALSE;
}

/**
 * Implementation of ike_sa_t.enable_condition.
 */
static void set_condition(private_ike_sa_t *this, ike_condition_t condition,
						  bool enable)
{
	if (has_condition(this, condition) != enable)
	{
		if (enable)
		{
			this->conditions |= condition;
			switch (condition)
			{
				case COND_STALE:
					DBG1(DBG_IKE, "no route to %H, setting IKE_SA to stale",
						 this->other_host);
					break;
				case COND_NAT_HERE:
					DBG1(DBG_IKE, "local host is behind NAT, sending keep alives");
					this->conditions |= COND_NAT_ANY;
					send_keepalive(this);
					break;
				case COND_NAT_THERE:
					DBG1(DBG_IKE, "remote host is behind NAT");
					this->conditions |= COND_NAT_ANY;
					break;
				default:
					break;
			}
		}
		else
		{
			this->conditions &= ~condition;
			switch (condition)
			{
				case COND_STALE:
					DBG1(DBG_IKE, "new route to %H found", this->other_host);
					break;
				case COND_NAT_HERE:
				case COND_NAT_THERE:
					set_condition(this, COND_NAT_ANY,
								  has_condition(this, COND_NAT_HERE) ||
								  has_condition(this, COND_NAT_THERE));
					break;
				default:
					break;
			}
		}
	}
}

/**
 * Implementation of ike_sa_t.send_dpd
 */
static status_t send_dpd(private_ike_sa_t *this)
{
	send_dpd_job_t *job;
	time_t diff, delay;
	
	delay = this->peer_cfg->get_dpd_delay(this->peer_cfg);
	
	if (delay == 0)
	{
		/* DPD disabled */
		return SUCCESS;
	}
	
	if (this->task_manager->busy(this->task_manager))
	{
		/* an exchange is in the air, no need to start a DPD check */
		diff = 0;
	}
	else
	{
		/* check if there was any inbound traffic */
		time_t last_in, now;
		last_in = get_use_time(this, TRUE);
		now = time(NULL);
		diff = now - last_in;
		if (diff >= delay)
		{
			/* to long ago, initiate dead peer detection */
			task_t *task;
			
			task = (task_t*)ike_dpd_create(TRUE);
			diff = 0;
			DBG1(DBG_IKE, "sending DPD request");
			
			this->task_manager->queue_task(this->task_manager, task);
			this->task_manager->initiate(this->task_manager);
		}
	}
	/* recheck in "interval" seconds */
	job = send_dpd_job_create(this->ike_sa_id);
	charon->scheduler->schedule_job(charon->scheduler, (job_t*)job,
									(delay - diff) * 1000);
	return SUCCESS;
}

/**
 * Implementation of ike_sa_t.get_state.
 */
static ike_sa_state_t get_state(private_ike_sa_t *this)
{
	return this->state;
}

/**
 * Implementation of ike_sa_t.set_state.
 */
static void set_state(private_ike_sa_t *this, ike_sa_state_t state)
{
	DBG1(DBG_IKE, "IKE_SA state change: %N => %N",
		 ike_sa_state_names, this->state,
		 ike_sa_state_names, state);
	
	switch (state)
	{
		case IKE_ESTABLISHED:
		{
			if (this->state == IKE_CONNECTING)
			{
				job_t *job;
				u_int32_t now = time(NULL);
				u_int32_t soft, hard;
				bool reauth;
			
				this->time.established = now;
				/* start DPD checks */
				send_dpd(this);
				
				/* schedule rekeying/reauthentication */
				soft = this->peer_cfg->get_lifetime(this->peer_cfg, TRUE);
				hard = this->peer_cfg->get_lifetime(this->peer_cfg, FALSE);
				reauth = this->peer_cfg->use_reauth(this->peer_cfg);
				DBG1(DBG_IKE, "scheduling %s in %ds, maximum lifetime %ds",
					 reauth ? "reauthentication": "rekeying", soft, hard);
					 
				if (soft)
				{
					this->time.rekey = now + soft;
					job = (job_t*)rekey_ike_sa_job_create(this->ike_sa_id, reauth);
					charon->scheduler->schedule_job(charon->scheduler, job,
													soft * 1000);
				}
				
				if (hard)
				{
					this->time.delete = now + hard;
					job = (job_t*)delete_ike_sa_job_create(this->ike_sa_id, TRUE);
					charon->scheduler->schedule_job(charon->scheduler, job,
													hard * 1000);
				}
			}
			break;
		}
		case IKE_DELETING:
		{
			/* delete may fail if a packet gets lost, so set a timeout */
			job_t *job = (job_t*)delete_ike_sa_job_create(this->ike_sa_id, TRUE);
			charon->scheduler->schedule_job(charon->scheduler, job, 
											HALF_OPEN_IKE_SA_TIMEOUT);
			break;
		}
		default:
			break;
	}
	
	this->state = state;
}

/**
 * Implementation of ike_sa_t.reset
 */
static void reset(private_ike_sa_t *this)
{
	/*  the responder ID is reset, as peer may choose another one */
	if (this->ike_sa_id->is_initiator(this->ike_sa_id))
	{
		this->ike_sa_id->set_responder_spi(this->ike_sa_id, 0);
	}
	
	set_state(this, IKE_CREATED);
	
	this->task_manager->reset(this->task_manager);
}

/**
 * Implementation of ike_sa_t.set_virtual_ip
 */
static void set_virtual_ip(private_ike_sa_t *this, bool local, host_t *ip)
{
	if (local)
	{
		DBG1(DBG_IKE, "installing new virtual IP %H", ip);
		if (this->my_virtual_ip)
		{
			DBG1(DBG_IKE, "removing old virtual IP %H", this->my_virtual_ip);
			charon->kernel_interface->del_ip(charon->kernel_interface,
											 this->my_virtual_ip);
			this->my_virtual_ip->destroy(this->my_virtual_ip);
		}
		if (charon->kernel_interface->add_ip(charon->kernel_interface, ip,
											 this->my_host) == SUCCESS)
		{
			this->my_virtual_ip = ip->clone(ip);
		}
		else
		{
			DBG1(DBG_IKE, "installing virtual IP %H failed", ip);
			this->my_virtual_ip = NULL;
		}
	}
	else
	{
		DESTROY_IF(this->other_virtual_ip);
		this->other_virtual_ip = ip->clone(ip);
	}
}

/**
 * Implementation of ike_sa_t.get_virtual_ip
 */
static host_t* get_virtual_ip(private_ike_sa_t *this, bool local)
{
	if (local)
	{
		return this->my_virtual_ip;
	}
	else
	{
		return this->other_virtual_ip;
	}
}

/**
 * Implementation of ike_sa_t.add_additional_address.
 */
static void add_additional_address(private_ike_sa_t *this, host_t *host)
{
	this->additional_addresses->insert_last(this->additional_addresses, host);
}
	
/**
 * Implementation of ike_sa_t.create_additional_address_iterator.
 */
static iterator_t* create_additional_address_iterator(private_ike_sa_t *this)
{
	return this->additional_addresses->create_iterator(
											this->additional_addresses, TRUE);
}
	
/**
 * Implementation of ike_sa_t.set_pending_updates.
 */
static void set_pending_updates(private_ike_sa_t *this, u_int32_t updates)
{
	this->pending_updates = updates;
}

/**
 * Implementation of ike_sa_t.get_pending_updates.
 */
static u_int32_t get_pending_updates(private_ike_sa_t *this)
{
	return this->pending_updates;
}

/**
 * Update hosts, as addresses may change (NAT)
 */
static void update_hosts(private_ike_sa_t *this, host_t *me, host_t *other)
{
	bool update = FALSE;
	
	if (supports_extension(this, EXT_MOBIKE))
	{	/* if peer speaks mobike, address updates are explicit only */
		return;
	}
	
	if (me == NULL)
	{
		me = this->my_host;
	}
	if (other == NULL)
	{
		other = this->other_host;
	}
	
	/* apply hosts on first received message */
	if (this->my_host->is_anyaddr(this->my_host) ||
		this->other_host->is_anyaddr(this->other_host))
	{
		set_my_host(this, me->clone(me));
		set_other_host(this, other->clone(other));
		update = TRUE;
	}
	else
	{
		/* update our address in any case */
		if (!me->equals(me, this->my_host))
		{
			set_my_host(this, me->clone(me));
			update = TRUE;
		}
		
		if (!other->equals(other, this->other_host))
		{
			/* update others adress if we are NOT NATed,
			 * and allow port changes if we are NATed */
			if (!has_condition(this, COND_NAT_HERE) ||
				other->ip_equals(other, this->other_host))
			{
				set_other_host(this, other->clone(other));
				update = TRUE;
			}
		}
	}
	
	/* update all associated CHILD_SAs, if required */
	if (update)
	{
		iterator_t *iterator;
		child_sa_t *child_sa;
	
		iterator = this->child_sas->create_iterator(this->child_sas, TRUE);
		while (iterator->iterate(iterator, (void**)&child_sa))
		{
			child_sa->update_hosts(child_sa, this->my_host, this->other_host,
								   has_condition(this, COND_NAT_ANY));
		}
		iterator->destroy(iterator);
	}
}

/**
 * Implementation of ike_sa_t.generate
 */
static status_t generate_message(private_ike_sa_t *this, message_t *message,
								 packet_t **packet)
{
	this->time.outbound = time(NULL);
	message->set_ike_sa_id(message, this->ike_sa_id);
	message->set_destination(message, this->other_host->clone(this->other_host));
	message->set_source(message, this->my_host->clone(this->my_host));
	return message->generate(message, this->crypter_out, this->signer_out, packet);
}

/**
 * send a notify back to the sender
 */
static void send_notify_response(private_ike_sa_t *this, message_t *request,
								 notify_type_t type)
{
	message_t *response;
	packet_t *packet;
	
	response = message_create();
	response->set_exchange_type(response, request->get_exchange_type(request));
	response->set_request(response, FALSE);
	response->set_message_id(response, request->get_message_id(request));
	response->add_notify(response, FALSE, type, chunk_empty);
	if (this->my_host->is_anyaddr(this->my_host))
	{
		this->my_host->destroy(this->my_host);
		this->my_host = request->get_destination(request);
		this->my_host = this->my_host->clone(this->my_host);
	}
	if (this->other_host->is_anyaddr(this->other_host))
	{
		this->other_host->destroy(this->other_host);
		this->other_host = request->get_source(request);
		this->other_host = this->other_host->clone(this->other_host);
	}
	if (generate_message(this, response, &packet) == SUCCESS)
	{
		charon->sender->send(charon->sender, packet);
	}
	response->destroy(response);
}

/**
 * Implementation of ike_sa_t.initiate.
 */
static status_t initiate(private_ike_sa_t *this, child_cfg_t *child_cfg)
{
	task_t *task;
	
	if (this->state == IKE_CREATED)
	{
		
		if (this->other_host->is_anyaddr(this->other_host))
		{
			child_cfg->destroy(child_cfg);
			SIG(IKE_UP_START, "initiating IKE_SA");
			SIG(IKE_UP_FAILED, "unable to initiate to %%any");
			return DESTROY_ME;
		}
		
		task = (task_t*)ike_init_create(&this->public, TRUE, NULL);
		this->task_manager->queue_task(this->task_manager, task);
		task = (task_t*)ike_natd_create(&this->public, TRUE);
		this->task_manager->queue_task(this->task_manager, task);
		task = (task_t*)ike_cert_create(&this->public, TRUE);
		this->task_manager->queue_task(this->task_manager, task);
		task = (task_t*)ike_auth_create(&this->public, TRUE);
		this->task_manager->queue_task(this->task_manager, task);
		task = (task_t*)ike_config_create(&this->public, TRUE);
		this->task_manager->queue_task(this->task_manager, task);
		task = (task_t*)ike_mobike_create(&this->public, TRUE);
		this->task_manager->queue_task(this->task_manager, task);
	}
	
	task = (task_t*)child_create_create(&this->public, child_cfg);
	child_cfg->destroy(child_cfg);
	this->task_manager->queue_task(this->task_manager, task);
	
	return this->task_manager->initiate(this->task_manager);
}

/**
 * Implementation of ike_sa_t.acquire.
 */
static status_t acquire(private_ike_sa_t *this, u_int32_t reqid)
{
	child_cfg_t *child_cfg;
	iterator_t *iterator;
	child_sa_t *current, *child_sa = NULL;
	task_t *task;
	child_create_t *child_create;
	
	if (this->state == IKE_DELETING)
	{
		SIG(CHILD_UP_START, "acquiring CHILD_SA on kernel request");
		SIG(CHILD_UP_FAILED, "acquiring CHILD_SA (reqid %d) failed: "
			"IKE_SA is deleting", reqid);
		return FAILED;
	}
	
	/* find CHILD_SA */
	iterator = this->child_sas->create_iterator(this->child_sas, TRUE);
	while (iterator->iterate(iterator, (void**)&current))
	{
		if (current->get_reqid(current) == reqid)
		{
			child_sa = current;
			break;
		}
	}
	iterator->destroy(iterator);
	if (!child_sa)
	{
		SIG(CHILD_UP_START, "acquiring CHILD_SA on kernel request");
		SIG(CHILD_UP_FAILED, "acquiring CHILD_SA (reqid %d) failed: "
			"CHILD_SA not found", reqid);
		return FAILED;
	}
	
	
	if (this->state == IKE_CREATED)
	{
		task = (task_t*)ike_init_create(&this->public, TRUE, NULL);
		this->task_manager->queue_task(this->task_manager, task);
		task = (task_t*)ike_natd_create(&this->public, TRUE);
		this->task_manager->queue_task(this->task_manager, task);
		task = (task_t*)ike_cert_create(&this->public, TRUE);
		this->task_manager->queue_task(this->task_manager, task);
		task = (task_t*)ike_auth_create(&this->public, TRUE);
		this->task_manager->queue_task(this->task_manager, task);
		task = (task_t*)ike_config_create(&this->public, TRUE);
		this->task_manager->queue_task(this->task_manager, task);
		task = (task_t*)ike_mobike_create(&this->public, TRUE);
		this->task_manager->queue_task(this->task_manager, task);
	}
	
	child_cfg = child_sa->get_config(child_sa);
	child_create = child_create_create(&this->public, child_cfg);
	child_create->use_reqid(child_create, reqid);
	this->task_manager->queue_task(this->task_manager, (task_t*)child_create);
	
	return this->task_manager->initiate(this->task_manager);
}

/**
 * Implementation of ike_sa_t.route.
 */
static status_t route(private_ike_sa_t *this, child_cfg_t *child_cfg)
{
	child_sa_t *child_sa;
	iterator_t *iterator;
	linked_list_t *my_ts, *other_ts;
	host_t *me, *other;
	status_t status;
	
	SIG(CHILD_ROUTE_START, "routing CHILD_SA");
	
	/* check if not already routed*/
	iterator = this->child_sas->create_iterator(this->child_sas, TRUE);
	while (iterator->iterate(iterator, (void**)&child_sa))
	{
		if (child_sa->get_state(child_sa) == CHILD_ROUTED &&
			streq(child_sa->get_name(child_sa), child_cfg->get_name(child_cfg)))
		{
			iterator->destroy(iterator);
			SIG(CHILD_ROUTE_FAILED, "CHILD_SA with such a config already routed");
			return FAILED;
		}
	}
	iterator->destroy(iterator);
	
	switch (this->state)
	{
		case IKE_DELETING:
		case IKE_REKEYING:
			SIG(CHILD_ROUTE_FAILED,
				"unable to route CHILD_SA, as its IKE_SA gets deleted");
			return FAILED;
		case IKE_CREATED:
		case IKE_CONNECTING:
		case IKE_ESTABLISHED:
		default:
			break;
	}

	/* install kernel policies */
	child_sa = child_sa_create(this->my_host, this->other_host, this->my_id,
							   this->other_id, child_cfg, FALSE, 0);
	me = this->my_host;
	if (this->my_virtual_ip)
	{
		me = this->my_virtual_ip;
	}
	other = this->other_host;
	if (this->other_virtual_ip)
	{
		other = this->other_virtual_ip;
	}
	
	my_ts = child_cfg->get_traffic_selectors(child_cfg, TRUE, NULL, me);
	other_ts = child_cfg->get_traffic_selectors(child_cfg, FALSE, NULL, other);
	status = child_sa->add_policies(child_sa, my_ts, other_ts,
									child_cfg->get_mode(child_cfg));
	my_ts->destroy_offset(my_ts, offsetof(traffic_selector_t, destroy));
	other_ts->destroy_offset(other_ts, offsetof(traffic_selector_t, destroy));
	if (status == SUCCESS)
	{
		this->child_sas->insert_last(this->child_sas, child_sa);
		SIG(CHILD_ROUTE_SUCCESS, "CHILD_SA routed");
	}
	else
	{
		SIG(CHILD_ROUTE_FAILED, "routing CHILD_SA failed");
	}
	return status;
}

/**
 * Implementation of ike_sa_t.unroute.
 */
static status_t unroute(private_ike_sa_t *this, u_int32_t reqid)
{
	iterator_t *iterator;
	child_sa_t *child_sa;
	bool found = FALSE;
	
	SIG(CHILD_UNROUTE_START, "unrouting CHILD_SA");
	
	/* find CHILD_SA in ROUTED state */
	iterator = this->child_sas->create_iterator(this->child_sas, TRUE);
	while (iterator->iterate(iterator, (void**)&child_sa))
	{
		if (child_sa->get_state(child_sa) == CHILD_ROUTED &&
			child_sa->get_reqid(child_sa) == reqid)
		{
			iterator->remove(iterator);
			SIG(CHILD_UNROUTE_SUCCESS, "CHILD_SA unrouted");
			child_sa->destroy(child_sa);
			found = TRUE;
			break;
		}
	}
	iterator->destroy(iterator);
	
	if (!found)
	{
		SIG(CHILD_UNROUTE_FAILED, "CHILD_SA to unroute not found");
		return FAILED;
	}
	/* if we are not established, and we have no more routed childs, remove whole SA */
	if (this->state == IKE_CREATED &&
		this->child_sas->get_count(this->child_sas) == 0)
	{
		return DESTROY_ME;
	}
	return SUCCESS;
}
/**
 * Implementation of ike_sa_t.process_message.
 */
static status_t process_message(private_ike_sa_t *this, message_t *message)
{
	status_t status;
	bool is_request;
	
	is_request = message->get_request(message);
	
	status = message->parse_body(message, this->crypter_in, this->signer_in);
	if (status != SUCCESS)
	{
		
		if (is_request)
		{
			switch (status)
			{
				case NOT_SUPPORTED:
					DBG1(DBG_IKE, "ciritcal unknown payloads found");
					if (is_request)
					{
						send_notify_response(this, message, UNSUPPORTED_CRITICAL_PAYLOAD);
					}
					break;
				case PARSE_ERROR:
					DBG1(DBG_IKE, "message parsing failed");
					if (is_request)
					{
						send_notify_response(this, message, INVALID_SYNTAX);
					}
					break;
				case VERIFY_ERROR:
					DBG1(DBG_IKE, "message verification failed");
					if (is_request)
					{
						send_notify_response(this, message, INVALID_SYNTAX);
					}
					break;
				case FAILED:
					DBG1(DBG_IKE, "integrity check failed");
					/* ignored */
					break;
				case INVALID_STATE:
					DBG1(DBG_IKE, "found encrypted message, but no keys available");
					if (is_request)
					{
						send_notify_response(this, message, INVALID_SYNTAX);
					}
				default:
					break;
			}
		}
		DBG1(DBG_IKE, "%N %s with message ID %d processing failed",
			 exchange_type_names, message->get_exchange_type(message),
			 message->get_request(message) ? "request" : "response",
			 message->get_message_id(message));
		return status;
	}
	else
	{
		host_t *me, *other;
		private_ike_sa_t *new;
		iterator_t *iterator;
		child_sa_t *child;
		bool has_routed = FALSE;
		
		me = message->get_destination(message);
		other = message->get_source(message);
	
		/* if this IKE_SA is virgin, we check for a config */
		if (this->ike_cfg == NULL)
		{
			job_t *job;
			this->ike_cfg = charon->backends->get_ike_cfg(charon->backends,
														  me, other);
			if (this->ike_cfg == NULL)
			{
				/* no config found for these hosts, destroy */
				DBG1(DBG_IKE, "no IKE config found for %H...%H, sending %N",
					 me, other, notify_type_names, NO_PROPOSAL_CHOSEN);
				send_notify_response(this, message, NO_PROPOSAL_CHOSEN);
				return DESTROY_ME;
			}
			/* add a timeout if peer does not establish it completely */
			job = (job_t*)delete_ike_sa_job_create(this->ike_sa_id, FALSE);
			charon->scheduler->schedule_job(charon->scheduler, job,
											HALF_OPEN_IKE_SA_TIMEOUT);
		}
		
		/* check if message is trustworthy, and update host information */
		if (this->state == IKE_CREATED || this->state == IKE_CONNECTING ||
			message->get_exchange_type(message) != IKE_SA_INIT)
		{
			update_hosts(this, me, other);
			this->time.inbound = time(NULL);
		}
		status = this->task_manager->process_message(this->task_manager, message);
		if (status != DESTROY_ME)
		{
			return status;
		}
		/* if IKE_SA gets closed for any reasons, reroute routed children */
		iterator = this->child_sas->create_iterator(this->child_sas, TRUE);
		while (iterator->iterate(iterator, (void**)&child))
		{
			if (child->get_state(child) == CHILD_ROUTED)
			{
				has_routed = TRUE;
				break;
			}
		}
		iterator->destroy(iterator);
		if (!has_routed)
		{
			return status;
		}
		/* move routed children to a new IKE_SA, apply connection info */
		new = (private_ike_sa_t*)charon->ike_sa_manager->checkout_new(
											charon->ike_sa_manager, TRUE);
		set_peer_cfg(new, this->peer_cfg);
		new->other_host->destroy(new->other_host);
		new->other_host = this->other_host->clone(this->other_host);
		if (!has_condition(this, COND_NAT_THERE))
		{
			new->other_host->set_port(new->other_host, IKEV2_UDP_PORT);
		}
		if (this->my_virtual_ip)
		{
			set_virtual_ip(new, TRUE, this->my_virtual_ip);
		}
		iterator = this->child_sas->create_iterator(this->child_sas, TRUE);
		while (iterator->iterate(iterator, (void**)&child))
		{
			if (child->get_state(child) == CHILD_ROUTED)
			{
				route(new, child->get_config(child));
			}
		}
		iterator->destroy(iterator);
		charon->ike_sa_manager->checkin(charon->ike_sa_manager, &new->public);
		return status;
	}
}

/**
 * Implementation of ike_sa_t.retransmit.
 */
static status_t retransmit(private_ike_sa_t *this, u_int32_t message_id)
{
	this->time.outbound = time(NULL);
	if (this->task_manager->retransmit(this->task_manager, message_id) != SUCCESS)
	{
		child_cfg_t *child_cfg;
		child_sa_t* child_sa;
		linked_list_t *to_route, *to_restart;
		iterator_t *iterator;
		
		/* send a proper signal to brief interested bus listeners */
		switch (this->state)
		{
			case IKE_CONNECTING:
			{
				/* retry IKE_SA_INIT if we have multiple keyingtries */
				u_int32_t tries = this->peer_cfg->get_keyingtries(this->peer_cfg);
				this->keyingtry++;
				if (tries == 0 || tries > this->keyingtry)
				{
					SIG(IKE_UP_FAILED, "peer not responding, trying again "
						"(%d/%d) in background ", this->keyingtry + 1, tries);
					reset(this);
					return this->task_manager->initiate(this->task_manager);
				}
				SIG(IKE_UP_FAILED, "establishing IKE_SA failed, peer not responding");
				break;
			}
			case IKE_REKEYING:
				SIG(IKE_REKEY_FAILED, "rekeying IKE_SA failed, peer not responding");
				break;
			case IKE_DELETING:
				SIG(IKE_DOWN_FAILED, "proper IKE_SA delete failed, peer not responding");
				break;
			default:
				break;
		}
		
		/* summarize how we have to handle each child */
		to_route = linked_list_create();
		to_restart = linked_list_create();
		iterator = this->child_sas->create_iterator(this->child_sas, TRUE);
		while (iterator->iterate(iterator, (void**)&child_sa))
		{
			child_cfg = child_sa->get_config(child_sa);
			
			if (child_sa->get_state(child_sa) == CHILD_ROUTED)
			{
				/* reroute routed CHILD_SAs */
				to_route->insert_last(to_route, child_cfg);
			}
			else
			{
				/* use DPD action for established CHILD_SAs */
				switch (this->peer_cfg->get_dpd_action(this->peer_cfg))
				{
					case DPD_ROUTE:
						to_route->insert_last(to_route, child_cfg);
						break;
					case DPD_RESTART:
						to_restart->insert_last(to_restart, child_cfg);
						break;
					default:
						break;
				}
			}
		}
		iterator->destroy(iterator);
		
		/* create a new IKE_SA if we have to route or to restart */
		if (to_route->get_count(to_route) || to_restart->get_count(to_restart))
		{
			private_ike_sa_t *new;
			task_t *task;
			
			new = (private_ike_sa_t*)charon->ike_sa_manager->checkout_new(
												charon->ike_sa_manager, TRUE);
			
			set_peer_cfg(new, this->peer_cfg);
			/* use actual used host, not the wildcarded one in config */
			new->other_host->destroy(new->other_host);
			new->other_host = this->other_host->clone(this->other_host);
			/* reset port to 500, but only if peer is not NATed */
			if (!has_condition(this, COND_NAT_THERE))
			{
				new->other_host->set_port(new->other_host, IKEV2_UDP_PORT);
			}
			/* take over virtual ip, as we need it for a proper route */
			if (this->my_virtual_ip)
			{
				set_virtual_ip(new, TRUE, this->my_virtual_ip);
			}
			
			/* install routes */
			while (to_route->remove_last(to_route, (void**)&child_cfg) == SUCCESS)
			{
				route(new, child_cfg);
			}
			
			/* restart children */
			if (to_restart->get_count(to_restart))
			{
				task = (task_t*)ike_init_create(&new->public, TRUE, NULL);
				new->task_manager->queue_task(new->task_manager, task);
				task = (task_t*)ike_natd_create(&new->public, TRUE);
				new->task_manager->queue_task(new->task_manager, task);
				task = (task_t*)ike_cert_create(&new->public, TRUE);
				new->task_manager->queue_task(new->task_manager, task);
				task = (task_t*)ike_config_create(&new->public, TRUE);
				new->task_manager->queue_task(new->task_manager, task);
				task = (task_t*)ike_auth_create(&new->public, TRUE);
				new->task_manager->queue_task(new->task_manager, task);
				
				while (to_restart->remove_last(to_restart, (void**)&child_cfg) == SUCCESS)
				{
					task = (task_t*)child_create_create(&new->public, child_cfg);
					new->task_manager->queue_task(new->task_manager, task);
				}
				task = (task_t*)ike_mobike_create(&new->public, TRUE);
				new->task_manager->queue_task(new->task_manager, task);
				new->task_manager->initiate(new->task_manager);
			}
			charon->ike_sa_manager->checkin(charon->ike_sa_manager, &new->public);
		}
		to_route->destroy(to_route);
		to_restart->destroy(to_restart);
		return DESTROY_ME;
	}
	return SUCCESS;
}

/**
 * Implementation of ike_sa_t.get_prf.
 */
static prf_t *get_prf(private_ike_sa_t *this)
{
	return this->prf;
}

/**
 * Implementation of ike_sa_t.get_prf.
 */
static prf_t *get_child_prf(private_ike_sa_t *this)
{
	return this->child_prf;
}

/**
 * Implementation of ike_sa_t.get_skp_bild
 */
static chunk_t get_skp_build(private_ike_sa_t *this)
{
	return this->skp_build;
}

/**
 * Implementation of ike_sa_t.get_skp_verify
 */
static chunk_t get_skp_verify(private_ike_sa_t *this)
{
	return this->skp_verify;
}

/**
 * Implementation of ike_sa_t.get_id.
 */
static ike_sa_id_t* get_id(private_ike_sa_t *this)
{
	return this->ike_sa_id;
}

/**
 * Implementation of ike_sa_t.get_my_id.
 */
static identification_t* get_my_id(private_ike_sa_t *this)
{
	return this->my_id;
}

/**
 * Implementation of ike_sa_t.set_my_id.
 */
static void set_my_id(private_ike_sa_t *this, identification_t *me)
{
	DESTROY_IF(this->my_id);
	this->my_id = me;
}

/**
 * Implementation of ike_sa_t.get_other_id.
 */
static identification_t* get_other_id(private_ike_sa_t *this)
{
	return this->other_id;
}

/**
 * Implementation of ike_sa_t.set_other_id.
 */
static void set_other_id(private_ike_sa_t *this, identification_t *other)
{
	DESTROY_IF(this->other_id);
	this->other_id = other;
}

/**
 * Implementation of ike_sa_t.get_other_ca.
 */
static ca_info_t* get_other_ca(private_ike_sa_t *this)
{
	return this->other_ca;
}

/**
 * Implementation of ike_sa_t.set_other_ca.
 */
static void set_other_ca(private_ike_sa_t *this, ca_info_t *other_ca)
{
	this->other_ca = other_ca;
}

/**
 * Implementation of ike_sa_t.derive_keys.
 */
static status_t derive_keys(private_ike_sa_t *this,
							proposal_t *proposal, chunk_t secret,
							chunk_t nonce_i, chunk_t nonce_r,
							bool initiator, prf_t *child_prf, prf_t *old_prf)
{
	prf_plus_t *prf_plus;
	chunk_t skeyseed, key, nonces, prf_plus_seed;
	algorithm_t *algo;
	size_t key_size;
	crypter_t *crypter_i, *crypter_r;
	signer_t *signer_i, *signer_r;
	u_int8_t spi_i_buf[sizeof(u_int64_t)], spi_r_buf[sizeof(u_int64_t)];
	chunk_t spi_i = chunk_from_buf(spi_i_buf);
	chunk_t spi_r = chunk_from_buf(spi_r_buf);
	
	/* Create SAs general purpose PRF first, we may use it here */
	if (!proposal->get_algorithm(proposal, PSEUDO_RANDOM_FUNCTION, &algo))
	{
		DBG1(DBG_IKE, "key derivation failed: no PSEUDO_RANDOM_FUNCTION");;
		return FAILED;
	}
	this->prf = prf_create(algo->algorithm);
	if (this->prf == NULL)
	{
		DBG1(DBG_IKE, "key derivation failed: PSEUDO_RANDOM_FUNCTION "
			 "%N not supported!", pseudo_random_function_names, algo->algorithm);
		return FAILED;
	}
	
	DBG4(DBG_IKE, "shared Diffie Hellman secret %B", &secret);
	nonces = chunk_cat("cc", nonce_i, nonce_r);
	*((u_int64_t*)spi_i.ptr) = this->ike_sa_id->get_initiator_spi(this->ike_sa_id);
	*((u_int64_t*)spi_r.ptr) = this->ike_sa_id->get_responder_spi(this->ike_sa_id);
	prf_plus_seed = chunk_cat("ccc", nonces, spi_i, spi_r);
	
	/* KEYMAT = prf+ (SKEYSEED, Ni | Nr | SPIi | SPIr) 
	 *
	 * if we are rekeying, SKEYSEED is built on another way
	 */
	if (child_prf == NULL) /* not rekeying */
	{
		/* SKEYSEED = prf(Ni | Nr, g^ir) */
		this->prf->set_key(this->prf, nonces);
		this->prf->allocate_bytes(this->prf, secret, &skeyseed);
		DBG4(DBG_IKE, "SKEYSEED %B", &skeyseed);
		this->prf->set_key(this->prf, skeyseed);
		chunk_free(&skeyseed);
		chunk_free(&secret);
		prf_plus = prf_plus_create(this->prf, prf_plus_seed);
	}
	else
	{
		/* SKEYSEED = prf(SK_d (old), [g^ir (new)] | Ni | Nr) 
		 * use OLD SAs PRF functions for both prf_plus and prf */
		secret = chunk_cat("mc", secret, nonces);
		child_prf->allocate_bytes(child_prf, secret, &skeyseed);
		DBG4(DBG_IKE, "SKEYSEED %B", &skeyseed);
		old_prf->set_key(old_prf, skeyseed);
		chunk_free(&skeyseed);
		chunk_free(&secret);
		prf_plus = prf_plus_create(old_prf, prf_plus_seed);
	}
	chunk_free(&nonces);
	chunk_free(&prf_plus_seed);
	
	/* KEYMAT = SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr */
	
	/* SK_d is used for generating CHILD_SA key mat => child_prf */
	proposal->get_algorithm(proposal, PSEUDO_RANDOM_FUNCTION, &algo);
	this->child_prf = prf_create(algo->algorithm);
	key_size = this->child_prf->get_key_size(this->child_prf);
	prf_plus->allocate_bytes(prf_plus, key_size, &key);
	DBG4(DBG_IKE, "Sk_d secret %B", &key);
	this->child_prf->set_key(this->child_prf, key);
	chunk_free(&key);
	
	/* SK_ai/SK_ar used for integrity protection => signer_in/signer_out */
	if (!proposal->get_algorithm(proposal, INTEGRITY_ALGORITHM, &algo))
	{
		DBG1(DBG_IKE, "key derivation failed: no INTEGRITY_ALGORITHM");
		return FAILED;
	}
	signer_i = signer_create(algo->algorithm);
	signer_r = signer_create(algo->algorithm);
	if (signer_i == NULL || signer_r == NULL)
	{
		DBG1(DBG_IKE, "key derivation failed: INTEGRITY_ALGORITHM "
			"%N not supported!", integrity_algorithm_names ,algo->algorithm);
		return FAILED;
	}
	key_size = signer_i->get_key_size(signer_i);
	
	prf_plus->allocate_bytes(prf_plus, key_size, &key);
	DBG4(DBG_IKE, "Sk_ai secret %B", &key);
	signer_i->set_key(signer_i, key);
	chunk_free(&key);
	
	prf_plus->allocate_bytes(prf_plus, key_size, &key);
	DBG4(DBG_IKE, "Sk_ar secret %B", &key);
	signer_r->set_key(signer_r, key);
	chunk_free(&key);
	
	if (initiator)
	{
		this->signer_in = signer_r;
		this->signer_out = signer_i;
	}
	else
	{
		this->signer_in = signer_i;
		this->signer_out = signer_r;
	}
	
	/* SK_ei/SK_er used for encryption => crypter_in/crypter_out */
	if (!proposal->get_algorithm(proposal, ENCRYPTION_ALGORITHM, &algo))
	{
		DBG1(DBG_IKE, "key derivation failed: no ENCRYPTION_ALGORITHM");
		return FAILED;
	}
	crypter_i = crypter_create(algo->algorithm, algo->key_size / 8);
	crypter_r = crypter_create(algo->algorithm, algo->key_size / 8);
	if (crypter_i == NULL || crypter_r == NULL)
	{
		DBG1(DBG_IKE, "key derivation failed: ENCRYPTION_ALGORITHM "
			"%N (key size %d) not supported!",
			encryption_algorithm_names, algo->algorithm, algo->key_size);
		return FAILED;
	}
	key_size = crypter_i->get_key_size(crypter_i);
	
	prf_plus->allocate_bytes(prf_plus, key_size, &key);
	DBG4(DBG_IKE, "Sk_ei secret %B", &key);
	crypter_i->set_key(crypter_i, key);
	chunk_free(&key);
	
	prf_plus->allocate_bytes(prf_plus, key_size, &key);
	DBG4(DBG_IKE, "Sk_er secret %B", &key);
	crypter_r->set_key(crypter_r, key);
	chunk_free(&key);
	
	if (initiator)
	{
		this->crypter_in = crypter_r;
		this->crypter_out = crypter_i;
	}
	else
	{
		this->crypter_in = crypter_i;
		this->crypter_out = crypter_r;
	}
	
	/* SK_pi/SK_pr used for authentication => stored for later */	
	key_size = this->prf->get_key_size(this->prf);
	prf_plus->allocate_bytes(prf_plus, key_size, &key);
	DBG4(DBG_IKE, "Sk_pi secret %B", &key);
	if (initiator)
	{
		this->skp_build = key;
	}
	else
	{
		this->skp_verify = key;
	}
	prf_plus->allocate_bytes(prf_plus, key_size, &key);
	DBG4(DBG_IKE, "Sk_pr secret %B", &key);
	if (initiator)
	{
		this->skp_verify = key;
	}
	else
	{
		this->skp_build = key;
	}
	
	/* all done, prf_plus not needed anymore */
	prf_plus->destroy(prf_plus);
	
	return SUCCESS;
}

/**
 * Implementation of ike_sa_t.add_child_sa.
 */
static void add_child_sa(private_ike_sa_t *this, child_sa_t *child_sa)
{
	this->child_sas->insert_last(this->child_sas, child_sa);
}

/**
 * Implementation of ike_sa_t.get_child_sa.
 */
static child_sa_t* get_child_sa(private_ike_sa_t *this, protocol_id_t protocol,
								u_int32_t spi, bool inbound)
{
	iterator_t *iterator;
	child_sa_t *current, *found = NULL;
	
	iterator = this->child_sas->create_iterator(this->child_sas, TRUE);
	while (iterator->iterate(iterator, (void**)&current))
	{
		if (current->get_spi(current, inbound) == spi &&
			current->get_protocol(current) == protocol)
		{
			found = current;
		}
	}
	iterator->destroy(iterator);
	return found;
}

/**
 * Implementation of ike_sa_t.create_child_sa_iterator.
 */
static iterator_t* create_child_sa_iterator(private_ike_sa_t *this)
{
	return this->child_sas->create_iterator(this->child_sas, TRUE);
}

/**
 * Implementation of ike_sa_t.rekey_child_sa.
 */
static status_t rekey_child_sa(private_ike_sa_t *this, protocol_id_t protocol, u_int32_t spi)
{
	child_sa_t *child_sa;
	child_rekey_t *child_rekey;
	
	child_sa = get_child_sa(this, protocol, spi, TRUE);
	if (child_sa)
	{
		child_rekey = child_rekey_create(&this->public, child_sa);
		this->task_manager->queue_task(this->task_manager, &child_rekey->task);
		return this->task_manager->initiate(this->task_manager);
	}
	return FAILED;
}

/**
 * Implementation of ike_sa_t.delete_child_sa.
 */
static status_t delete_child_sa(private_ike_sa_t *this, protocol_id_t protocol, u_int32_t spi)
{
	child_sa_t *child_sa;
	child_delete_t *child_delete;
	
	child_sa = get_child_sa(this, protocol, spi, TRUE);
	if (child_sa)
	{
		child_delete = child_delete_create(&this->public, child_sa);
		this->task_manager->queue_task(this->task_manager, &child_delete->task);
		return this->task_manager->initiate(this->task_manager);
	}
	return FAILED;
}

/**
 * Implementation of ike_sa_t.destroy_child_sa.
 */
static status_t destroy_child_sa(private_ike_sa_t *this, protocol_id_t protocol,
								 u_int32_t spi)
{
	iterator_t *iterator;
	child_sa_t *child_sa;
	status_t status = NOT_FOUND;
	
	iterator = this->child_sas->create_iterator(this->child_sas, TRUE);
	while (iterator->iterate(iterator, (void**)&child_sa))
	{
		if (child_sa->get_protocol(child_sa) == protocol &&
			child_sa->get_spi(child_sa, TRUE) == spi)
		{
			child_sa->destroy(child_sa);
			iterator->remove(iterator);
			status = SUCCESS;
			break;
		}
	}
	iterator->destroy(iterator);
	return status;
}

/**
 * Implementation of public_ike_sa_t.delete.
 */
static status_t delete_(private_ike_sa_t *this)
{
	ike_delete_t *ike_delete;

	switch (this->state)
	{
		case IKE_ESTABLISHED:
		case IKE_REKEYING:
			ike_delete = ike_delete_create(&this->public, TRUE);
			this->task_manager->queue_task(this->task_manager, &ike_delete->task);
			return this->task_manager->initiate(this->task_manager);
		case IKE_CREATED:
			SIG(IKE_DOWN_SUCCESS, "deleting unestablished IKE_SA");
			break;
		default:
			SIG(IKE_DOWN_SUCCESS, "destroying IKE_SA in state %N "
				"without notification", ike_sa_state_names, this->state);
			break;
	}
	return DESTROY_ME;
}

/**
 * Implementation of ike_sa_t.rekey.
 */
static status_t rekey(private_ike_sa_t *this)
{
	ike_rekey_t *ike_rekey;
	
	ike_rekey = ike_rekey_create(&this->public, TRUE);
	
	this->task_manager->queue_task(this->task_manager, &ike_rekey->task);
	return this->task_manager->initiate(this->task_manager);
}

/**
 * Implementation of ike_sa_t.reestablish
 */
static status_t reestablish(private_ike_sa_t *this)
{
	task_t *task;
	
	task = (task_t*)ike_reauth_create(&this->public);
	this->task_manager->queue_task(this->task_manager, task);
	
	return this->task_manager->initiate(this->task_manager);
}

/**
 * Implementation of ike_sa_t.roam.
 */
static status_t roam(private_ike_sa_t *this, bool address)
{
	host_t *me, *other;
	ike_mobike_t *mobike;
	
	/* responder just updates the peer about changed address config */
	if (!this->ike_sa_id->is_initiator(this->ike_sa_id))
	{
		if (supports_extension(this, EXT_MOBIKE) && address)
		{
			DBG1(DBG_IKE, "sending address list update using MOBIKE");
			mobike = ike_mobike_create(&this->public, TRUE);
			this->task_manager->queue_task(this->task_manager, (task_t*)mobike);
			return this->task_manager->initiate(this->task_manager);
		}
		return SUCCESS;
	}
	
	/* get best address pair to use */
	other = this->other_host;
	me = charon->kernel_interface->get_source_addr(charon->kernel_interface,
												   other);
												   
	/* TODO: find a better path using additional addresses of peer */
	
	if (!me)
	{
		/* no route found to host, set to stale, wait for a new route */
		set_condition(this, COND_STALE, TRUE);
		return FAILED;
	}
	
	set_condition(this, COND_STALE, FALSE);
	if (me->ip_equals(me, this->my_host) &&
		other->ip_equals(other, this->other_host))
	{
		DBG2(DBG_IKE, "%H still reached through %H, no update needed",
			 this->other_host, me);
		me->destroy(me);
		return SUCCESS;
	}
	me->set_port(me, this->my_host->get_port(this->my_host));
	other = other->clone(other);
	other->set_port(other, this->other_host->get_port(this->other_host));
	set_my_host(this, me);
	set_other_host(this, other);
	
	/* update addresses with mobike, if supported ... */
	if (supports_extension(this, EXT_MOBIKE))
	{
		DBG1(DBG_IKE, "requesting address change using MOBIKE");
		mobike = ike_mobike_create(&this->public, TRUE);
		mobike->roam(mobike, address);
		this->task_manager->queue_task(this->task_manager, (task_t*)mobike);
		return this->task_manager->initiate(this->task_manager);
	}
	DBG1(DBG_IKE, "reestablishing IKE_SA due address change");
	/* ... reestablish if not */
	return reestablish(this);
}

/**
 * Implementation of ike_sa_t.inherit.
 */
static status_t inherit(private_ike_sa_t *this, private_ike_sa_t *other)
{
	child_sa_t *child_sa;
	host_t *ip;
	
	/* apply hosts and ids */
	this->my_host->destroy(this->my_host);
	this->other_host->destroy(this->other_host);
	this->my_id->destroy(this->my_id);
	this->other_id->destroy(this->other_id);
	this->my_host = other->my_host->clone(other->my_host);
	this->other_host = other->other_host->clone(other->other_host);
	this->my_id = other->my_id->clone(other->my_id);
	this->other_id = other->other_id->clone(other->other_id);
	
	/* apply virtual assigned IPs... */
	if (other->my_virtual_ip)
	{
		this->my_virtual_ip = other->my_virtual_ip;
		other->my_virtual_ip = NULL;
	}
	if (other->other_virtual_ip)
	{
		this->other_virtual_ip = other->other_virtual_ip;
		other->other_virtual_ip = NULL;
	}
	
	/* ... and DNS servers */
	while (other->dns_servers->remove_last(other->dns_servers, 
										   (void**)&ip) == SUCCESS)
	{
		this->dns_servers->insert_first(this->dns_servers, ip);
	}
	
	/* adopt all children */
	while (other->child_sas->remove_last(other->child_sas,
		   								 (void**)&child_sa) == SUCCESS)
	{
		this->child_sas->insert_first(this->child_sas, (void*)child_sa);
	}
	
	/* move pending tasks to the new IKE_SA */
	this->task_manager->adopt_tasks(this->task_manager, other->task_manager);
	
	/* we have to initate here, there may be new tasks to handle */
	return this->task_manager->initiate(this->task_manager);
}

/**
 * Implementation of ike_sa_t.remove_dns_server
 */
static void remove_dns_servers(private_ike_sa_t *this)
{
	FILE *file;
	struct stat stats;
	chunk_t contents, line, orig_line, token;
	char string[INET6_ADDRSTRLEN];
	host_t *ip;
	iterator_t *iterator;
	
	if (this->dns_servers->get_count(this->dns_servers) == 0)
	{
		/* don't touch anything if we have no nameservers installed */
		return;
	}
	
	file = fopen(RESOLV_CONF, "r");
	if (file == NULL || stat(RESOLV_CONF, &stats) != 0)
	{
		DBG1(DBG_IKE, "unable to open DNS configuration file %s: %s",
			 RESOLV_CONF, strerror(errno));
		return;
	}
	
	contents = chunk_alloca((size_t)stats.st_size);
	
	if (fread(contents.ptr, 1, contents.len, file) != contents.len)
	{
		DBG1(DBG_IKE, "unable to read DNS configuration file: %s", strerror(errno));
		fclose(file);
		return;
	}
	
	fclose(file);
	file = fopen(RESOLV_CONF, "w");
	if (file == NULL)
	{
		DBG1(DBG_IKE, "unable to open DNS configuration file %s: %s",
			 RESOLV_CONF, strerror(errno));
		return;
	}
	
	iterator = this->dns_servers->create_iterator(this->dns_servers, TRUE);
	while (fetchline(&contents, &line))
	{
		bool found = FALSE;
		orig_line = line;
		if (extract_token(&token, ' ', &line) &&
			strncasecmp(token.ptr, "nameserver", token.len) == 0)
		{
			if (!extract_token(&token, ' ', &line))
			{
				token = line;
			}
			iterator->reset(iterator);
			while (iterator->iterate(iterator, (void**)&ip))
			{
				snprintf(string, sizeof(string), "%H", ip);
				if (strlen(string) == token.len &&
					strncmp(token.ptr, string, token.len) == 0)
				{
					iterator->remove(iterator);
					ip->destroy(ip);
					found = TRUE;
					break;
				}
			}
		}		
		
		if (!found)
		{	
			/* write line untouched back to file */
			fwrite(orig_line.ptr, orig_line.len, 1, file);
			fprintf(file, "\n");
		}
	}
	iterator->destroy(iterator);
	fclose(file);
}

/**
 * Implementation of ike_sa_t.add_dns_server
 */
static void add_dns_server(private_ike_sa_t *this, host_t *dns)
{
	FILE *file;
	struct stat stats;
	chunk_t contents;

	DBG1(DBG_IKE, "installing DNS server %H", dns);
	
	file = fopen(RESOLV_CONF, "a+");
	if (file == NULL || stat(RESOLV_CONF, &stats) != 0)
	{
		DBG1(DBG_IKE, "unable to open DNS configuration file %s: %s",
			 RESOLV_CONF, strerror(errno));
		return;
	}

	contents = chunk_alloca(stats.st_size);
	
	if (fread(contents.ptr, 1, contents.len, file) != contents.len)
	{
		DBG1(DBG_IKE, "unable to read DNS configuration file: %s", strerror(errno));
		fclose(file);
		return;
	}
	
	fclose(file);
	file = fopen(RESOLV_CONF, "w");
	if (file == NULL)
	{
		DBG1(DBG_IKE, "unable to open DNS configuration file %s: %s",
			 RESOLV_CONF, strerror(errno));
		return;
	}
	
	if (fprintf(file, "nameserver %H   # added by strongSwan, assigned by %D\n",
		dns, this->other_id) < 0)
	{
		DBG1(DBG_IKE, "unable to write DNS configuration: %s", strerror(errno));
	}
	else
	{
		this->dns_servers->insert_last(this->dns_servers, dns->clone(dns));
	}
	fwrite(contents.ptr, contents.len, 1, file);
	
	fclose(file);	
}

/**
 * Implementation of ike_sa_t.destroy.
 */
static void destroy(private_ike_sa_t *this)
{
	this->child_sas->destroy_offset(this->child_sas, offsetof(child_sa_t, destroy));
	
	DESTROY_IF(this->crypter_in);
	DESTROY_IF(this->crypter_out);
	DESTROY_IF(this->signer_in);
	DESTROY_IF(this->signer_out);
	DESTROY_IF(this->prf);
	DESTROY_IF(this->child_prf);
	chunk_free(&this->skp_verify);
	chunk_free(&this->skp_build);
	
	if (this->my_virtual_ip)
	{
		charon->kernel_interface->del_ip(charon->kernel_interface,
										 this->my_virtual_ip);
		this->my_virtual_ip->destroy(this->my_virtual_ip);
	}
	DESTROY_IF(this->other_virtual_ip);
	
	remove_dns_servers(this);
	this->dns_servers->destroy_offset(this->dns_servers,
													offsetof(host_t, destroy));
	this->additional_addresses->destroy_offset(this->additional_addresses,
													offsetof(host_t, destroy));
	
	DESTROY_IF(this->my_host);
	DESTROY_IF(this->other_host);
	DESTROY_IF(this->my_id);
	DESTROY_IF(this->other_id);
	
	DESTROY_IF(this->ike_cfg);
	DESTROY_IF(this->peer_cfg);
	
	this->ike_sa_id->destroy(this->ike_sa_id);
	this->task_manager->destroy(this->task_manager);
	free(this);
}

/*
 * Described in header.
 */
ike_sa_t * ike_sa_create(ike_sa_id_t *ike_sa_id)
{
	private_ike_sa_t *this = malloc_thing(private_ike_sa_t);
	static u_int32_t unique_id = 0;
	
	/* Public functions */
	this->public.get_state = (ike_sa_state_t (*)(ike_sa_t*)) get_state;
	this->public.set_state = (void (*)(ike_sa_t*,ike_sa_state_t)) set_state;
	this->public.get_stats = (void (*)(ike_sa_t*,u_int32_t*))get_stats;
	this->public.get_name = (char* (*)(ike_sa_t*))get_name;
	this->public.process_message = (status_t (*)(ike_sa_t*, message_t*)) process_message;
	this->public.initiate = (status_t (*)(ike_sa_t*,child_cfg_t*)) initiate;
	this->public.route = (status_t (*)(ike_sa_t*,child_cfg_t*)) route;
	this->public.unroute = (status_t (*)(ike_sa_t*,u_int32_t)) unroute;
	this->public.acquire = (status_t (*)(ike_sa_t*,u_int32_t)) acquire;
	this->public.get_ike_cfg = (ike_cfg_t* (*)(ike_sa_t*))get_ike_cfg;
	this->public.set_ike_cfg = (void (*)(ike_sa_t*,ike_cfg_t*))set_ike_cfg;
	this->public.get_peer_cfg = (peer_cfg_t* (*)(ike_sa_t*))get_peer_cfg;
	this->public.set_peer_cfg = (void (*)(ike_sa_t*,peer_cfg_t*))set_peer_cfg;
	this->public.get_id = (ike_sa_id_t* (*)(ike_sa_t*)) get_id;
	this->public.get_my_host = (host_t* (*)(ike_sa_t*)) get_my_host;
	this->public.set_my_host = (void (*)(ike_sa_t*,host_t*)) set_my_host;
	this->public.get_other_host = (host_t* (*)(ike_sa_t*)) get_other_host;
	this->public.set_other_host = (void (*)(ike_sa_t*,host_t*)) set_other_host;
	this->public.update_hosts = (void(*)(ike_sa_t*, host_t *me, host_t *other))update_hosts;
	this->public.get_my_id = (identification_t* (*)(ike_sa_t*)) get_my_id;
	this->public.set_my_id = (void (*)(ike_sa_t*,identification_t*)) set_my_id;
	this->public.get_other_id = (identification_t* (*)(ike_sa_t*)) get_other_id;
	this->public.set_other_id = (void (*)(ike_sa_t*,identification_t*)) set_other_id;
	this->public.get_other_ca = (ca_info_t* (*)(ike_sa_t*)) get_other_ca;
	this->public.set_other_ca = (void (*)(ike_sa_t*,ca_info_t*)) set_other_ca;
	this->public.enable_extension = (void(*)(ike_sa_t*, ike_extension_t extension))enable_extension;
	this->public.supports_extension = (bool(*)(ike_sa_t*, ike_extension_t extension))supports_extension;
	this->public.set_condition = (void (*)(ike_sa_t*, ike_condition_t,bool)) set_condition;
	this->public.has_condition = (bool (*)(ike_sa_t*,ike_condition_t)) has_condition;
	this->public.set_pending_updates = (void(*)(ike_sa_t*, u_int32_t updates))set_pending_updates;
	this->public.get_pending_updates = (u_int32_t(*)(ike_sa_t*))get_pending_updates;
	this->public.create_additional_address_iterator = (iterator_t*(*)(ike_sa_t*))create_additional_address_iterator;
	this->public.add_additional_address = (void(*)(ike_sa_t*, host_t *host))add_additional_address;
	this->public.retransmit = (status_t (*)(ike_sa_t *, u_int32_t)) retransmit;
	this->public.delete = (status_t (*)(ike_sa_t*))delete_;
	this->public.destroy = (void (*)(ike_sa_t*))destroy;
	this->public.send_dpd = (status_t (*)(ike_sa_t*)) send_dpd;
	this->public.send_keepalive = (void (*)(ike_sa_t*)) send_keepalive;
	this->public.get_prf = (prf_t* (*)(ike_sa_t*)) get_prf;
	this->public.get_child_prf = (prf_t* (*)(ike_sa_t *)) get_child_prf;
	this->public.get_skp_verify = (chunk_t (*)(ike_sa_t *)) get_skp_verify;
	this->public.get_skp_build = (chunk_t (*)(ike_sa_t *)) get_skp_build;
	this->public.derive_keys = (status_t (*)(ike_sa_t *,proposal_t*,chunk_t,chunk_t,chunk_t,bool,prf_t*,prf_t*)) derive_keys;
	this->public.add_child_sa = (void (*)(ike_sa_t*,child_sa_t*)) add_child_sa;
	this->public.get_child_sa = (child_sa_t* (*)(ike_sa_t*,protocol_id_t,u_int32_t,bool)) get_child_sa;
	this->public.create_child_sa_iterator = (iterator_t* (*)(ike_sa_t*)) create_child_sa_iterator;
	this->public.rekey_child_sa = (status_t (*)(ike_sa_t*,protocol_id_t,u_int32_t)) rekey_child_sa;
	this->public.delete_child_sa = (status_t (*)(ike_sa_t*,protocol_id_t,u_int32_t)) delete_child_sa;
	this->public.destroy_child_sa = (status_t (*)(ike_sa_t*,protocol_id_t,u_int32_t))destroy_child_sa;
	this->public.rekey = (status_t (*)(ike_sa_t*))rekey;
	this->public.reestablish = (status_t (*)(ike_sa_t*))reestablish;
	this->public.roam = (status_t(*)(ike_sa_t*,bool))roam;
	this->public.inherit = (status_t (*)(ike_sa_t*,ike_sa_t*))inherit;
	this->public.generate_message = (status_t (*)(ike_sa_t*,message_t*,packet_t**))generate_message;
	this->public.reset = (void (*)(ike_sa_t*))reset;
	this->public.get_unique_id = (u_int32_t (*)(ike_sa_t*))get_unique_id;
	this->public.set_virtual_ip = (void (*)(ike_sa_t*,bool,host_t*))set_virtual_ip;
	this->public.get_virtual_ip = (host_t* (*)(ike_sa_t*,bool))get_virtual_ip;
	this->public.add_dns_server = (void (*)(ike_sa_t*,host_t*))add_dns_server;
	
	/* initialize private fields */
	this->ike_sa_id = ike_sa_id->clone(ike_sa_id);
	this->child_sas = linked_list_create();
	this->my_host = host_create_any(AF_INET);
	this->other_host = host_create_any(AF_INET);
	this->my_id = identification_create_from_encoding(ID_ANY, chunk_empty);
	this->other_id = identification_create_from_encoding(ID_ANY, chunk_empty);
	this->other_ca = NULL;
	this->extensions = 0;
	this->conditions = 0;
	this->crypter_in = NULL;
	this->crypter_out = NULL;
	this->signer_in = NULL;
	this->signer_out = NULL;
	this->prf = NULL;
	this->skp_verify = chunk_empty;
	this->skp_build = chunk_empty;
 	this->child_prf = NULL;
	this->state = IKE_CREATED;
	this->time.inbound = this->time.outbound = time(NULL);
	this->time.established = 0;
	this->time.rekey = 0;
	this->time.delete = 0;
	this->ike_cfg = NULL;
	this->peer_cfg = NULL;
	this->task_manager = task_manager_create(&this->public);
	this->unique_id = ++unique_id;
	this->my_virtual_ip = NULL;
	this->other_virtual_ip = NULL;
	this->dns_servers = linked_list_create();
	this->additional_addresses = linked_list_create();
	this->pending_updates = 0;
	this->keyingtry = 0;
	
	return &this->public;
}
