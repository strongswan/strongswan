/*
 * Copyright (C) 2006-2008 Tobias Brunner
 * Copyright (C) 2006 Daniel Roethlisberger
 * Copyright (C) 2005-2009 Martin Willi
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

#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>

#include "ike_sa.h"

#include <library.h>
#include <daemon.h>
#include <utils/linked_list.h>
#include <utils/lexparser.h>
#include <sa/task_manager.h>
#include <sa/tasks/ike_init.h>
#include <sa/tasks/ike_natd.h>
#include <sa/tasks/ike_mobike.h>
#include <sa/tasks/ike_auth.h>
#include <sa/tasks/ike_auth_lifetime.h>
#include <sa/tasks/ike_config.h>
#include <sa/tasks/ike_cert_pre.h>
#include <sa/tasks/ike_cert_post.h>
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

#ifdef ME
#include <sa/tasks/ike_me.h>
#include <processing/jobs/initiate_mediation_job.h>
#endif

ENUM(ike_sa_state_names, IKE_CREATED, IKE_DESTROYING,
	"CREATED",
	"CONNECTING",
	"ESTABLISHED",
	"PASSIVE",
	"REKEYING",
	"DELETING",
	"DESTROYING",
);

typedef struct private_ike_sa_t private_ike_sa_t;
typedef struct attribute_entry_t attribute_entry_t;

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
	 * currently used authentication ruleset, local (as auth_cfg_t)
	 */
	auth_cfg_t *my_auth;

	/**
	 * currently used authentication constraints, remote (as auth_cfg_t)
	 */
	auth_cfg_t *other_auth;

	/**
	 * Selected IKE proposal
	 */
	proposal_t *proposal;

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

#ifdef ME
	/**
	 * Are we mediation server
	 */
	bool is_mediation_server;

	/**
	 * Server reflexive host
	 */
	host_t *server_reflexive_host;

	/**
	 * Connect ID
	 */
	chunk_t connect_id;
#endif /* ME */

	/**
	 * Identification used for us
	 */
	identification_t *my_id;

	/**
	 * Identification used for other
	 */
	identification_t *other_id;

	/**
	 * EAP Identity exchange in EAP-Identity method
	 */
	identification_t *eap_identity;;

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
	 * keymat of this IKE_SA
	 */
	keymat_t *keymat;

	/**
	 * Virtual IP on local host, if any
	 */
	host_t *my_virtual_ip;

	/**
	 * Virtual IP on remote host, if any
	 */
	host_t *other_virtual_ip;

	/**
	 * List of configuration attributes (attribute_entry_t)
	 */
	linked_list_t *attributes;

	/**
	 * list of peers additional addresses, transmitted via MOBIKE
	 */
	linked_list_t *additional_addresses;

	/**
	 * previously value of received DESTINATION_IP hash
	 */
	chunk_t nat_detection_dest;

	/**
	 * number pending UPDATE_SA_ADDRESS (MOBIKE)
	 */
	u_int32_t pending_updates;

	/**
	 * NAT keep alive interval
	 */
	u_int32_t keepalive_interval;

	/**
	 * Timestamps for this IKE_SA
	 */
	u_int32_t stats[STAT_MAX];

	/**
	 * how many times we have retried so far (keyingtries)
	 */
	u_int32_t keyingtry;

	/**
	 * local host address to be used for IKE, set via MIGRATE kernel message
	 */
	host_t *local_host;

	/**
	 * remote host address to be used for IKE, set via MIGRATE kernel message
	 */
	host_t *remote_host;
};

/**
 * Entry to maintain install configuration attributes during IKE_SA lifetime
 */
struct attribute_entry_t {
	/** handler used to install this attribute */
	attribute_handler_t *handler;
	/** attribute type */
	configuration_attribute_type_t type;
	/** attribute data */
	chunk_t data;
};

/**
 * get the time of the latest traffic processed by the kernel
 */
static time_t get_use_time(private_ike_sa_t* this, bool inbound)
{
	enumerator_t *enumerator;
	child_sa_t *child_sa;
	time_t use_time, current;

	if (inbound)
	{
		use_time = this->stats[STAT_INBOUND];
	}
	else
	{
		use_time = this->stats[STAT_OUTBOUND];
	}
	enumerator = this->child_sas->create_enumerator(this->child_sas);
	while (enumerator->enumerate(enumerator, &child_sa))
	{
		child_sa->get_usestats(child_sa, inbound, &current, NULL);
		use_time = max(use_time, current);
	}
	enumerator->destroy(enumerator);

	return use_time;
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
 * Implementation of ike_sa_t.get_statistic.
 */
static u_int32_t get_statistic(private_ike_sa_t *this, statistic_t kind)
{
	if (kind < STAT_MAX)
	{
		return this->stats[kind];
	}
	return 0;
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
	DESTROY_IF(this->peer_cfg);
	peer_cfg->get_ref(peer_cfg);
	this->peer_cfg = peer_cfg;

	if (this->ike_cfg == NULL)
	{
		this->ike_cfg = peer_cfg->get_ike_cfg(peer_cfg);
		this->ike_cfg->get_ref(this->ike_cfg);
	}
}

/**
 * Implementation of ike_sa_t.get_auth_cfg
 */
static auth_cfg_t* get_auth_cfg(private_ike_sa_t *this, bool local)
{
	if (local)
	{
		return this->my_auth;
	}
	return this->other_auth;
}

/**
 * Implementation of ike_sa_t.get_proposal
 */
static proposal_t* get_proposal(private_ike_sa_t *this)
{
	return this->proposal;
}

/**
 * Implementation of ike_sa_t.set_proposal
 */
static void set_proposal(private_ike_sa_t *this, proposal_t *proposal)
{
	DESTROY_IF(this->proposal);
	this->proposal = proposal->clone(proposal);
}

/**
 * Implementation of ike_sa_t.set_message_id
 */
static void set_message_id(private_ike_sa_t *this, bool initiate, u_int32_t mid)
{
	if (initiate)
	{
		this->task_manager->reset(this->task_manager, mid, UINT_MAX);
	}
	else
	{
		this->task_manager->reset(this->task_manager, UINT_MAX, mid);
	}
}

/**
 * Implementation of ike_sa_t.send_keepalive
 */
static void send_keepalive(private_ike_sa_t *this)
{
	send_keepalive_job_t *job;
	time_t last_out, now, diff;

	if (!(this->conditions & COND_NAT_HERE) || this->keepalive_interval == 0)
	{	/* disable keep alives if we are not NATed anymore */
		return;
	}

	last_out = get_use_time(this, FALSE);
	now = time_monotonic(NULL);

	diff = now - last_out;

	if (diff >= this->keepalive_interval)
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
									this->keepalive_interval - diff);
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
				case COND_NAT_HERE:
					DBG1(DBG_IKE, "local host is behind NAT, sending keep alives");
					this->conditions |= COND_NAT_ANY;
					send_keepalive(this);
					break;
				case COND_NAT_THERE:
					DBG1(DBG_IKE, "remote host is behind NAT");
					this->conditions |= COND_NAT_ANY;
					break;
				case COND_NAT_FAKE:
					DBG1(DBG_IKE, "faking NAT situation to enforce UDP encapsulation");
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
				case COND_NAT_HERE:
				case COND_NAT_FAKE:
				case COND_NAT_THERE:
					set_condition(this, COND_NAT_ANY,
								  has_condition(this, COND_NAT_HERE) ||
								  has_condition(this, COND_NAT_THERE) ||
								  has_condition(this, COND_NAT_FAKE));
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
	job_t *job;
	time_t diff, delay;

	delay = this->peer_cfg->get_dpd(this->peer_cfg);

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
		now = time_monotonic(NULL);
		diff = now - last_in;
		if (diff >= delay)
		{
			/* to long ago, initiate dead peer detection */
			task_t *task;
			ike_mobike_t *mobike;

			if (supports_extension(this, EXT_MOBIKE) &&
				has_condition(this, COND_NAT_HERE))
			{
				/* use mobike enabled DPD to detect NAT mapping changes */
				mobike = ike_mobike_create(&this->public, TRUE);
				mobike->dpd(mobike);
				task = &mobike->task;
			}
			else
			{
				task = (task_t*)ike_dpd_create(TRUE);
			}
			diff = 0;
			DBG1(DBG_IKE, "sending DPD request");

			this->task_manager->queue_task(this->task_manager, task);
			this->task_manager->initiate(this->task_manager);
		}
	}
	/* recheck in "interval" seconds */
	job = (job_t*)send_dpd_job_create(this->ike_sa_id);
	charon->scheduler->schedule_job(charon->scheduler, job, delay - diff);
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
	DBG2(DBG_IKE, "IKE_SA %s[%d] state change: %N => %N",
		 get_name(this), this->unique_id,
		 ike_sa_state_names, this->state,
		 ike_sa_state_names, state);

	switch (state)
	{
		case IKE_ESTABLISHED:
		{
			if (this->state == IKE_CONNECTING ||
				this->state == IKE_PASSIVE)
			{
				job_t *job;
				u_int32_t t;

				/* calculate rekey, reauth and lifetime */
				this->stats[STAT_ESTABLISHED] = time_monotonic(NULL);

				/* schedule rekeying if we have a time which is smaller than
				 * an already scheduled rekeying */
				t = this->peer_cfg->get_rekey_time(this->peer_cfg);
				if (t && (this->stats[STAT_REKEY] == 0 ||
					(this->stats[STAT_REKEY] > t + this->stats[STAT_ESTABLISHED])))
				{
					this->stats[STAT_REKEY] = t + this->stats[STAT_ESTABLISHED];
					job = (job_t*)rekey_ike_sa_job_create(this->ike_sa_id, FALSE);
					charon->scheduler->schedule_job(charon->scheduler, job, t);
					DBG1(DBG_IKE, "scheduling rekeying in %ds", t);
				}
				t = this->peer_cfg->get_reauth_time(this->peer_cfg);
				if (t && (this->stats[STAT_REAUTH] == 0 ||
					(this->stats[STAT_REAUTH] > t + this->stats[STAT_ESTABLISHED])))
				{
					this->stats[STAT_REAUTH] = t + this->stats[STAT_ESTABLISHED];
					job = (job_t*)rekey_ike_sa_job_create(this->ike_sa_id, TRUE);
					charon->scheduler->schedule_job(charon->scheduler, job, t);
					DBG1(DBG_IKE, "scheduling reauthentication in %ds", t);
				}
				t = this->peer_cfg->get_over_time(this->peer_cfg);
				if (this->stats[STAT_REKEY] || this->stats[STAT_REAUTH])
				{
					if (this->stats[STAT_REAUTH] == 0)
					{
						this->stats[STAT_DELETE] = this->stats[STAT_REKEY];
					}
					else if (this->stats[STAT_REKEY] == 0)
					{
						this->stats[STAT_DELETE] = this->stats[STAT_REAUTH];
					}
					else
					{
						this->stats[STAT_DELETE] = min(this->stats[STAT_REKEY],
													   this->stats[STAT_REAUTH]);
					}
					this->stats[STAT_DELETE] += t;
					t = this->stats[STAT_DELETE] - this->stats[STAT_ESTABLISHED];
					job = (job_t*)delete_ike_sa_job_create(this->ike_sa_id, TRUE);
					charon->scheduler->schedule_job(charon->scheduler, job, t);
					DBG1(DBG_IKE, "maximum IKE_SA lifetime %ds", t);
				}

				/* start DPD checks */
				send_dpd(this);
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
	charon->bus->ike_state_change(charon->bus, &this->public, state);
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

	this->task_manager->reset(this->task_manager, 0, 0);
}

/**
 * Implementation of ike_sa_t.get_keymat
 */
static keymat_t* get_keymat(private_ike_sa_t *this)
{
	return this->keymat;
}

/**
 * Implementation of ike_sa_t.set_virtual_ip
 */
static void set_virtual_ip(private_ike_sa_t *this, bool local, host_t *ip)
{
	if (local)
	{
		DBG1(DBG_IKE, "installing new virtual IP %H", ip);
		if (charon->kernel_interface->add_ip(charon->kernel_interface, ip,
											 this->my_host) == SUCCESS)
		{
			if (this->my_virtual_ip)
			{
				DBG1(DBG_IKE, "removing old virtual IP %H", this->my_virtual_ip);
				charon->kernel_interface->del_ip(charon->kernel_interface,
												 this->my_virtual_ip);
			}
			DESTROY_IF(this->my_virtual_ip);
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
 * Implementation of ike_sa_t.has_mapping_changed
 */
static bool has_mapping_changed(private_ike_sa_t *this, chunk_t hash)
{
	if (this->nat_detection_dest.ptr == NULL)
	{
		this->nat_detection_dest = chunk_clone(hash);
		return FALSE;
	}
	if (chunk_equals(hash, this->nat_detection_dest))
	{
		return FALSE;
	}
	free(this->nat_detection_dest.ptr);
	this->nat_detection_dest = chunk_clone(hash);
	return TRUE;
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
			if (child_sa->update(child_sa, this->my_host,
						this->other_host, this->my_virtual_ip,
						has_condition(this, COND_NAT_ANY)) == NOT_SUPPORTED)
			{
				this->public.rekey_child_sa(&this->public,
						child_sa->get_protocol(child_sa),
						child_sa->get_spi(child_sa, TRUE));
			}
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
	this->stats[STAT_OUTBOUND] = time_monotonic(NULL);
	message->set_ike_sa_id(message, this->ike_sa_id);
	return message->generate(message,
				this->keymat->get_crypter(this->keymat, FALSE),
				this->keymat->get_signer(this->keymat, FALSE), packet);
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
	response->set_source(response, this->my_host->clone(this->my_host));
	response->set_destination(response, this->other_host->clone(this->other_host));
	if (generate_message(this, response, &packet) == SUCCESS)
	{
		charon->sender->send(charon->sender, packet);
	}
	response->destroy(response);
}

/**
 * Implementation of ike_sa_t.set_kmaddress.
 */
static void set_kmaddress(private_ike_sa_t *this, host_t *local, host_t *remote)
{
	DESTROY_IF(this->local_host);
	DESTROY_IF(this->remote_host);
	this->local_host = local->clone(local);
	this->remote_host = remote->clone(remote);
}

#ifdef ME
/**
 * Implementation of ike_sa_t.act_as_mediation_server.
 */
static void act_as_mediation_server(private_ike_sa_t *this)
{
	charon->mediation_manager->update_sa_id(charon->mediation_manager,
			this->other_id, this->ike_sa_id);
	this->is_mediation_server = TRUE;
}

/**
 * Implementation of ike_sa_t.get_server_reflexive_host.
 */
static host_t *get_server_reflexive_host(private_ike_sa_t *this)
{
	return this->server_reflexive_host;
}

/**
 * Implementation of ike_sa_t.set_server_reflexive_host.
 */
static void set_server_reflexive_host(private_ike_sa_t *this, host_t *host)
{
	DESTROY_IF(this->server_reflexive_host);
	this->server_reflexive_host = host;
}

/**
 * Implementation of ike_sa_t.get_connect_id.
 */
static chunk_t get_connect_id(private_ike_sa_t *this)
{
	return this->connect_id;
}

/**
 * Implementation of ike_sa_t.respond
 */
static status_t respond(private_ike_sa_t *this, identification_t *peer_id,
						chunk_t connect_id)
{
	ike_me_t *task = ike_me_create(&this->public, TRUE);
	task->respond(task, peer_id, connect_id);
	this->task_manager->queue_task(this->task_manager, (task_t*)task);
	return this->task_manager->initiate(this->task_manager);
}

/**
 * Implementation of ike_sa_t.callback
 */
static status_t callback(private_ike_sa_t *this, identification_t *peer_id)
{
	ike_me_t *task = ike_me_create(&this->public, TRUE);
	task->callback(task, peer_id);
	this->task_manager->queue_task(this->task_manager, (task_t*)task);
	return this->task_manager->initiate(this->task_manager);
}

/**
 * Implementation of ike_sa_t.relay
 */
static status_t relay(private_ike_sa_t *this, identification_t *requester,
					  chunk_t connect_id, chunk_t connect_key,
					  linked_list_t *endpoints, bool response)
{
	ike_me_t *task = ike_me_create(&this->public, TRUE);
	task->relay(task, requester, connect_id, connect_key, endpoints, response);
	this->task_manager->queue_task(this->task_manager, (task_t*)task);
	return this->task_manager->initiate(this->task_manager);
}

/**
 * Implementation of ike_sa_t.initiate_mediation
 */
static status_t initiate_mediation(private_ike_sa_t *this,
								   peer_cfg_t *mediated_cfg)
{
	ike_me_t *task = ike_me_create(&this->public, TRUE);
	task->connect(task, mediated_cfg->get_peer_id(mediated_cfg));
	this->task_manager->queue_task(this->task_manager, (task_t*)task);
	return this->task_manager->initiate(this->task_manager);
}

/**
 * Implementation of ike_sa_t.initiate_mediated
 */
static status_t initiate_mediated(private_ike_sa_t *this, host_t *me,
								  host_t *other, chunk_t connect_id)
{
	set_my_host(this, me->clone(me));
	set_other_host(this, other->clone(other));
	chunk_free(&this->connect_id);
	this->connect_id = chunk_clone(connect_id);
	return this->task_manager->initiate(this->task_manager);
}
#endif /* ME */

/**
 * Resolve DNS host in configuration
 */
static void resolve_hosts(private_ike_sa_t *this)
{
	host_t *host;

	if (this->remote_host)
	{
		host = this->remote_host->clone(this->remote_host);
		host->set_port(host, IKEV2_UDP_PORT);
	}
	else
	{
		host = host_create_from_dns(this->ike_cfg->get_other_addr(this->ike_cfg),
									0, IKEV2_UDP_PORT);
	}
	if (host)
	{
		set_other_host(this, host);
	}

	if (this->local_host)
	{
		host = this->local_host->clone(this->local_host);
		host->set_port(host, IKEV2_UDP_PORT);
	}
	else
	{
		int family = 0;

		/* use same address family as for other */
		if (!this->other_host->is_anyaddr(this->other_host))
		{
			family = this->other_host->get_family(this->other_host);
		}
		host = host_create_from_dns(this->ike_cfg->get_my_addr(this->ike_cfg),
									family, IKEV2_UDP_PORT);

		if (host && host->is_anyaddr(host) &&
			!this->other_host->is_anyaddr(this->other_host))
		{
			host->destroy(host);
			host = charon->kernel_interface->get_source_addr(
							charon->kernel_interface, this->other_host, NULL);
			if (host)
			{
				host->set_port(host, IKEV2_UDP_PORT);
			}
			else
			{	/* fallback to address family specific %any(6), if configured */
				host = host_create_from_dns(
									this->ike_cfg->get_my_addr(this->ike_cfg),
									0, IKEV2_UDP_PORT);
			}
		}
	}
	if (host)
	{
		set_my_host(this, host);
	}
}

/**
 * Implementation of ike_sa_t.initiate
 */
static status_t initiate(private_ike_sa_t *this,
						 child_cfg_t *child_cfg, u_int32_t reqid,
						 traffic_selector_t *tsi, traffic_selector_t *tsr)
{
	task_t *task;

	if (this->state == IKE_CREATED)
	{
		resolve_hosts(this);

		if (this->other_host->is_anyaddr(this->other_host)
#ifdef ME
			&& !this->peer_cfg->get_mediated_by(this->peer_cfg)
#endif /* ME */
			)
		{
			child_cfg->destroy(child_cfg);
			DBG1(DBG_IKE, "unable to initiate to %%any");
			return DESTROY_ME;
		}

		set_condition(this, COND_ORIGINAL_INITIATOR, TRUE);

		task = (task_t*)ike_init_create(&this->public, TRUE, NULL);
		this->task_manager->queue_task(this->task_manager, task);
		task = (task_t*)ike_natd_create(&this->public, TRUE);
		this->task_manager->queue_task(this->task_manager, task);
		task = (task_t*)ike_cert_pre_create(&this->public, TRUE);
		this->task_manager->queue_task(this->task_manager, task);
		task = (task_t*)ike_auth_create(&this->public, TRUE);
		this->task_manager->queue_task(this->task_manager, task);
		task = (task_t*)ike_cert_post_create(&this->public, TRUE);
		this->task_manager->queue_task(this->task_manager, task);
		task = (task_t*)ike_config_create(&this->public, TRUE);
		this->task_manager->queue_task(this->task_manager, task);
		task = (task_t*)ike_auth_lifetime_create(&this->public, TRUE);
		this->task_manager->queue_task(this->task_manager, task);
		if (this->peer_cfg->use_mobike(this->peer_cfg))
		{
			task = (task_t*)ike_mobike_create(&this->public, TRUE);
			this->task_manager->queue_task(this->task_manager, task);
		}
#ifdef ME
		task = (task_t*)ike_me_create(&this->public, TRUE);
		this->task_manager->queue_task(this->task_manager, task);
#endif /* ME */
	}

#ifdef ME
	if (this->peer_cfg->is_mediation(this->peer_cfg))
	{
		if (this->state == IKE_ESTABLISHED)
		{
			/* mediation connection is already established, retrigger state
			 * change to notify bus listeners */
			DBG1(DBG_IKE, "mediation connection is already up");
			set_state(this, IKE_ESTABLISHED);
		}
		DESTROY_IF(child_cfg);
	}
	else
#endif /* ME */
	{
		/* normal IKE_SA with CHILD_SA */
		task = (task_t*)child_create_create(&this->public, child_cfg, FALSE,
											tsi, tsr);
		child_cfg->destroy(child_cfg);
		if (reqid)
		{
			child_create_t *child_create = (child_create_t*)task;
			child_create->use_reqid(child_create, reqid);
		}
		this->task_manager->queue_task(this->task_manager, task);

#ifdef ME
		if (this->peer_cfg->get_mediated_by(this->peer_cfg))
		{
			/* mediated connection, initiate mediation process */
			job_t *job = (job_t*)initiate_mediation_job_create(this->ike_sa_id);
			charon->processor->queue_job(charon->processor, job);
			return SUCCESS;
		}
#endif /* ME */
	}

	return this->task_manager->initiate(this->task_manager);
}

/**
 * Implementation of ike_sa_t.process_message.
 */
static status_t process_message(private_ike_sa_t *this, message_t *message)
{
	status_t status;
	bool is_request;

	if (this->state == IKE_PASSIVE)
	{	/* do not handle messages in passive state */
		return FAILED;
	}

	is_request = message->get_request(message);

	status = message->parse_body(message,
								 this->keymat->get_crypter(this->keymat, TRUE),
								 this->keymat->get_signer(this->keymat, TRUE));
	if (status != SUCCESS)
	{

		if (is_request)
		{
			switch (status)
			{
				case NOT_SUPPORTED:
					DBG1(DBG_IKE, "critical unknown payloads found");
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

		if (this->state == IKE_CREATED)
		{	/* invalid initiation attempt, close SA */
			return DESTROY_ME;
		}
		return status;
	}
	else
	{
		host_t *me, *other;

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
		this->stats[STAT_INBOUND] = time_monotonic(NULL);
		/* check if message is trustworthy, and update host information */
		if (this->state == IKE_CREATED || this->state == IKE_CONNECTING ||
			message->get_exchange_type(message) != IKE_SA_INIT)
		{
			if (!supports_extension(this, EXT_MOBIKE))
			{	/* with MOBIKE, we do no implicit updates */
				update_hosts(this, me, other);
			}
		}
		return this->task_manager->process_message(this->task_manager, message);
	}
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
 * Implementation of ike_sa_t.get_eap_identity.
 */
static identification_t* get_eap_identity(private_ike_sa_t *this)
{
	return this->eap_identity;
}

/**
 * Implementation of ike_sa_t.set_eap_identity.
 */
static void set_eap_identity(private_ike_sa_t *this, identification_t *id)
{
	DESTROY_IF(this->eap_identity);
	this->eap_identity = id;
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
static status_t rekey_child_sa(private_ike_sa_t *this, protocol_id_t protocol,
							   u_int32_t spi)
{
	child_rekey_t *child_rekey;

	child_rekey = child_rekey_create(&this->public, protocol, spi);
	this->task_manager->queue_task(this->task_manager, &child_rekey->task);
	return this->task_manager->initiate(this->task_manager);
}

/**
 * Implementation of ike_sa_t.delete_child_sa.
 */
static status_t delete_child_sa(private_ike_sa_t *this, protocol_id_t protocol,
								u_int32_t spi)
{
	child_delete_t *child_delete;

	child_delete = child_delete_create(&this->public, protocol, spi);
	this->task_manager->queue_task(this->task_manager, &child_delete->task);
	return this->task_manager->initiate(this->task_manager);
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
			DBG1(DBG_IKE, "deleting unestablished IKE_SA");
			break;
		case IKE_PASSIVE:
			break;
		default:
			DBG1(DBG_IKE, "destroying IKE_SA in state %N "
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
 * Implementation of ike_sa_t.reauth
 */
static status_t reauth(private_ike_sa_t *this)
{
	task_t *task;

	/* we can't reauthenticate as responder when we use EAP or virtual IPs.
	 * If the peer does not support RFC4478, there is no way to keep the
	 * IKE_SA up. */
	if (!has_condition(this, COND_ORIGINAL_INITIATOR))
	{
		DBG1(DBG_IKE, "initiator did not reauthenticate as requested");
		if (this->other_virtual_ip != NULL ||
			has_condition(this, COND_EAP_AUTHENTICATED)
#ifdef ME
			/* as mediation server we too cannot reauth the IKE_SA */
			|| this->is_mediation_server
#endif /* ME */
			)
		{
			time_t now = time_monotonic(NULL);

			DBG1(DBG_IKE, "IKE_SA will timeout in %V",
				 &now, &this->stats[STAT_DELETE]);
			return FAILED;
		}
		else
		{
			DBG1(DBG_IKE, "reauthenticating actively");
		}
	}
	task = (task_t*)ike_reauth_create(&this->public);
	this->task_manager->queue_task(this->task_manager, task);

	return this->task_manager->initiate(this->task_manager);
}

/**
 * Implementation of ike_sa_t.reestablish
 */
static status_t reestablish(private_ike_sa_t *this)
{
	ike_sa_t *new;
	host_t *host;
	action_t action;
	iterator_t *iterator;
	child_sa_t *child_sa;
	child_cfg_t *child_cfg;
	bool restart = FALSE;
	status_t status = FAILED;

	/* check if we have children to keep up at all */
	iterator = create_child_sa_iterator(this);
	while (iterator->iterate(iterator, (void**)&child_sa))
	{
		child_cfg = child_sa->get_config(child_sa);
		if (this->state == IKE_DELETING)
		{
			action = child_cfg->get_close_action(child_cfg);
		}
		else
		{
			action = child_cfg->get_dpd_action(child_cfg);
		}
		switch (action)
		{
			case ACTION_RESTART:
				restart = TRUE;
				break;
			case ACTION_ROUTE:
				charon->traps->install(charon->traps, this->peer_cfg, child_cfg);
				break;
			default:
				break;
		}
	}
	iterator->destroy(iterator);
#ifdef ME
	/* mediation connections have no children, keep them up anyway */
	if (this->peer_cfg->is_mediation(this->peer_cfg))
	{
		restart = TRUE;
	}
#endif /* ME */
	if (!restart)
	{
		return FAILED;
	}

	/* check if we are able to reestablish this IKE_SA */
	if (!has_condition(this, COND_ORIGINAL_INITIATOR) &&
		(this->other_virtual_ip != NULL ||
		 has_condition(this, COND_EAP_AUTHENTICATED)
#ifdef ME
		 || this->is_mediation_server
#endif /* ME */
		))
	{
		DBG1(DBG_IKE, "unable to reestablish IKE_SA due asymetric setup");
		return FAILED;
	}

	new = charon->ike_sa_manager->checkout_new(charon->ike_sa_manager, TRUE);
	new->set_peer_cfg(new, this->peer_cfg);
	host = this->other_host;
	new->set_other_host(new, host->clone(host));
	host = this->my_host;
	new->set_my_host(new, host->clone(host));
	/* if we already have a virtual IP, we reuse it */
	host = this->my_virtual_ip;
	if (host)
	{
		new->set_virtual_ip(new, TRUE, host);
	}

#ifdef ME
	if (this->peer_cfg->is_mediation(this->peer_cfg))
	{
		status = new->initiate(new, NULL, 0, NULL, NULL);
	}
	else
#endif /* ME */
	{
		iterator = create_child_sa_iterator(this);
		while (iterator->iterate(iterator, (void**)&child_sa))
		{
			child_cfg = child_sa->get_config(child_sa);
			if (this->state == IKE_DELETING)
			{
				action = child_cfg->get_close_action(child_cfg);
			}
			else
			{
				action = child_cfg->get_dpd_action(child_cfg);
			}
			switch (action)
			{
				case ACTION_RESTART:
					DBG1(DBG_IKE, "restarting CHILD_SA %s",
						 child_cfg->get_name(child_cfg));
					child_cfg->get_ref(child_cfg);
					status = new->initiate(new, child_cfg, 0, NULL, NULL);
					break;
				default:
					continue;
			}
			if (status == DESTROY_ME)
			{
				break;
			}
		}
		iterator->destroy(iterator);
	}

	if (status == DESTROY_ME)
	{
		charon->ike_sa_manager->checkin_and_destroy(charon->ike_sa_manager, new);
		status = FAILED;
	}
	else
	{
		charon->ike_sa_manager->checkin(charon->ike_sa_manager, new);
		status = SUCCESS;
	}
	charon->bus->set_sa(charon->bus, &this->public);
	return status;
}

/**
 * Implementation of ike_sa_t.retransmit.
 */
static status_t retransmit(private_ike_sa_t *this, u_int32_t message_id)
{
	this->stats[STAT_OUTBOUND] = time_monotonic(NULL);
	if (this->task_manager->retransmit(this->task_manager, message_id) != SUCCESS)
	{
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
					DBG1(DBG_IKE, "peer not responding, trying again (%d/%d)",
						 this->keyingtry + 1, tries);
					reset(this);
					return this->task_manager->initiate(this->task_manager);
				}
				DBG1(DBG_IKE, "establishing IKE_SA failed, peer not responding");
				break;
			}
			case IKE_DELETING:
				DBG1(DBG_IKE, "proper IKE_SA delete failed, peer not responding");
				break;
			case IKE_REKEYING:
				DBG1(DBG_IKE, "rekeying IKE_SA failed, peer not responding");
				/* FALL */
			default:
				reestablish(this);
				break;
		}
		return DESTROY_ME;
	}
	return SUCCESS;
}

/**
 * Implementation of ike_sa_t.set_auth_lifetime.
 */
static void set_auth_lifetime(private_ike_sa_t *this, u_int32_t lifetime)
{
	u_int32_t reduction = this->peer_cfg->get_over_time(this->peer_cfg);
	u_int32_t reauth_time = time_monotonic(NULL) + lifetime - reduction;

	if (lifetime < reduction)
	{
		DBG1(DBG_IKE, "received AUTH_LIFETIME of %ds, starting reauthentication",
			 lifetime);
		charon->processor->queue_job(charon->processor,
					(job_t*)rekey_ike_sa_job_create(this->ike_sa_id, TRUE));
	}
	else if (this->stats[STAT_REAUTH] == 0 ||
			 this->stats[STAT_REAUTH] > reauth_time)
	{
		this->stats[STAT_REAUTH] = reauth_time;
		DBG1(DBG_IKE, "received AUTH_LIFETIME of %ds, scheduling reauthentication"
			 " in %ds", lifetime, lifetime - reduction);
		charon->scheduler->schedule_job(charon->scheduler,
						(job_t*)rekey_ike_sa_job_create(this->ike_sa_id, TRUE),
						lifetime - reduction);
	}
	else
	{
		DBG1(DBG_IKE, "received AUTH_LIFETIME of %ds, "
			 "reauthentication already scheduled in %ds", lifetime,
			 this->stats[STAT_REAUTH] - time_monotonic(NULL));
	}
}

/**
 * Implementation of ike_sa_t.roam.
 */
static status_t roam(private_ike_sa_t *this, bool address)
{
	host_t *src;
	ike_mobike_t *mobike;

	switch (this->state)
	{
		case IKE_CREATED:
		case IKE_DELETING:
		case IKE_DESTROYING:
		case IKE_PASSIVE:
			return SUCCESS;
		default:
			break;
	}
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

	/* keep existing path if possible */
	src = charon->kernel_interface->get_source_addr(charon->kernel_interface,
											this->other_host, this->my_host);
	if (src)
	{
		if (src->ip_equals(src, this->my_host))
		{
			DBG2(DBG_IKE, "keeping connection path %H - %H",
				 src, this->other_host);
			src->destroy(src);
			set_condition(this, COND_STALE, FALSE);
			return SUCCESS;
		}
		src->destroy(src);

	}
	else
	{
		/* check if we find a route at all */
		enumerator_t *enumerator;
		host_t *addr;

		src = charon->kernel_interface->get_source_addr(charon->kernel_interface,
														this->other_host, NULL);
		if (!src)
		{
			enumerator = this->additional_addresses->create_enumerator(
													this->additional_addresses);
			while (enumerator->enumerate(enumerator, &addr))
			{
				DBG1(DBG_IKE, "looking for a route to %H ...", addr);
				src = charon->kernel_interface->get_source_addr(
										charon->kernel_interface, addr, NULL);
				if (src)
				{
					break;
				}
			}
			enumerator->destroy(enumerator);
		}
		if (!src)
		{
			DBG1(DBG_IKE, "no route found to reach %H, MOBIKE update deferred",
				 this->other_host);
			set_condition(this, COND_STALE, TRUE);
			return SUCCESS;
		}
		src->destroy(src);
	}
	set_condition(this, COND_STALE, FALSE);

	/* update addresses with mobike, if supported ... */
	if (supports_extension(this, EXT_MOBIKE))
	{
		DBG1(DBG_IKE, "requesting address change using MOBIKE");
		mobike = ike_mobike_create(&this->public, TRUE);
		mobike->roam(mobike, address);
		this->task_manager->queue_task(this->task_manager, (task_t*)mobike);
		return this->task_manager->initiate(this->task_manager);
	}
	DBG1(DBG_IKE, "reauthenticating IKE_SA due to address change");
	/* ... reauth if not */
	return reauth(this);
}

/**
 * Implementation of ike_sa_t.add_configuration_attribute
 */
static void add_configuration_attribute(private_ike_sa_t *this,
							configuration_attribute_type_t type, chunk_t data)
{
	attribute_entry_t *entry;
	attribute_handler_t *handler;

	handler = lib->attributes->handle(lib->attributes, this->other_id,
									  type, data);
	if (handler)
	{
		entry = malloc_thing(attribute_entry_t);
		entry->handler = handler;
		entry->type = type;
		entry->data = chunk_clone(data);

		this->attributes->insert_last(this->attributes, entry);
	}
}

/**
 * Implementation of ike_sa_t.inherit.
 */
static status_t inherit(private_ike_sa_t *this, private_ike_sa_t *other)
{
	child_sa_t *child_sa;
	attribute_entry_t *entry;

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

	/* ... and configuration attributes */
	while (other->attributes->remove_last(other->attributes,
										  (void**)&entry) == SUCCESS)
	{
		this->attributes->insert_first(this->attributes, entry);
	}

	/* inherit all conditions */
	this->conditions = other->conditions;
	if (this->conditions & COND_NAT_HERE)
	{
		send_keepalive(this);
	}

#ifdef ME
	if (other->is_mediation_server)
	{
		act_as_mediation_server(this);
	}
	else if (other->server_reflexive_host)
	{
		this->server_reflexive_host = other->server_reflexive_host->clone(
				other->server_reflexive_host);
	}
#endif /* ME */

	/* adopt all children */
	while (other->child_sas->remove_last(other->child_sas,
										 (void**)&child_sa) == SUCCESS)
	{
		this->child_sas->insert_first(this->child_sas, (void*)child_sa);
	}

	/* move pending tasks to the new IKE_SA */
	this->task_manager->adopt_tasks(this->task_manager, other->task_manager);

	/* reauthentication timeout survives a rekeying */
	if (other->stats[STAT_REAUTH])
	{
		time_t reauth, delete, now = time_monotonic(NULL);

		this->stats[STAT_REAUTH] = other->stats[STAT_REAUTH];
		reauth = this->stats[STAT_REAUTH] - now;
		delete = reauth + this->peer_cfg->get_over_time(this->peer_cfg);
		this->stats[STAT_DELETE] = this->stats[STAT_REAUTH] + delete;
		DBG1(DBG_IKE, "rescheduling reauthentication in %ds after rekeying, "
			 "lifetime reduced to %ds", reauth, delete);
		charon->scheduler->schedule_job(charon->scheduler,
				(job_t*)rekey_ike_sa_job_create(this->ike_sa_id, TRUE), reauth);
		charon->scheduler->schedule_job(charon->scheduler,
				(job_t*)delete_ike_sa_job_create(this->ike_sa_id, TRUE), delete);
	}
	/* we have to initate here, there may be new tasks to handle */
	return this->task_manager->initiate(this->task_manager);
}

/**
 * Implementation of ike_sa_t.destroy.
 */
static void destroy(private_ike_sa_t *this)
{
	attribute_entry_t *entry;

	charon->bus->set_sa(charon->bus, &this->public);

	set_state(this, IKE_DESTROYING);

	/* remove attributes first, as we pass the IKE_SA to the handler */
	while (this->attributes->remove_last(this->attributes,
										 (void**)&entry) == SUCCESS)
	{
		lib->attributes->release(lib->attributes, entry->handler,
								 this->other_id, entry->type, entry->data);
		free(entry->data.ptr);
		free(entry);
	}
	this->attributes->destroy(this->attributes);

	this->child_sas->destroy_offset(this->child_sas, offsetof(child_sa_t, destroy));

	/* unset SA after here to avoid usage by the listeners */
	charon->bus->set_sa(charon->bus, NULL);

	this->task_manager->destroy(this->task_manager);
	this->keymat->destroy(this->keymat);

	if (this->my_virtual_ip)
	{
		charon->kernel_interface->del_ip(charon->kernel_interface,
										 this->my_virtual_ip);
		this->my_virtual_ip->destroy(this->my_virtual_ip);
	}
	if (this->other_virtual_ip)
	{
		if (this->peer_cfg && this->peer_cfg->get_pool(this->peer_cfg))
		{
			lib->attributes->release_address(lib->attributes,
									this->peer_cfg->get_pool(this->peer_cfg),
									this->other_virtual_ip, this->other_id);
		}
		this->other_virtual_ip->destroy(this->other_virtual_ip);
	}
	this->additional_addresses->destroy_offset(this->additional_addresses,
													offsetof(host_t, destroy));
#ifdef ME
	if (this->is_mediation_server)
	{
		charon->mediation_manager->remove(charon->mediation_manager,
										  this->ike_sa_id);
	}
	DESTROY_IF(this->server_reflexive_host);
	chunk_free(&this->connect_id);
#endif /* ME */
	free(this->nat_detection_dest.ptr);

	DESTROY_IF(this->my_host);
	DESTROY_IF(this->other_host);
	DESTROY_IF(this->my_id);
	DESTROY_IF(this->other_id);
	DESTROY_IF(this->local_host);
	DESTROY_IF(this->remote_host);
	DESTROY_IF(this->eap_identity);

	DESTROY_IF(this->ike_cfg);
	DESTROY_IF(this->peer_cfg);
	DESTROY_IF(this->proposal);
	this->my_auth->destroy(this->my_auth);
	this->other_auth->destroy(this->other_auth);

	this->ike_sa_id->destroy(this->ike_sa_id);
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
	this->public.get_name = (char* (*)(ike_sa_t*))get_name;
	this->public.get_statistic = (u_int32_t(*)(ike_sa_t*, statistic_t kind))get_statistic;
	this->public.process_message = (status_t (*)(ike_sa_t*, message_t*)) process_message;
	this->public.initiate = (status_t (*)(ike_sa_t*,child_cfg_t*,u_int32_t,traffic_selector_t*,traffic_selector_t*)) initiate;
	this->public.get_ike_cfg = (ike_cfg_t* (*)(ike_sa_t*))get_ike_cfg;
	this->public.set_ike_cfg = (void (*)(ike_sa_t*,ike_cfg_t*))set_ike_cfg;
	this->public.get_peer_cfg = (peer_cfg_t* (*)(ike_sa_t*))get_peer_cfg;
	this->public.set_peer_cfg = (void (*)(ike_sa_t*,peer_cfg_t*))set_peer_cfg;
	this->public.get_auth_cfg = (auth_cfg_t*(*)(ike_sa_t*, bool local))get_auth_cfg;
	this->public.get_proposal = (proposal_t*(*)(ike_sa_t*))get_proposal;
	this->public.set_proposal = (void(*)(ike_sa_t*, proposal_t *proposal))set_proposal;
	this->public.get_id = (ike_sa_id_t* (*)(ike_sa_t*)) get_id;
	this->public.get_my_host = (host_t* (*)(ike_sa_t*)) get_my_host;
	this->public.set_my_host = (void (*)(ike_sa_t*,host_t*)) set_my_host;
	this->public.get_other_host = (host_t* (*)(ike_sa_t*)) get_other_host;
	this->public.set_other_host = (void (*)(ike_sa_t*,host_t*)) set_other_host;
	this->public.set_message_id = (void(*)(ike_sa_t*, bool inbound, u_int32_t mid))set_message_id;
	this->public.update_hosts = (void(*)(ike_sa_t*, host_t *me, host_t *other))update_hosts;
	this->public.get_my_id = (identification_t* (*)(ike_sa_t*)) get_my_id;
	this->public.set_my_id = (void (*)(ike_sa_t*,identification_t*)) set_my_id;
	this->public.get_other_id = (identification_t* (*)(ike_sa_t*)) get_other_id;
	this->public.set_other_id = (void (*)(ike_sa_t*,identification_t*)) set_other_id;
	this->public.get_eap_identity = (identification_t* (*)(ike_sa_t*)) get_eap_identity;
	this->public.set_eap_identity = (void (*)(ike_sa_t*,identification_t*)) set_eap_identity;
	this->public.enable_extension = (void(*)(ike_sa_t*, ike_extension_t extension))enable_extension;
	this->public.supports_extension = (bool(*)(ike_sa_t*, ike_extension_t extension))supports_extension;
	this->public.set_condition = (void (*)(ike_sa_t*, ike_condition_t,bool)) set_condition;
	this->public.has_condition = (bool (*)(ike_sa_t*,ike_condition_t)) has_condition;
	this->public.set_pending_updates = (void(*)(ike_sa_t*, u_int32_t updates))set_pending_updates;
	this->public.get_pending_updates = (u_int32_t(*)(ike_sa_t*))get_pending_updates;
	this->public.create_additional_address_iterator = (iterator_t*(*)(ike_sa_t*))create_additional_address_iterator;
	this->public.add_additional_address = (void(*)(ike_sa_t*, host_t *host))add_additional_address;
	this->public.has_mapping_changed = (bool(*)(ike_sa_t*, chunk_t hash))has_mapping_changed;
	this->public.retransmit = (status_t (*)(ike_sa_t *, u_int32_t)) retransmit;
	this->public.delete = (status_t (*)(ike_sa_t*))delete_;
	this->public.destroy = (void (*)(ike_sa_t*))destroy;
	this->public.send_dpd = (status_t (*)(ike_sa_t*)) send_dpd;
	this->public.send_keepalive = (void (*)(ike_sa_t*)) send_keepalive;
	this->public.get_keymat = (keymat_t*(*)(ike_sa_t*))get_keymat;
	this->public.add_child_sa = (void (*)(ike_sa_t*,child_sa_t*)) add_child_sa;
	this->public.get_child_sa = (child_sa_t* (*)(ike_sa_t*,protocol_id_t,u_int32_t,bool)) get_child_sa;
	this->public.create_child_sa_iterator = (iterator_t* (*)(ike_sa_t*)) create_child_sa_iterator;
	this->public.rekey_child_sa = (status_t (*)(ike_sa_t*,protocol_id_t,u_int32_t)) rekey_child_sa;
	this->public.delete_child_sa = (status_t (*)(ike_sa_t*,protocol_id_t,u_int32_t)) delete_child_sa;
	this->public.destroy_child_sa = (status_t (*)(ike_sa_t*,protocol_id_t,u_int32_t))destroy_child_sa;
	this->public.rekey = (status_t (*)(ike_sa_t*))rekey;
	this->public.reauth = (status_t (*)(ike_sa_t*))reauth;
	this->public.reestablish = (status_t (*)(ike_sa_t*))reestablish;
	this->public.set_auth_lifetime = (void(*)(ike_sa_t*, u_int32_t lifetime))set_auth_lifetime;
	this->public.roam = (status_t(*)(ike_sa_t*,bool))roam;
	this->public.inherit = (status_t (*)(ike_sa_t*,ike_sa_t*))inherit;
	this->public.generate_message = (status_t (*)(ike_sa_t*,message_t*,packet_t**))generate_message;
	this->public.reset = (void (*)(ike_sa_t*))reset;
	this->public.get_unique_id = (u_int32_t (*)(ike_sa_t*))get_unique_id;
	this->public.set_virtual_ip = (void (*)(ike_sa_t*,bool,host_t*))set_virtual_ip;
	this->public.get_virtual_ip = (host_t* (*)(ike_sa_t*,bool))get_virtual_ip;
	this->public.add_configuration_attribute = (void(*)(ike_sa_t*, configuration_attribute_type_t type, chunk_t data))add_configuration_attribute;
	this->public.set_kmaddress = (void (*)(ike_sa_t*,host_t*,host_t*))set_kmaddress;
#ifdef ME
	this->public.act_as_mediation_server = (void (*)(ike_sa_t*)) act_as_mediation_server;
	this->public.get_server_reflexive_host = (host_t* (*)(ike_sa_t*)) get_server_reflexive_host;
	this->public.set_server_reflexive_host = (void (*)(ike_sa_t*,host_t*)) set_server_reflexive_host;
	this->public.get_connect_id = (chunk_t (*)(ike_sa_t*)) get_connect_id;
	this->public.initiate_mediation = (status_t (*)(ike_sa_t*,peer_cfg_t*)) initiate_mediation;
	this->public.initiate_mediated = (status_t (*)(ike_sa_t*,host_t*,host_t*,chunk_t)) initiate_mediated;
	this->public.relay = (status_t (*)(ike_sa_t*,identification_t*,chunk_t,chunk_t,linked_list_t*,bool)) relay;
	this->public.callback = (status_t (*)(ike_sa_t*,identification_t*)) callback;
	this->public.respond = (status_t (*)(ike_sa_t*,identification_t*,chunk_t)) respond;
#endif /* ME */

	/* initialize private fields */
	this->ike_sa_id = ike_sa_id->clone(ike_sa_id);
	this->child_sas = linked_list_create();
	this->my_host = host_create_any(AF_INET);
	this->my_host->set_port(this->my_host, IKEV2_UDP_PORT);
	this->other_host = host_create_any(AF_INET);
	this->my_id = identification_create_from_encoding(ID_ANY, chunk_empty);
	this->other_id = identification_create_from_encoding(ID_ANY, chunk_empty);
	this->eap_identity = NULL;
	this->extensions = 0;
	this->conditions = 0;
	this->keymat = keymat_create(ike_sa_id->is_initiator(ike_sa_id));
	this->state = IKE_CREATED;
	this->keepalive_interval = lib->settings->get_time(lib->settings,
									"charon.keep_alive", KEEPALIVE_INTERVAL);
	memset(this->stats, 0, sizeof(this->stats));
	this->stats[STAT_INBOUND] = this->stats[STAT_OUTBOUND] = time_monotonic(NULL);
	this->ike_cfg = NULL;
	this->peer_cfg = NULL;
	this->my_auth = auth_cfg_create();
	this->other_auth = auth_cfg_create();
	this->proposal = NULL;
	this->task_manager = task_manager_create(&this->public);
	this->unique_id = ++unique_id;
	this->my_virtual_ip = NULL;
	this->other_virtual_ip = NULL;
	this->additional_addresses = linked_list_create();
	this->attributes = linked_list_create();
	this->nat_detection_dest = chunk_empty;
	this->pending_updates = 0;
	this->keyingtry = 0;
	this->local_host = NULL;
	this->remote_host = NULL;
#ifdef ME
	this->is_mediation_server = FALSE;
	this->server_reflexive_host = NULL;
	this->connect_id = chunk_empty;
#endif /* ME */

	return &this->public;
}
