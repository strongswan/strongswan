/*
 * Copyright (C) 2009-2020 Tobias Brunner
 * Copyright (C) 2005-2007 Martin Willi
 * Copyright (C) 2005 Jan Hutter
 * HSR Hochschule fuer Technik Rapperswil
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

#include "child_rekey.h"

#include <daemon.h>
#include <encoding/payloads/notify_payload.h>
#include <sa/ikev2/tasks/child_create.h>
#include <sa/ikev2/tasks/child_delete.h>
#include <processing/jobs/rekey_child_sa_job.h>
#include <processing/jobs/rekey_ike_sa_job.h>


typedef struct private_child_rekey_t private_child_rekey_t;

/**
 * Private members of a child_rekey_t task.
 */
struct private_child_rekey_t {

	/**
	 * Public methods and task_t interface.
	 */
	child_rekey_t public;

	/**
	 * Assigned IKE_SA.
	 */
	ike_sa_t *ike_sa;

	/**
	 * Are we the initiator?
	 */
	bool initiator;

	/**
	 * Protocol of CHILD_SA to rekey
	 */
	protocol_id_t protocol;

	/**
	 * Inbound SPI of CHILD_SA to rekey
	 */
	uint32_t spi;

	/**
	 * the CHILD_CREATE task which is reused to simplify rekeying
	 */
	child_create_t *child_create;

	/**
	 * the CHILD_DELETE task to delete rekeyed CHILD_SA
	 */
	child_delete_t *child_delete;

	/**
	 * CHILD_SA which gets rekeyed
	 */
	child_sa_t *child_sa;

	/**
	 * colliding task, may be delete or rekey
	 */
	task_t *collision;

	/**
	 * State flags
	 */
	enum {

		/**
		 * Set if we use multiple key exchanges and already processed the
		 * CREATE_CHILD_SA response and started sending IKE_FOLLOWUP_KEs.
		 */
		CHILD_REKEY_FOLLOWUP_KE = (1<<0),

		/**
		 * Set if we adopted a completed passive task, otherwise (i.e. for
		 * multi-KE rekeyings) we just reference it.
		 */
		CHILD_REKEY_ADOPTED_PASSIVE = (1<<1),

		/**
		 * Indicate that the peer destroyed the redundant child from a
		 * collision. This happens if a peer's delete notification for the
		 * redundant child gets processed before the active rekey job is
		 * complete. If so, we must not touch the child created in the collision
		 * since it points to memory already freed.
		 */
		CHILD_REKEY_OTHER_DESTROYED = (1<<2),

	} flags;
};

/**
 * Schedule a retry if rekeying temporary failed
 */
static void schedule_delayed_rekey(private_child_rekey_t *this)
{
	uint32_t retry;
	job_t *job;

	retry = RETRY_INTERVAL - (random() % RETRY_JITTER);
	job = (job_t*)rekey_child_sa_job_create(
						this->child_sa->get_protocol(this->child_sa),
						this->child_sa->get_spi(this->child_sa, TRUE),
						this->ike_sa->get_my_host(this->ike_sa));
	DBG1(DBG_IKE, "CHILD_SA rekeying failed, trying again in %d seconds", retry);
	this->child_sa->set_state(this->child_sa, CHILD_INSTALLED);
	lib->scheduler->schedule_job(lib->scheduler, job, retry);
}

/**
 * Implementation of task_t.build for initiator, after rekeying
 */
static status_t build_i_delete(private_child_rekey_t *this, message_t *message)
{
	/* update exchange type to INFORMATIONAL for the delete */
	message->set_exchange_type(message, INFORMATIONAL);

	return this->child_delete->task.build(&this->child_delete->task, message);
}

/**
 * Implementation of task_t.process for initiator, after rekeying
 */
static status_t process_i_delete(private_child_rekey_t *this, message_t *message)
{
	return this->child_delete->task.process(&this->child_delete->task, message);
}

/**
 * find a child using the REKEY_SA notify
 */
static void find_child(private_child_rekey_t *this, message_t *message)
{
	notify_payload_t *notify;
	protocol_id_t protocol;
	uint32_t spi;
	child_sa_t *child_sa;

	notify = message->get_notify(message, REKEY_SA);
	if (notify)
	{
		protocol = notify->get_protocol_id(notify);
		spi = notify->get_spi(notify);

		if (protocol == PROTO_ESP || protocol == PROTO_AH)
		{
			child_sa = this->ike_sa->get_child_sa(this->ike_sa, protocol,
												  spi, FALSE);
			if (child_sa &&
				child_sa->get_state(child_sa) == CHILD_DELETED)
			{	/* ignore rekeyed CHILD_SAs we keep around */
				return;
			}
			this->child_sa = child_sa;
		}
	}
}

METHOD(task_t, build_i, status_t,
	private_child_rekey_t *this, message_t *message)
{
	notify_payload_t *notify;

	this->child_sa = this->ike_sa->get_child_sa(this->ike_sa, this->protocol,
												this->spi, TRUE);
	if (!this->child_sa)
	{	/* check if it is an outbound CHILD_SA */
		this->child_sa = this->ike_sa->get_child_sa(this->ike_sa, this->protocol,
													this->spi, FALSE);
		if (this->child_sa)
		{
			/* we work only with the inbound SPI */
			this->spi = this->child_sa->get_spi(this->child_sa, TRUE);
		}
	}
	if (!this->child_sa ||
		(!this->child_create &&
		  this->child_sa->get_state(this->child_sa) != CHILD_INSTALLED) ||
		(this->child_create &&
		 this->child_sa->get_state(this->child_sa) != CHILD_REKEYING))
	{
		/* CHILD_SA is gone or in the wrong state, unable to rekey */
		message->set_exchange_type(message, EXCHANGE_TYPE_UNDEFINED);
		return SUCCESS;
	}

	/* our CHILD_CREATE task does the hard work for us */
	if (!this->child_create)
	{
		child_cfg_t *config;
		proposal_t *proposal;
		uint16_t dh_group;
		uint32_t reqid;

		config = this->child_sa->get_config(this->child_sa);
		this->child_create = child_create_create(this->ike_sa,
									config->get_ref(config), TRUE, NULL, NULL);

		proposal = this->child_sa->get_proposal(this->child_sa);
		if (proposal->get_algorithm(proposal, KEY_EXCHANGE_METHOD,
									&dh_group, NULL))
		{	/* reuse the DH group negotiated previously */
			this->child_create->use_dh_group(this->child_create, dh_group);
		}
		reqid = this->child_sa->get_reqid(this->child_sa);
		this->child_create->use_reqid(this->child_create, reqid);
		this->child_create->use_marks(this->child_create,
						this->child_sa->get_mark(this->child_sa, TRUE).value,
						this->child_sa->get_mark(this->child_sa, FALSE).value);
		this->child_create->use_if_ids(this->child_create,
						this->child_sa->get_if_id(this->child_sa, TRUE),
						this->child_sa->get_if_id(this->child_sa, FALSE));
	}

	if (this->child_create->task.build(&this->child_create->task,
									   message) != NEED_MORE)
	{
		schedule_delayed_rekey(this);
		message->set_exchange_type(message, EXCHANGE_TYPE_UNDEFINED);
		return SUCCESS;
	}
	if (message->get_exchange_type(message) == CREATE_CHILD_SA)
	{
		/* don't add the notify if the CHILD_CREATE task changed the exchange */
		notify = notify_payload_create_from_protocol_and_type(PLV2_NOTIFY,
													this->protocol, REKEY_SA);
		notify->set_spi(notify, this->spi);
		message->add_payload(message, (payload_t*)notify);
	}
	this->child_sa->set_state(this->child_sa, CHILD_REKEYING);

	return NEED_MORE;
}

METHOD(task_t, process_r, status_t,
	private_child_rekey_t *this, message_t *message)
{
	/* let the CHILD_CREATE task process the message */
	this->child_create->task.process(&this->child_create->task, message);

	find_child(this, message);

	return NEED_MORE;
}

/**
 * Check if we are actively rekeying and optionally, if we already sent an
 * IKE_FOLLOWUP_KE message.
 */
static bool actively_rekeying(private_child_rekey_t *this, bool *followup_sent)
{
	enumerator_t *enumerator;
	task_t *task;
	bool found = FALSE;

	enumerator = this->ike_sa->create_task_enumerator(this->ike_sa,
													  TASK_QUEUE_ACTIVE);
	while (enumerator->enumerate(enumerator, (void**)&task))
	{
		if (task->get_type(task) == TASK_CHILD_REKEY)
		{
			private_child_rekey_t *rekey = (private_child_rekey_t*)task;

			if (this->child_sa == rekey->child_sa)
			{
				if (followup_sent)
				{
					*followup_sent = rekey->flags & CHILD_REKEY_FOLLOWUP_KE;
				}
				found = TRUE;
			}
			break;
		}
	}
	enumerator->destroy(enumerator);
	return found;
}

METHOD(task_t, build_r, status_t,
	private_child_rekey_t *this, message_t *message)
{
	child_cfg_t *config;
	child_sa_t *child_sa;
	child_sa_state_t state = CHILD_INSTALLED;
	uint32_t reqid;
	bool followup_sent;

	if (!this->child_sa)
	{
		DBG1(DBG_IKE, "unable to rekey, CHILD_SA not found");
		message->add_notify(message, TRUE, CHILD_SA_NOT_FOUND, chunk_empty);
		return SUCCESS;
	}
	if (this->child_sa->get_state(this->child_sa) == CHILD_DELETING)
	{
		DBG1(DBG_IKE, "unable to rekey, we are deleting the CHILD_SA");
		message->add_notify(message, TRUE, TEMPORARY_FAILURE, chunk_empty);
		return SUCCESS;
	}
	if (actively_rekeying(this, &followup_sent) && followup_sent)
	{
		DBG1(DBG_IKE, "peer initiated rekeying, but we did too and already "
			 "sent IKE_FOLLOWUP_KE");
		message->add_notify(message, TRUE, TEMPORARY_FAILURE, chunk_empty);
		return SUCCESS;
	}

	if (message->get_exchange_type(message) == CREATE_CHILD_SA)
	{
		reqid = this->child_sa->get_reqid(this->child_sa);
		this->child_create->use_reqid(this->child_create, reqid);
		this->child_create->use_marks(this->child_create,
						this->child_sa->get_mark(this->child_sa, TRUE).value,
						this->child_sa->get_mark(this->child_sa, FALSE).value);
		this->child_create->use_if_ids(this->child_create,
						this->child_sa->get_if_id(this->child_sa, TRUE),
						this->child_sa->get_if_id(this->child_sa, FALSE));
		config = this->child_sa->get_config(this->child_sa);
		this->child_create->set_config(this->child_create,
									   config->get_ref(config));
		state = this->child_sa->get_state(this->child_sa);
		this->child_sa->set_state(this->child_sa, CHILD_REKEYING);
	}

	if (this->child_create->task.build(&this->child_create->task,
									   message) == NEED_MORE)
	{
		/* additional key exchanges */
		this->flags |= CHILD_REKEY_FOLLOWUP_KE;
		return NEED_MORE;
	}

	child_sa = this->child_create->get_child(this->child_create);
	if (child_sa && child_sa->get_state(child_sa) == CHILD_INSTALLED)
	{
		this->child_sa->set_state(this->child_sa, CHILD_REKEYED);
		this->child_sa->set_rekey_spi(this->child_sa,
									  child_sa->get_spi(child_sa, FALSE));

		/* FIXME: this might trigger twice if there was a collision */
		charon->bus->child_rekey(charon->bus, this->child_sa, child_sa);
	}
	else if (this->child_sa->get_state(this->child_sa) == CHILD_REKEYING)
	{	/* rekeying failed, reuse old child */
		this->child_sa->set_state(this->child_sa, state);
	}
	return SUCCESS;
}

/**
 * Remove the passive rekey task that's waiting for IKE_FOLLOWUP_KE requests
 * that will never come.
 */
static void remove_passive_rekey_task(private_child_rekey_t *this)
{
	enumerator_t *enumerator;
	task_t *task;

	enumerator = this->ike_sa->create_task_enumerator(this->ike_sa,
													  TASK_QUEUE_PASSIVE);
	while (enumerator->enumerate(enumerator, &task))
	{
		if (task->get_type(task) == TASK_CHILD_REKEY)
		{
			this->ike_sa->remove_task(this->ike_sa, enumerator);
			task->destroy(task);
			break;
		}
	}
	enumerator->destroy(enumerator);
}

/**
 * Handle a rekey collision
 */
static child_sa_t *handle_collision(private_child_rekey_t *this,
									child_sa_t **to_install, bool multi_ke)
{
	private_child_rekey_t *other = (private_child_rekey_t*)this->collision;
	chunk_t this_nonce, other_nonce;
	child_sa_t *to_delete, *child_sa;

	if (this->collision->get_type(this->collision) == TASK_CHILD_DELETE)
	{	/* CHILD_DELETE, which we only adopt if it is for the CHILD_SA we are
		 * ourselves rekeying */
		to_delete = this->child_create->get_child(this->child_create);
		if (multi_ke)
		{
			DBG1(DBG_IKE, "CHILD_SA rekey/delete collision, abort incomplete "
				 "multi-KE rekeying");
		}
		else
		{
			DBG1(DBG_IKE, "CHILD_SA rekey/delete collision, deleting redundant "
				 "child %s{%d}", to_delete->get_name(to_delete),
				 to_delete->get_unique_id(to_delete));
		}
		return to_delete;
	}

	this_nonce = this->child_create->get_lower_nonce(this->child_create);
	other_nonce = other->child_create->get_lower_nonce(other->child_create);

	/* the SA with the lowest nonce should be deleted (if already complete),
	 * check if we or the peer created it */
	if (memcmp(this_nonce.ptr, other_nonce.ptr,
			   min(this_nonce.len, other_nonce.len)) < 0)
	{
		to_delete = this->child_create->get_child(this->child_create);
		if (multi_ke)
		{
			DBG1(DBG_IKE, "CHILD_SA rekey collision lost, abort incomplete "
				 "multi-KE rekeying");
		}
		else
		{
			DBG1(DBG_IKE, "CHILD_SA rekey collision lost, deleting "
				 "redundant child %s{%d}", to_delete->get_name(to_delete),
				 to_delete->get_unique_id(to_delete));
		}
		return to_delete;
	}

	*to_install = this->child_create->get_child(this->child_create);
	to_delete = this->child_sa;

	/* the passive rekeying is complete only if it was single-KE.  otherwise,
	 * the peer would either have stopped before sending IKE_FOLLOWUP_KE when
	 * it noticed it lost, or it responded with TEMPORARY_FAILURE to our
	 * CREATE_CHILD_SA request if it already started sending them. */
	if (this->flags & CHILD_REKEY_ADOPTED_PASSIVE)
	{
		/* we don't want to install the peer's redundant outbound SA */
		this->child_sa->set_rekey_spi(this->child_sa, 0);
		/* don't touch child other created if it has already been deleted */
		if (!(this->flags & CHILD_REKEY_OTHER_DESTROYED))
		{
			/* disable close action and updown event for redundant child the
			 * other is expected to delete */
			child_sa = other->child_create->get_child(other->child_create);
			if (child_sa)
			{
				child_sa->set_close_action(child_sa, ACTION_NONE);
				if (child_sa->get_state(child_sa) != CHILD_REKEYED)
				{
					child_sa->set_state(child_sa, CHILD_REKEYED);
				}
			}
		}
		if (multi_ke)
		{
			DBG1(DBG_IKE, "CHILD_SA rekey collision won, continue with "
				 "multi-KE rekeying");
			/* change the state back, we are not done rekeying yet */
			this->child_sa->set_state(this->child_sa, CHILD_REKEYING);
		}
		else
		{
			DBG1(DBG_IKE, "CHILD_SA rekey collision won, deleting old child "
				 "%s{%d}", to_delete->get_name(to_delete),
				 to_delete->get_unique_id(to_delete));
		}
		this->collision->destroy(this->collision);
	}
	else
	{
		/* the peer will not continue with its multi-KE rekeying, so we must
		 * remove the passive task that's waiting for IKE_FOLLOWUP_KEs */
		if (multi_ke)
		{
			DBG1(DBG_IKE, "CHILD_SA rekey collision won, continue with "
				 "multi-KE rekeying and remove passive %N task",
				 task_type_names, TASK_CHILD_REKEY);
		}
		else
		{
			DBG1(DBG_IKE, "CHILD_SA rekey collision won, remove passive %N "
				 "task", task_type_names, TASK_CHILD_REKEY);
		}
		remove_passive_rekey_task(this);
	}
	this->collision = NULL;
	return to_delete;
}

METHOD(task_t, process_i, status_t,
	private_child_rekey_t *this, message_t *message)
{
	protocol_id_t protocol;
	uint32_t spi;
	child_sa_t *child_sa, *to_delete = NULL, *to_install = NULL;

	if (message->get_notify(message, NO_ADDITIONAL_SAS))
	{
		DBG1(DBG_IKE, "peer seems to not support CHILD_SA rekeying, "
			 "starting reauthentication");
		this->child_sa->set_state(this->child_sa, CHILD_INSTALLED);
		lib->processor->queue_job(lib->processor,
				(job_t*)rekey_ike_sa_job_create(
							this->ike_sa->get_id(this->ike_sa), TRUE));
		return SUCCESS;
	}
	if (message->get_notify(message, CHILD_SA_NOT_FOUND))
	{
		child_cfg_t *child_cfg;
		uint32_t reqid;

		if (this->collision &&
			this->collision->get_type(this->collision) == TASK_CHILD_DELETE)
		{	/* ignore this error if we already deleted the CHILD_SA on the
			 * peer's behalf (could happen if the other peer does not detect
			 * the collision and did not respond with TEMPORARY_FAILURE) */
			return SUCCESS;
		}
		DBG1(DBG_IKE, "peer didn't find the CHILD_SA we tried to rekey");
		/* FIXME: according to RFC 7296 we should only create a new CHILD_SA if
		 * it does not exist yet, we currently have no good way of checking for
		 * that (we could go by name, but that might be tricky e.g. due to
		 * narrowing) */
		spi = this->child_sa->get_spi(this->child_sa, TRUE);
		reqid = this->child_sa->get_reqid(this->child_sa);
		protocol = this->child_sa->get_protocol(this->child_sa);
		child_cfg = this->child_sa->get_config(this->child_sa);
		child_cfg->get_ref(child_cfg);
		charon->bus->child_updown(charon->bus, this->child_sa, FALSE);
		this->ike_sa->destroy_child_sa(this->ike_sa, protocol, spi);
		return this->ike_sa->initiate(this->ike_sa,
									  child_cfg->get_ref(child_cfg), reqid,
									  NULL, NULL);
	}

	if (this->child_create->task.process(&this->child_create->task,
										 message) == NEED_MORE)
	{
		if (message->get_notify(message, INVALID_KE_PAYLOAD) ||
			!this->child_create->get_child(this->child_create))
		{	/* bad key exchange mechanism, retry, or failure requiring delete */
			return NEED_MORE;
		}
		/* multiple key exchanges */
		this->flags |= CHILD_REKEY_FOLLOWUP_KE;
		/* there will only be a collision while we process a CREATE_CHILD_SA
		 * response, later we just respond with TEMPORARY_FAILURE and ignore
		 * the passive task - if we lost, the returned SA is the one we created
		 * in this task, since it's not complete yet, we abort the task */
		if (this->collision)
		{
			to_delete = handle_collision(this, &to_install, TRUE);
		}
		return (to_delete && to_delete != this->child_sa) ? SUCCESS : NEED_MORE;
	}

	child_sa = this->child_create->get_child(this->child_create);
	if (!child_sa || child_sa->get_state(child_sa) != CHILD_INSTALLED)
	{
		/* establishing new child failed, reuse old and try again. but not when
		 * we received a delete in the meantime or passively rekeyed the SA */
		if (!this->collision ||
			(this->collision->get_type(this->collision) != TASK_CHILD_DELETE &&
			 !(this->flags & CHILD_REKEY_ADOPTED_PASSIVE)))
		{
			schedule_delayed_rekey(this);
		}
		return SUCCESS;
	}

	/* there won't be a collision if this task is for a multi-KE rekeying, as a
	 * collision during CREATE_CHILD_SA was cleaned up above */
	if (this->collision)
	{
		to_delete = handle_collision(this, &to_install, FALSE);
	}
	else
	{
		to_install = this->child_create->get_child(this->child_create);
		to_delete = this->child_sa;
	}
	if (to_install)
	{
		if (to_install->install_outbound(to_install) != SUCCESS)
		{
			DBG1(DBG_IKE, "unable to install outbound IPsec SA (SAD) in kernel");
			charon->bus->alert(charon->bus, ALERT_INSTALL_CHILD_SA_FAILED,
							   to_install);
			/* FIXME: delete the child_sa? fail the task? */
		}
		else
		{
			linked_list_t *my_ts, *other_ts;

			my_ts = linked_list_create_from_enumerator(
						to_install->create_ts_enumerator(to_install, TRUE));
			other_ts = linked_list_create_from_enumerator(
						to_install->create_ts_enumerator(to_install, FALSE));

			DBG0(DBG_IKE, "outbound CHILD_SA %s{%d} established "
				 "with SPIs %.8x_i %.8x_o and TS %#R === %#R",
				 to_install->get_name(to_install),
				 to_install->get_unique_id(to_install),
				 ntohl(to_install->get_spi(to_install, TRUE)),
				 ntohl(to_install->get_spi(to_install, FALSE)),
				 my_ts, other_ts);

			my_ts->destroy(my_ts);
			other_ts->destroy(other_ts);
		}
	}
	if (to_delete != this->child_create->get_child(this->child_create))
	{	/* invoke rekey hook if rekeying successful */
		charon->bus->child_rekey(charon->bus, this->child_sa,
							this->child_create->get_child(this->child_create));
	}
	if (!to_delete)
	{
		return SUCCESS;
	}
	/* disable updown event for redundant CHILD_SA */
	if (to_delete->get_state(to_delete) != CHILD_REKEYED)
	{
		to_delete->set_state(to_delete, CHILD_REKEYED);
	}
	spi = to_delete->get_spi(to_delete, TRUE);
	protocol = to_delete->get_protocol(to_delete);

	/* rekeying done, delete the obsolete CHILD_SA using a subtask */
	this->child_delete = child_delete_create(this->ike_sa, protocol, spi, FALSE);
	this->public.task.build = (status_t(*)(task_t*,message_t*))build_i_delete;
	this->public.task.process = (status_t(*)(task_t*,message_t*))process_i_delete;

	return NEED_MORE;
}

METHOD(task_t, get_type, task_type_t,
	private_child_rekey_t *this)
{
	return TASK_CHILD_REKEY;
}

METHOD(child_rekey_t, is_redundant, bool,
	private_child_rekey_t *this, child_sa_t *child)
{
	if (this->collision &&
		this->collision->get_type(this->collision) == TASK_CHILD_REKEY)
	{
		private_child_rekey_t *rekey = (private_child_rekey_t*)this->collision;
		return child == rekey->child_create->get_child(rekey->child_create);
	}
	return FALSE;
}

METHOD(child_rekey_t, collide, bool,
	private_child_rekey_t *this, task_t *other)
{
	/* the task manager only detects exchange collision, but not if
	 * the collision is for the same child. we check it here. */
	if (other->get_type(other) == TASK_CHILD_REKEY)
	{
		private_child_rekey_t *rekey = (private_child_rekey_t*)other;
		child_sa_t *other_child;

		if (rekey->child_sa != this->child_sa)
		{	/* not the same child => no collision */
			return FALSE;
		}
		/* ignore passive tasks that did not successfully create a CHILD_SA */
		other_child = rekey->child_create->get_child(rekey->child_create);
		if (!other_child)
		{
			return FALSE;
		}
		if (other_child->get_state(other_child) != CHILD_INSTALLED)
		{
			DBG1(DBG_IKE, "colliding passive rekeying is not yet complete",
				 task_type_names, TASK_CHILD_REKEY);
			/* we do reference the task to check its state later */
			this->collision = other;
			return FALSE;
		}
	}
	else if (other->get_type(other) == TASK_CHILD_DELETE)
	{
		child_delete_t *del = (child_delete_t*)other;
		if (is_redundant(this, del->get_child(del)))
		{
			this->flags |= CHILD_REKEY_OTHER_DESTROYED;
			return FALSE;
		}
		if (del->get_child(del) != this->child_sa)
		{
			/* not the same child => no collision */
			return FALSE;
		}
	}
	else
	{
		/* shouldn't happen */
		return FALSE;
	}

	DBG1(DBG_IKE, "detected %N collision with %N", task_type_names,
		 TASK_CHILD_REKEY, task_type_names, other->get_type(other));

	if (this->flags & CHILD_REKEY_ADOPTED_PASSIVE)
	{
		DESTROY_IF(this->collision);
	}
	this->flags |= CHILD_REKEY_ADOPTED_PASSIVE;
	this->collision = other;
	return TRUE;
}

METHOD(task_t, migrate, void,
	private_child_rekey_t *this, ike_sa_t *ike_sa)
{
	/* only migrate the currently active task */
	if (this->child_delete)
	{
		this->child_delete->task.migrate(&this->child_delete->task, ike_sa);
	}
	else if (this->child_create)
	{
		this->child_create->task.migrate(&this->child_create->task, ike_sa);
	}
	if (this->flags & CHILD_REKEY_ADOPTED_PASSIVE)
	{
		DESTROY_IF(this->collision);
	}

	this->ike_sa = ike_sa;
	this->collision = NULL;
}

METHOD(task_t, destroy, void,
	private_child_rekey_t *this)
{
	if (this->child_create)
	{
		this->child_create->task.destroy(&this->child_create->task);
	}
	if (this->child_delete)
	{
		this->child_delete->task.destroy(&this->child_delete->task);
	}
	if (this->flags & CHILD_REKEY_ADOPTED_PASSIVE)
	{
		DESTROY_IF(this->collision);
	}
	free(this);
}

/*
 * Described in header.
 */
child_rekey_t *child_rekey_create(ike_sa_t *ike_sa, protocol_id_t protocol,
								  uint32_t spi)
{
	private_child_rekey_t *this;

	INIT(this,
		.public = {
			.task = {
				.get_type = _get_type,
				.migrate = _migrate,
				.destroy = _destroy,
			},
			.is_redundant = _is_redundant,
			.collide = _collide,
		},
		.ike_sa = ike_sa,
		.protocol = protocol,
		.spi = spi,
	);

	if (protocol != PROTO_NONE)
	{
		this->public.task.build = _build_i;
		this->public.task.process = _process_i;
		this->initiator = TRUE;
		this->child_create = NULL;
	}
	else
	{
		this->public.task.build = _build_r;
		this->public.task.process = _process_r;
		this->initiator = FALSE;
		this->child_create = child_create_create(ike_sa, NULL, TRUE, NULL, NULL);
	}

	return &this->public;
}
