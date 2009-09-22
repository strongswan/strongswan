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
 */

#include "ha_sync_segments.h"

#include <utils/mutex.h>
#include <utils/linked_list.h>

typedef struct private_ha_sync_segments_t private_ha_sync_segments_t;

/**
 * Private data of an ha_sync_segments_t object.
 */
struct private_ha_sync_segments_t {

	/**
	 * Public ha_sync_segments_t interface.
	 */
	ha_sync_segments_t public;

	/**
	 * communication socket
	 */
	ha_sync_socket_t *socket;

	/**
	 * Interface to control segments at kernel level
	 */
	ha_sync_kernel_t *kernel;

	/**
	 * read/write lock for segment manipulation
	 */
	rwlock_t *lock;

	/**
	 * Total number of ClusterIP segments
	 */
	u_int segment_count;

	/**
	 * mask of active segments
	 */
	segment_mask_t active;
};

/**
 * Log currently active segments
 */
static void log_segments(private_ha_sync_segments_t *this, bool activated,
						 u_int segment)
{
	char buf[64] = "none", *pos = buf;
	int i;
	bool first = TRUE;

	for (i = 0; i < this->segment_count; i++)
	{
		if (this->active & 0x01 << i)
		{
			if (first)
			{
				first = FALSE;
			}
			else
			{
				pos += snprintf(pos, buf + sizeof(buf) - pos, ",");
			}
			pos += snprintf(pos, buf + sizeof(buf) - pos, "%d", i+1);
		}
	}
	DBG1(DBG_CFG, "HA sync segment %d %sactivated, now active: %s",
		 segment, activated ? "" : "de", buf);
}

/**
 * Enable/Disable an an IKE_SA.
 */
static void enable_disable(private_ha_sync_segments_t *this, u_int segment,
						   ike_sa_state_t old, ike_sa_state_t new, bool enable)
{
	ike_sa_t *ike_sa;
	enumerator_t *enumerator;
	u_int i, limit;

	this->lock->write_lock(this->lock);

	if (segment == 0 || segment <= this->segment_count)
	{
		if (segment)
		{	/* loop once for single segment ... */
			limit = segment + 1;
		}
		else
		{	/* or segment_count times for all segments */
			limit = this->segment_count;
		}
		enumerator = charon->ike_sa_manager->create_enumerator(charon->ike_sa_manager);
		while (enumerator->enumerate(enumerator, &ike_sa))
		{
			if (ike_sa->get_state(ike_sa) == old)
			{
				for (i = segment; i < limit; i++)
				{
					if (this->kernel->in_segment(this->kernel,
											ike_sa->get_other_host(ike_sa), i))
					{
						ike_sa->set_state(ike_sa, new);
					}
				}
			}
		}
		enumerator->destroy(enumerator);
		for (i = segment; i < limit; i++)
		{
			if (enable)
			{
				this->active |= SEGMENTS_BIT(i);
				this->kernel->activate(this->kernel, i);
			}
			else
			{
				this->active &= ~SEGMENTS_BIT(i);
				this->kernel->deactivate(this->kernel, i);
			}
		}

		log_segments(this, enable, segment);
	}

	this->lock->unlock(this->lock);
}

/**
 * Implementation of ha_sync_segments_t.activate
 */
static void activate(private_ha_sync_segments_t *this, u_int segment,
					 bool notify)
{
	ha_sync_message_t *message;

	enable_disable(this, segment, IKE_PASSIVE, IKE_ESTABLISHED, TRUE);

	if (notify)
	{
		message = ha_sync_message_create(HA_SYNC_SEGMENT_TAKE);
		message->add_attribute(message, HA_SYNC_SEGMENT, segment);
		this->socket->push(this->socket, message);
	}
}

/**
 * Implementation of ha_sync_segments_t.deactivate
 */
static void deactivate(private_ha_sync_segments_t *this, u_int segment,
					   bool notify)
{
	ha_sync_message_t *message;

	enable_disable(this, segment, IKE_ESTABLISHED, IKE_PASSIVE, FALSE);

	if (notify)
	{
		message = ha_sync_message_create(HA_SYNC_SEGMENT_DROP);
		message->add_attribute(message, HA_SYNC_SEGMENT, segment);
		this->socket->push(this->socket, message);
	}
}

/**
 * Rekey all children of an IKE_SA
 */
static status_t rekey_children(ike_sa_t *ike_sa)
{
	iterator_t *iterator;
	child_sa_t *child_sa;
	status_t status = SUCCESS;

	iterator = ike_sa->create_child_sa_iterator(ike_sa);
	while (iterator->iterate(iterator, (void**)&child_sa))
	{
		DBG1(DBG_CFG, "resyncing CHILD_SA");
		status = ike_sa->rekey_child_sa(ike_sa, child_sa->get_protocol(child_sa),
										child_sa->get_spi(child_sa, TRUE));
		if (status == DESTROY_ME)
		{
			break;
		}
	}
	iterator->destroy(iterator);
	return status;
}

/**
 * Implementation of ha_sync_segments_t.resync
 */
static void resync(private_ha_sync_segments_t *this, u_int segment)
{
	ike_sa_t *ike_sa;
	enumerator_t *enumerator;
	linked_list_t *list;
	ike_sa_id_t *id;
	u_int16_t mask = SEGMENTS_BIT(segment);

	list = linked_list_create();
	this->lock->read_lock(this->lock);

	if (segment > 0 && segment <= this->segment_count && (this->active & mask))
	{
		this->active &= ~mask;

		DBG1(DBG_CFG, "resyncing HA sync segment %d", segment);

		/* we do the actual rekeying in a seperate loop to avoid rekeying
		 * an SA twice. */
		enumerator = charon->ike_sa_manager->create_enumerator(
													charon->ike_sa_manager);
		while (enumerator->enumerate(enumerator, &ike_sa))
		{
			if (ike_sa->get_state(ike_sa) == IKE_ESTABLISHED &&
				this->kernel->in_segment(this->kernel,
									ike_sa->get_other_host(ike_sa), segment))
			{
				id = ike_sa->get_id(ike_sa);
				list->insert_last(list, id->clone(id));
			}
		}
		enumerator->destroy(enumerator);
	}
	this->lock->unlock(this->lock);

	while (list->remove_last(list, (void**)&id) == SUCCESS)
	{
		ike_sa = charon->ike_sa_manager->checkout(charon->ike_sa_manager, id);
		id->destroy(id);
		if (ike_sa)
		{
			DBG1(DBG_CFG, "resyncing IKE_SA");
			if (ike_sa->rekey(ike_sa) != DESTROY_ME)
			{
				if (rekey_children(ike_sa) != DESTROY_ME)
				{
					charon->ike_sa_manager->checkin(
										charon->ike_sa_manager, ike_sa);
					continue;
				}
			}
			charon->ike_sa_manager->checkin_and_destroy(
										charon->ike_sa_manager, ike_sa);
		}
	}
	list->destroy(list);
}

/**
 * Implementation of listener_t.alert
 */
static bool alert_hook(private_ha_sync_segments_t *this, ike_sa_t *ike_sa,
					   alert_t alert, va_list args)
{
	if (alert == ALERT_SHUTDOWN_SIGNAL)
	{
		int i;

		for (i = 0; i < SEGMENTS_MAX; i++)
		{
			if (this->active & SEGMENTS_BIT(i))
			{
				deactivate(this, i, TRUE);
			}
		}
	}
	return TRUE;
}

/**
 * Implementation of ha_sync_segments_t.destroy.
 */
static void destroy(private_ha_sync_segments_t *this)
{
	this->lock->destroy(this->lock);
	free(this);
}

/**
 * See header
 */
ha_sync_segments_t *ha_sync_segments_create(ha_sync_socket_t *socket,
											ha_sync_kernel_t *kernel,
											u_int count, segment_mask_t active)
{
	private_ha_sync_segments_t *this = malloc_thing(private_ha_sync_segments_t);

	memset(&this->public.listener, 0, sizeof(listener_t));
	this->public.listener.alert = (bool(*)(listener_t*, ike_sa_t *, alert_t, va_list))alert_hook;
	this->public.activate = (void(*)(ha_sync_segments_t*, u_int segment,bool))activate;
	this->public.deactivate = (void(*)(ha_sync_segments_t*, u_int segment,bool))deactivate;
	this->public.resync = (void(*)(ha_sync_segments_t*, u_int segment))resync;
	this->public.destroy = (void(*)(ha_sync_segments_t*))destroy;

	this->socket = socket;
	this->kernel = kernel;
	this->lock = rwlock_create(RWLOCK_TYPE_DEFAULT);
	this->active = active;
	this->segment_count = count;

	return &this->public;
}

