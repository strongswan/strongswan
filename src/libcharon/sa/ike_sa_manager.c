/*
 * Copyright (C) 2005-2011 Martin Willi
 * Copyright (C) 2011 revosec AG
 * Copyright (C) 2008 Tobias Brunner
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

#include "ike_sa_manager.h"

#include <daemon.h>
#include <sa/ike_sa_id.h>
#include <bus/bus.h>
#include <threading/condvar.h>
#include <threading/mutex.h>
#include <threading/rwlock.h>
#include <utils/linked_list.h>
#include <crypto/hashers/hasher.h>

/* the default size of the hash table (MUST be a power of 2) */
#define DEFAULT_HASHTABLE_SIZE 1

/* the maximum size of the hash table (MUST be a power of 2) */
#define MAX_HASHTABLE_SIZE (1 << 30)

/* the default number of segments (MUST be a power of 2) */
#define DEFAULT_SEGMENT_COUNT 1

typedef struct entry_t entry_t;

/**
 * An entry in the linked list, contains IKE_SA, locking and lookup data.
 */
struct entry_t {

	/**
	 * Number of threads waiting for this ike_sa_t object.
	 */
	int waiting_threads;

	/**
	 * Condvar where threads can wait until ike_sa_t object is free for use again.
	 */
	condvar_t *condvar;

	/**
	 * Is this ike_sa currently checked out?
	 */
	bool checked_out;

	/**
	 * Does this SA drives out new threads?
	 */
	bool driveout_new_threads;

	/**
	 * Does this SA drives out waiting threads?
	 */
	bool driveout_waiting_threads;

	/**
	 * Identification of an IKE_SA (SPIs).
	 */
	ike_sa_id_t *ike_sa_id;

	/**
	 * The contained ike_sa_t object.
	 */
	ike_sa_t *ike_sa;

	/**
	 * hash of the IKE_SA_INIT message, used to detect retransmissions
	 */
	chunk_t init_hash;

	/**
	 * remote host address, required for DoS detection and duplicate
	 * checking (host with same my_id and other_id is *not* considered
	 * a duplicate if the address family differs)
	 */
	host_t *other;

	/**
	 * As responder: Is this SA half-open?
	 */
	bool half_open;

	/**
	 * own identity, required for duplicate checking
	 */
	identification_t *my_id;

	/**
	 * remote identity, required for duplicate checking
	 */
	identification_t *other_id;

	/**
	 * message ID currently processing, if any
	 */
	u_int32_t message_id;
};

/**
 * Implementation of entry_t.destroy.
 */
static status_t entry_destroy(entry_t *this)
{
	/* also destroy IKE SA */
	this->ike_sa->destroy(this->ike_sa);
	this->ike_sa_id->destroy(this->ike_sa_id);
	chunk_free(&this->init_hash);
	DESTROY_IF(this->other);
	DESTROY_IF(this->my_id);
	DESTROY_IF(this->other_id);
	this->condvar->destroy(this->condvar);
	free(this);
	return SUCCESS;
}

/**
 * Creates a new entry for the ike_sa_t list.
 */
static entry_t *entry_create()
{
	entry_t *this = malloc_thing(entry_t);

	this->waiting_threads = 0;
	this->condvar = condvar_create(CONDVAR_TYPE_DEFAULT);

	/* we set checkout flag when we really give it out */
	this->checked_out = FALSE;
	this->driveout_new_threads = FALSE;
	this->driveout_waiting_threads = FALSE;
	this->message_id = -1;
	this->init_hash = chunk_empty;
	this->other = NULL;
	this->half_open = FALSE;
	this->my_id = NULL;
	this->other_id = NULL;
	this->ike_sa_id = NULL;
	this->ike_sa = NULL;

	return this;
}

/**
 * Function that matches entry_t objects by initiator SPI and the hash of the
 * IKE_SA_INIT message.
 */
static bool entry_match_by_hash(entry_t *entry, ike_sa_id_t *id, chunk_t *hash)
{
	return id->get_responder_spi(id) == 0 &&
		id->is_initiator(id) == entry->ike_sa_id->is_initiator(entry->ike_sa_id) &&
		id->get_initiator_spi(id) == entry->ike_sa_id->get_initiator_spi(entry->ike_sa_id) &&
		chunk_equals(*hash, entry->init_hash);
}

/**
 * Function that matches entry_t objects by ike_sa_id_t.
 */
static bool entry_match_by_id(entry_t *entry, ike_sa_id_t *id)
{
	if (id->equals(id, entry->ike_sa_id))
	{
		return TRUE;
	}
	if ((id->get_responder_spi(id) == 0 ||
		 entry->ike_sa_id->get_responder_spi(entry->ike_sa_id) == 0) &&
		id->is_initiator(id) == entry->ike_sa_id->is_initiator(entry->ike_sa_id) &&
		id->get_initiator_spi(id) == entry->ike_sa_id->get_initiator_spi(entry->ike_sa_id))
	{
		/* this is TRUE for IKE_SAs that we initiated but have not yet received a response */
		return TRUE;
	}
	return FALSE;
}

/**
 * Function that matches entry_t objects by ike_sa_t pointers.
 */
static bool entry_match_by_sa(entry_t *entry, ike_sa_t *ike_sa)
{
	return entry->ike_sa == ike_sa;
}

/**
 * Hash function for ike_sa_id_t objects.
 */
static u_int ike_sa_id_hash(ike_sa_id_t *ike_sa_id)
{
	/* we always use initiator spi as key */
	return ike_sa_id->get_initiator_spi(ike_sa_id);
}

typedef struct half_open_t half_open_t;

/**
 * Struct to manage half-open IKE_SAs per peer.
 */
struct half_open_t {
	/** chunk of remote host address */
	chunk_t other;

	/** the number of half-open IKE_SAs with that host */
	u_int count;
};

/**
 * Destroys a half_open_t object.
 */
static void half_open_destroy(half_open_t *this)
{
	chunk_free(&this->other);
	free(this);
}

/**
 * Function that matches half_open_t objects by the given IP address chunk.
 */
static bool half_open_match(half_open_t *half_open, chunk_t *addr)
{
	return chunk_equals(*addr, half_open->other);
}

typedef struct connected_peers_t connected_peers_t;

struct connected_peers_t {
	/** own identity */
	identification_t *my_id;

	/** remote identity */
	identification_t *other_id;

	/** ip address family of peer */
	int family;

	/** list of ike_sa_id_t objects of IKE_SAs between the two identities */
	linked_list_t *sas;
};

static void connected_peers_destroy(connected_peers_t *this)
{
	this->my_id->destroy(this->my_id);
	this->other_id->destroy(this->other_id);
	this->sas->destroy(this->sas);
	free(this);
}

/**
 * Function that matches connected_peers_t objects by the given ids.
 */
static bool connected_peers_match(connected_peers_t *connected_peers,
							identification_t *my_id, identification_t *other_id,
							uintptr_t family)
{
	return my_id->equals(my_id, connected_peers->my_id) &&
		   other_id->equals(other_id, connected_peers->other_id) &&
		   family == connected_peers->family;
}

typedef struct segment_t segment_t;

/**
 * Struct to manage segments of the hash table.
 */
struct segment_t {
	/** mutex to access a segment exclusively */
	mutex_t *mutex;

	/** the number of entries in this segment */
	u_int count;
};

typedef struct shareable_segment_t shareable_segment_t;

/**
 * Struct to manage segments of the "half-open" and "connected peers" hash tables.
 */
struct shareable_segment_t {
	/** rwlock to access a segment non-/exclusively */
	rwlock_t *lock;

	/** the number of entries in this segment - in case of the "half-open table"
	 * it's the sum of all half_open_t.count in a segment. */
	u_int count;
};

typedef struct private_ike_sa_manager_t private_ike_sa_manager_t;

/**
 * Additional private members of ike_sa_manager_t.
 */
struct private_ike_sa_manager_t {
	/**
	 * Public interface of ike_sa_manager_t.
	 */
	ike_sa_manager_t public;

	/**
	 * Hash table with entries for the ike_sa_t objects.
	 */
	linked_list_t **ike_sa_table;

	/**
	 * The size of the hash table.
	 */
	u_int table_size;

	/**
	 * Mask to map the hashes to table rows.
	 */
	u_int table_mask;

	/**
	 * Segments of the hash table.
	 */
	segment_t *segments;

	/**
	 * The number of segments.
	 */
	u_int segment_count;

	/**
	 * Mask to map a table row to a segment.
	 */
	u_int segment_mask;

	/**
	 * Hash table with half_open_t objects.
	 */
	linked_list_t **half_open_table;

	/**
	  * Segments of the "half-open" hash table.
	 */
	shareable_segment_t *half_open_segments;

	/**
	 * Hash table with connected_peers_t objects.
	 */
	linked_list_t **connected_peers_table;

	/**
	 * Segments of the "connected peers" hash table.
	 */
	shareable_segment_t *connected_peers_segments;

	/**
	 * RNG to get random SPIs for our side
	 */
	rng_t *rng;

	/**
	 * SHA1 hasher for IKE_SA_INIT retransmit detection
	 */
	hasher_t *hasher;

	/**
	 * reuse existing IKE_SAs in checkout_by_config
	 */
	bool reuse_ikesa;
};

/**
 * Acquire a lock to access the segment of the table row with the given index.
 * It also works with the segment index directly.
 */
static void lock_single_segment(private_ike_sa_manager_t *this, u_int index)
{
	mutex_t *lock = this->segments[index & this->segment_mask].mutex;

	lock->lock(lock);
}

/**
 * Release the lock required to access the segment of the table row with the given index.
 * It also works with the segment index directly.
 */
static void unlock_single_segment(private_ike_sa_manager_t *this, u_int index)
{
	mutex_t *lock = this->segments[index & this->segment_mask].mutex;

	lock->unlock(lock);
}

/**
 * Lock all segments
 */
static void lock_all_segments(private_ike_sa_manager_t *this)
{
	u_int i;

	for (i = 0; i < this->segment_count; i++)
	{
		this->segments[i].mutex->lock(this->segments[i].mutex);
	}
}

/**
 * Unlock all segments
 */
static void unlock_all_segments(private_ike_sa_manager_t *this)
{
	u_int i;

	for (i = 0; i < this->segment_count; i++)
	{
		this->segments[i].mutex->unlock(this->segments[i].mutex);
	}
}

typedef struct private_enumerator_t private_enumerator_t;

/**
 * hash table enumerator implementation
 */
struct private_enumerator_t {

	/**
	 * implements enumerator interface
	 */
	enumerator_t enumerator;

	/**
	 * associated ike_sa_manager_t
	 */
	private_ike_sa_manager_t *manager;

	/**
	 * current segment index
	 */
	u_int segment;

	/**
	 * currently enumerating entry
	 */
	entry_t *entry;

	/**
	 * current table row index
	 */
	u_int row;

	/**
	 * enumerator for the current table row
	 */
	enumerator_t *current;
};

METHOD(enumerator_t, enumerate, bool,
	private_enumerator_t *this, entry_t **entry, u_int *segment)
{
	if (this->entry)
	{
		this->entry->condvar->signal(this->entry->condvar);
		this->entry = NULL;
	}
	while (this->segment < this->manager->segment_count)
	{
		while (this->row < this->manager->table_size)
		{
			if (this->current)
			{
				entry_t *item;

				if (this->current->enumerate(this->current, &item))
				{
					*entry = this->entry = item;
					*segment = this->segment;
					return TRUE;
				}
				this->current->destroy(this->current);
				this->current = NULL;
				unlock_single_segment(this->manager, this->segment);
			}
			else
			{
				linked_list_t *list;

				lock_single_segment(this->manager, this->segment);
				if ((list = this->manager->ike_sa_table[this->row]) != NULL &&
					 list->get_count(list))
				{
					this->current = list->create_enumerator(list);
					continue;
				}
				unlock_single_segment(this->manager, this->segment);
			}
			this->row += this->manager->segment_count;
		}
		this->segment++;
		this->row = this->segment;
	}
	return FALSE;
}

METHOD(enumerator_t, enumerator_destroy, void,
	private_enumerator_t *this)
{
	if (this->entry)
	{
		this->entry->condvar->signal(this->entry->condvar);
	}
	if (this->current)
	{
		this->current->destroy(this->current);
		unlock_single_segment(this->manager, this->segment);
	}
	free(this);
}

/**
 * Creates an enumerator to enumerate the entries in the hash table.
 */
static enumerator_t* create_table_enumerator(private_ike_sa_manager_t *this)
{
	private_enumerator_t *enumerator;

	INIT(enumerator,
		.enumerator = {
			.enumerate = (void*)_enumerate,
			.destroy = _enumerator_destroy,
		},
		.manager = this,
	);
	return &enumerator->enumerator;
}

/**
 * Put an entry into the hash table.
 * Note: The caller has to unlock the returned segment.
 */
static u_int put_entry(private_ike_sa_manager_t *this, entry_t *entry)
{
	linked_list_t *list;
	u_int row, segment;

	row = ike_sa_id_hash(entry->ike_sa_id) & this->table_mask;
	segment = row & this->segment_mask;

	lock_single_segment(this, segment);
	list = this->ike_sa_table[row];
	if (!list)
	{
		list = this->ike_sa_table[row] = linked_list_create();
	}
	list->insert_last(list, entry);
	this->segments[segment].count++;
	return segment;
}

/**
 * Remove an entry from the hash table.
 * Note: The caller MUST have a lock on the segment of this entry.
 */
static void remove_entry(private_ike_sa_manager_t *this, entry_t *entry)
{
	linked_list_t *list;
	u_int row, segment;

	row = ike_sa_id_hash(entry->ike_sa_id) & this->table_mask;
	segment = row & this->segment_mask;
	list = this->ike_sa_table[row];
	if (list)
	{
		entry_t *current;
		enumerator_t *enumerator;

		enumerator = list->create_enumerator(list);
		while (enumerator->enumerate(enumerator, &current))
		{
			if (current == entry)
			{
				list->remove_at(list, enumerator);
				this->segments[segment].count--;
				break;
			}
		}
		enumerator->destroy(enumerator);
	}
}

/**
 * Remove the entry at the current enumerator position.
 */
static void remove_entry_at(private_enumerator_t *this)
{
	this->entry = NULL;
	if (this->current)
	{
		linked_list_t *list = this->manager->ike_sa_table[this->row];
		list->remove_at(list, this->current);
		this->manager->segments[this->segment].count--;
	}
}

/**
 * Find an entry using the provided match function to compare the entries for
 * equality.
 */
static status_t get_entry_by_match_function(private_ike_sa_manager_t *this,
					ike_sa_id_t *ike_sa_id, entry_t **entry, u_int *segment,
					linked_list_match_t match, void *p1, void *p2)
{
	entry_t *current;
	linked_list_t *list;
	u_int row, seg;

	row = ike_sa_id_hash(ike_sa_id) & this->table_mask;
	seg = row & this->segment_mask;

	lock_single_segment(this, seg);
	list = this->ike_sa_table[row];
	if (list)
	{
		if (list->find_first(list, match, (void**)&current, p1, p2) == SUCCESS)
		{
			*entry = current;
			*segment = seg;
			/* the locked segment has to be unlocked by the caller */
			return SUCCESS;
		}
	}
	unlock_single_segment(this, seg);
	return NOT_FOUND;
}

/**
 * Find an entry by ike_sa_id_t.
 * Note: On SUCCESS, the caller has to unlock the segment.
 */
static status_t get_entry_by_id(private_ike_sa_manager_t *this,
						ike_sa_id_t *ike_sa_id, entry_t **entry, u_int *segment)
{
	return get_entry_by_match_function(this, ike_sa_id, entry, segment,
				(linked_list_match_t)entry_match_by_id, ike_sa_id, NULL);
}

/**
 * Find an entry by initiator SPI and IKE_SA_INIT hash.
 * Note: On SUCCESS, the caller has to unlock the segment.
 */
static status_t get_entry_by_hash(private_ike_sa_manager_t *this,
			ike_sa_id_t *ike_sa_id, chunk_t hash, entry_t **entry, u_int *segment)
{
	return get_entry_by_match_function(this, ike_sa_id, entry, segment,
				(linked_list_match_t)entry_match_by_hash, ike_sa_id, &hash);
}

/**
 * Find an entry by IKE_SA pointer.
 * Note: On SUCCESS, the caller has to unlock the segment.
 */
static status_t get_entry_by_sa(private_ike_sa_manager_t *this,
			ike_sa_id_t *ike_sa_id, ike_sa_t *ike_sa, entry_t **entry, u_int *segment)
{
	return get_entry_by_match_function(this, ike_sa_id, entry, segment,
				(linked_list_match_t)entry_match_by_sa, ike_sa, NULL);
}

/**
 * Wait until no other thread is using an IKE_SA, return FALSE if entry not
 * acquirable.
 */
static bool wait_for_entry(private_ike_sa_manager_t *this, entry_t *entry,
						   u_int segment)
{
	if (entry->driveout_new_threads)
	{
		/* we are not allowed to get this */
		return FALSE;
	}
	while (entry->checked_out && !entry->driveout_waiting_threads)
	{
		/* so wait until we can get it for us.
		 * we register us as waiting. */
		entry->waiting_threads++;
		entry->condvar->wait(entry->condvar, this->segments[segment].mutex);
		entry->waiting_threads--;
	}
	/* hm, a deletion request forbids us to get this SA, get next one */
	if (entry->driveout_waiting_threads)
	{
		/* we must signal here, others may be waiting on it, too */
		entry->condvar->signal(entry->condvar);
		return FALSE;
	}
	return TRUE;
}

/**
 * Put a half-open SA into the hash table.
 */
static void put_half_open(private_ike_sa_manager_t *this, entry_t *entry)
{
	half_open_t *half_open = NULL;
	linked_list_t *list;
	chunk_t addr;
	u_int row, segment;
	rwlock_t *lock;

	addr = entry->other->get_address(entry->other);
	row = chunk_hash(addr) & this->table_mask;
	segment = row & this->segment_mask;
	lock = this->half_open_segments[segment].lock;
	lock->write_lock(lock);
	list = this->half_open_table[row];
	if (list)
	{
		half_open_t *current;

		if (list->find_first(list, (linked_list_match_t)half_open_match,
							 (void**)&current, &addr) == SUCCESS)
		{
			half_open = current;
			half_open->count++;
			this->half_open_segments[segment].count++;
		}
	}
	else
	{
		list = this->half_open_table[row] = linked_list_create();
	}

	if (!half_open)
	{
		INIT(half_open,
			.other = chunk_clone(addr),
			.count = 1,
		);
		list->insert_last(list, half_open);
		this->half_open_segments[segment].count++;
	}
	lock->unlock(lock);
}

/**
 * Remove a half-open SA from the hash table.
 */
static void remove_half_open(private_ike_sa_manager_t *this, entry_t *entry)
{
	linked_list_t *list;
	chunk_t addr;
	u_int row, segment;
	rwlock_t *lock;

	addr = entry->other->get_address(entry->other);
	row = chunk_hash(addr) & this->table_mask;
	segment = row & this->segment_mask;
	lock = this->half_open_segments[segment].lock;
	lock->write_lock(lock);
	list = this->half_open_table[row];
	if (list)
	{
		half_open_t *current;
		enumerator_t *enumerator;

		enumerator = list->create_enumerator(list);
		while (enumerator->enumerate(enumerator, &current))
		{
			if (half_open_match(current, &addr))
			{
				if (--current->count == 0)
				{
					list->remove_at(list, enumerator);
					half_open_destroy(current);
				}
				this->half_open_segments[segment].count--;
				break;
			}
		}
		enumerator->destroy(enumerator);
	}
	lock->unlock(lock);
}

/**
 * Put an SA between two peers into the hash table.
 */
static void put_connected_peers(private_ike_sa_manager_t *this, entry_t *entry)
{
	connected_peers_t *connected_peers = NULL;
	chunk_t my_id, other_id;
	linked_list_t *list;
	u_int row, segment;
	rwlock_t *lock;

	my_id = entry->my_id->get_encoding(entry->my_id);
	other_id = entry->other_id->get_encoding(entry->other_id);
	row = chunk_hash_inc(other_id, chunk_hash(my_id)) & this->table_mask;
	segment = row & this->segment_mask;
	lock = this->connected_peers_segments[segment].lock;
	lock->write_lock(lock);
	list = this->connected_peers_table[row];
	if (list)
	{
		connected_peers_t *current;

		if (list->find_first(list, (linked_list_match_t)connected_peers_match,
				(void**)&current, entry->my_id, entry->other_id,
				(uintptr_t)entry->other->get_family(entry->other)) == SUCCESS)
		{
			connected_peers = current;
			if (connected_peers->sas->find_first(connected_peers->sas,
					(linked_list_match_t)entry->ike_sa_id->equals,
					NULL, entry->ike_sa_id) == SUCCESS)
			{
				lock->unlock(lock);
				return;
			}
		}
	}
	else
	{
		list = this->connected_peers_table[row] = linked_list_create();
	}

	if (!connected_peers)
	{
		INIT(connected_peers,
			.my_id = entry->my_id->clone(entry->my_id),
			.other_id = entry->other_id->clone(entry->other_id),
			.family = entry->other->get_family(entry->other),
			.sas = linked_list_create(),
		);
		list->insert_last(list, connected_peers);
	}
	connected_peers->sas->insert_last(connected_peers->sas,
									  entry->ike_sa_id->clone(entry->ike_sa_id));
	this->connected_peers_segments[segment].count++;
	lock->unlock(lock);
}

/**
 * Remove an SA between two peers from the hash table.
 */
static void remove_connected_peers(private_ike_sa_manager_t *this, entry_t *entry)
{
	chunk_t my_id, other_id;
	linked_list_t *list;
	u_int row, segment;
	rwlock_t *lock;

	my_id = entry->my_id->get_encoding(entry->my_id);
	other_id = entry->other_id->get_encoding(entry->other_id);
	row = chunk_hash_inc(other_id, chunk_hash(my_id)) & this->table_mask;
	segment = row & this->segment_mask;

	lock = this->connected_peers_segments[segment].lock;
	lock->write_lock(lock);
	list = this->connected_peers_table[row];
	if (list)
	{
		connected_peers_t *current;
		enumerator_t *enumerator;

		enumerator = list->create_enumerator(list);
		while (enumerator->enumerate(enumerator, &current))
		{
			if (connected_peers_match(current, entry->my_id, entry->other_id,
						(uintptr_t)entry->other->get_family(entry->other)))
			{
				ike_sa_id_t *ike_sa_id;
				enumerator_t *inner;

				inner = current->sas->create_enumerator(current->sas);
				while (inner->enumerate(inner, &ike_sa_id))
				{
					if (ike_sa_id->equals(ike_sa_id, entry->ike_sa_id))
					{
						current->sas->remove_at(current->sas, inner);
						ike_sa_id->destroy(ike_sa_id);
						this->connected_peers_segments[segment].count--;
						break;
					}
				}
				inner->destroy(inner);
				if (current->sas->get_count(current->sas) == 0)
				{
					list->remove_at(list, enumerator);
					connected_peers_destroy(current);
				}
				break;
			}
		}
		enumerator->destroy(enumerator);
	}
	lock->unlock(lock);
}

/**
 * Get a random SPI for new IKE_SAs
 */
static u_int64_t get_spi(private_ike_sa_manager_t *this)
{
	u_int64_t spi = 0;

	if (this->rng)
	{
		this->rng->get_bytes(this->rng, sizeof(spi), (u_int8_t*)&spi);
	}
	return spi;
}

METHOD(ike_sa_manager_t, checkout, ike_sa_t*,
	private_ike_sa_manager_t *this, ike_sa_id_t *ike_sa_id)
{
	ike_sa_t *ike_sa = NULL;
	entry_t *entry;
	u_int segment;

	DBG2(DBG_MGR, "checkout IKE_SA");

	if (get_entry_by_id(this, ike_sa_id, &entry, &segment) == SUCCESS)
	{
		if (wait_for_entry(this, entry, segment))
		{
			entry->checked_out = TRUE;
			ike_sa = entry->ike_sa;
			DBG2(DBG_MGR, "IKE_SA %s[%u] successfully checked out",
					ike_sa->get_name(ike_sa), ike_sa->get_unique_id(ike_sa));
		}
		unlock_single_segment(this, segment);
	}
	charon->bus->set_sa(charon->bus, ike_sa);
	return ike_sa;
}

METHOD(ike_sa_manager_t, checkout_new, ike_sa_t*,
	private_ike_sa_manager_t* this, bool initiator)
{
	ike_sa_id_t *ike_sa_id;
	ike_sa_t *ike_sa;

	if (initiator)
	{
		ike_sa_id = ike_sa_id_create(get_spi(this), 0, TRUE);
	}
	else
	{
		ike_sa_id = ike_sa_id_create(0, get_spi(this), FALSE);
	}
	ike_sa = ike_sa_create(ike_sa_id);
	ike_sa_id->destroy(ike_sa_id);

	DBG2(DBG_MGR, "created IKE_SA %s[%u]", ike_sa->get_name(ike_sa),
			ike_sa->get_unique_id(ike_sa));

	return ike_sa;
}

METHOD(ike_sa_manager_t, checkout_by_message, ike_sa_t*,
	private_ike_sa_manager_t* this, message_t *message)
{
	u_int segment;
	entry_t *entry;
	ike_sa_t *ike_sa = NULL;
	ike_sa_id_t *id;

	id = message->get_ike_sa_id(message);
	id = id->clone(id);
	id->switch_initiator(id);

	DBG2(DBG_MGR, "checkout IKE_SA by message");

	if (message->get_request(message) &&
		message->get_exchange_type(message) == IKE_SA_INIT &&
		this->hasher)
	{
		/* IKE_SA_INIT request. Check for an IKE_SA with such a message hash. */
		chunk_t data, hash;

		data = message->get_packet_data(message);
		this->hasher->allocate_hash(this->hasher, data, &hash);
		chunk_free(&data);

		if (get_entry_by_hash(this, id, hash, &entry, &segment) == SUCCESS)
		{
			if (entry->message_id == 0)
			{
				unlock_single_segment(this, segment);
				chunk_free(&hash);
				id->destroy(id);
				DBG1(DBG_MGR, "ignoring IKE_SA_INIT, already processing");
				return NULL;
			}
			else if (wait_for_entry(this, entry, segment))
			{
				entry->checked_out = TRUE;
				entry->message_id = message->get_message_id(message);
				ike_sa = entry->ike_sa;
				DBG2(DBG_MGR, "IKE_SA %s[%u] checked out by hash",
						ike_sa->get_name(ike_sa), ike_sa->get_unique_id(ike_sa));
			}
			unlock_single_segment(this, segment);
		}

		if (ike_sa == NULL)
		{
			if (id->get_responder_spi(id) == 0 &&
				message->get_exchange_type(message) == IKE_SA_INIT)
			{
				/* no IKE_SA found, create a new one */
				id->set_responder_spi(id, get_spi(this));
				entry = entry_create();
				entry->ike_sa = ike_sa_create(id);
				entry->ike_sa_id = id->clone(id);

				segment = put_entry(this, entry);
				entry->checked_out = TRUE;
				unlock_single_segment(this, segment);

				entry->message_id = message->get_message_id(message);
				entry->init_hash = hash;
				ike_sa = entry->ike_sa;

				DBG2(DBG_MGR, "created IKE_SA %s[%u]",
						ike_sa->get_name(ike_sa), ike_sa->get_unique_id(ike_sa));
			}
			else
			{
				chunk_free(&hash);
				DBG1(DBG_MGR, "ignoring message, no such IKE_SA");
			}
		}
		else
		{
			chunk_free(&hash);
		}
		id->destroy(id);
		charon->bus->set_sa(charon->bus, ike_sa);
		return ike_sa;
	}

	if (get_entry_by_id(this, id, &entry, &segment) == SUCCESS)
	{
		/* only check out if we are not processing this request */
		if (message->get_request(message) &&
			message->get_message_id(message) == entry->message_id)
		{
			DBG1(DBG_MGR, "ignoring request with ID %d, already processing",
				 entry->message_id);
		}
		else if (wait_for_entry(this, entry, segment))
		{
			ike_sa_id_t *ike_id = entry->ike_sa->get_id(entry->ike_sa);
			entry->checked_out = TRUE;
			entry->message_id = message->get_message_id(message);
			if (ike_id->get_responder_spi(ike_id) == 0)
			{
				ike_id->set_responder_spi(ike_id, id->get_responder_spi(id));
			}
			ike_sa = entry->ike_sa;
			DBG2(DBG_MGR, "IKE_SA %s[%u] successfully checked out",
					ike_sa->get_name(ike_sa), ike_sa->get_unique_id(ike_sa));
		}
		unlock_single_segment(this, segment);
	}
	id->destroy(id);
	charon->bus->set_sa(charon->bus, ike_sa);
	return ike_sa;
}

METHOD(ike_sa_manager_t, checkout_by_config, ike_sa_t*,
	private_ike_sa_manager_t *this, peer_cfg_t *peer_cfg)
{
	enumerator_t *enumerator;
	entry_t *entry;
	ike_sa_t *ike_sa = NULL;
	peer_cfg_t *current_peer;
	ike_cfg_t *current_ike;
	u_int segment;

	DBG2(DBG_MGR, "checkout IKE_SA by config");

	if (!this->reuse_ikesa)
	{	/* IKE_SA reuse disable by config */
		ike_sa = checkout_new(this, TRUE);
		charon->bus->set_sa(charon->bus, ike_sa);
		return ike_sa;
	}

	enumerator = create_table_enumerator(this);
	while (enumerator->enumerate(enumerator, &entry, &segment))
	{
		if (!wait_for_entry(this, entry, segment))
		{
			continue;
		}
		if (entry->ike_sa->get_state(entry->ike_sa) == IKE_DELETING)
		{	/* skip IKE_SAs which are not usable */
			continue;
		}

		current_peer = entry->ike_sa->get_peer_cfg(entry->ike_sa);
		if (current_peer && current_peer->equals(current_peer, peer_cfg))
		{
			current_ike = current_peer->get_ike_cfg(current_peer);
			if (current_ike->equals(current_ike, peer_cfg->get_ike_cfg(peer_cfg)))
			{
				entry->checked_out = TRUE;
				ike_sa = entry->ike_sa;
				DBG2(DBG_MGR, "found existing IKE_SA %u with a '%s' config",
						ike_sa->get_unique_id(ike_sa),
						current_peer->get_name(current_peer));
				break;
			}
		}
	}
	enumerator->destroy(enumerator);

	if (!ike_sa)
	{	/* no IKE_SA using such a config, hand out a new */
		ike_sa = checkout_new(this, TRUE);
	}
	charon->bus->set_sa(charon->bus, ike_sa);
	return ike_sa;
}

METHOD(ike_sa_manager_t, checkout_by_id, ike_sa_t*,
	private_ike_sa_manager_t *this, u_int32_t id, bool child)
{
	enumerator_t *enumerator, *children;
	entry_t *entry;
	ike_sa_t *ike_sa = NULL;
	child_sa_t *child_sa;
	u_int segment;

	DBG2(DBG_MGR, "checkout IKE_SA by ID");

	enumerator = create_table_enumerator(this);
	while (enumerator->enumerate(enumerator, &entry, &segment))
	{
		if (wait_for_entry(this, entry, segment))
		{
			/* look for a child with such a reqid ... */
			if (child)
			{
				children = entry->ike_sa->create_child_sa_enumerator(entry->ike_sa);
				while (children->enumerate(children, (void**)&child_sa))
				{
					if (child_sa->get_reqid(child_sa) == id)
					{
						ike_sa = entry->ike_sa;
						break;
					}
				}
				children->destroy(children);
			}
			else /* ... or for a IKE_SA with such a unique id */
			{
				if (entry->ike_sa->get_unique_id(entry->ike_sa) == id)
				{
					ike_sa = entry->ike_sa;
				}
			}
			/* got one, return */
			if (ike_sa)
			{
				entry->checked_out = TRUE;
				DBG2(DBG_MGR, "IKE_SA %s[%u] successfully checked out",
						ike_sa->get_name(ike_sa), ike_sa->get_unique_id(ike_sa));
				break;
			}
		}
	}
	enumerator->destroy(enumerator);

	charon->bus->set_sa(charon->bus, ike_sa);
	return ike_sa;
}

METHOD(ike_sa_manager_t, checkout_by_name, ike_sa_t*,
	private_ike_sa_manager_t *this, char *name, bool child)
{
	enumerator_t *enumerator, *children;
	entry_t *entry;
	ike_sa_t *ike_sa = NULL;
	child_sa_t *child_sa;
	u_int segment;

	enumerator = create_table_enumerator(this);
	while (enumerator->enumerate(enumerator, &entry, &segment))
	{
		if (wait_for_entry(this, entry, segment))
		{
			/* look for a child with such a policy name ... */
			if (child)
			{
				children = entry->ike_sa->create_child_sa_enumerator(entry->ike_sa);
				while (children->enumerate(children, (void**)&child_sa))
				{
					if (streq(child_sa->get_name(child_sa), name))
					{
						ike_sa = entry->ike_sa;
						break;
					}
				}
				children->destroy(children);
			}
			else /* ... or for a IKE_SA with such a connection name */
			{
				if (streq(entry->ike_sa->get_name(entry->ike_sa), name))
				{
					ike_sa = entry->ike_sa;
				}
			}
			/* got one, return */
			if (ike_sa)
			{
				entry->checked_out = TRUE;
				DBG2(DBG_MGR, "IKE_SA %s[%u] successfully checked out",
						ike_sa->get_name(ike_sa), ike_sa->get_unique_id(ike_sa));
				break;
			}
		}
	}
	enumerator->destroy(enumerator);

	charon->bus->set_sa(charon->bus, ike_sa);
	return ike_sa;
}

/**
 * enumerator filter function, waiting variant
 */
static bool enumerator_filter_wait(private_ike_sa_manager_t *this,
								   entry_t **in, ike_sa_t **out, u_int *segment)
{
	if (wait_for_entry(this, *in, *segment))
	{
		*out = (*in)->ike_sa;
		return TRUE;
	}
	return FALSE;
}

/**
 * enumerator filter function, skipping variant
 */
static bool enumerator_filter_skip(private_ike_sa_manager_t *this,
								   entry_t **in, ike_sa_t **out, u_int *segment)
{
	if (!(*in)->driveout_new_threads &&
		!(*in)->driveout_waiting_threads &&
		!(*in)->checked_out)
	{
		*out = (*in)->ike_sa;
		return TRUE;
	}
	return FALSE;
}

METHOD(ike_sa_manager_t, create_enumerator, enumerator_t*,
	private_ike_sa_manager_t* this, bool wait)
{
	return enumerator_create_filter(create_table_enumerator(this),
			wait ? (void*)enumerator_filter_wait : (void*)enumerator_filter_skip,
			this, NULL);
}

METHOD(ike_sa_manager_t, checkin, void,
	private_ike_sa_manager_t *this, ike_sa_t *ike_sa)
{
	/* to check the SA back in, we look for the pointer of the ike_sa
	 * in all entries.
	 * The lookup is done by initiator SPI, so even if the SPI has changed (e.g.
	 * on reception of a IKE_SA_INIT response) the lookup will work but
	 * updating of the SPI MAY be necessary...
	 */
	entry_t *entry;
	ike_sa_id_t *ike_sa_id;
	host_t *other;
	identification_t *my_id, *other_id;
	u_int segment;

	ike_sa_id = ike_sa->get_id(ike_sa);
	my_id = ike_sa->get_my_id(ike_sa);
	other_id = ike_sa->get_other_id(ike_sa);
	other = ike_sa->get_other_host(ike_sa);

	DBG2(DBG_MGR, "checkin IKE_SA %s[%u]", ike_sa->get_name(ike_sa),
			ike_sa->get_unique_id(ike_sa));

	/* look for the entry */
	if (get_entry_by_sa(this, ike_sa_id, ike_sa, &entry, &segment) == SUCCESS)
	{
		/* ike_sa_id must be updated */
		entry->ike_sa_id->replace_values(entry->ike_sa_id, ike_sa->get_id(ike_sa));
		/* signal waiting threads */
		entry->checked_out = FALSE;
		entry->message_id = -1;
		/* check if this SA is half-open */
		if (entry->half_open && ike_sa->get_state(ike_sa) != IKE_CONNECTING)
		{
			/* not half open anymore */
			entry->half_open = FALSE;
			remove_half_open(this, entry);
		}
		else if (entry->half_open && !other->ip_equals(other, entry->other))
		{
			/* the other host's IP has changed, we must update the hash table */
			remove_half_open(this, entry);
			DESTROY_IF(entry->other);
			entry->other = other->clone(other);
			put_half_open(this, entry);
		}
		else if (!entry->half_open &&
				 !entry->ike_sa_id->is_initiator(entry->ike_sa_id) &&
				 ike_sa->get_state(ike_sa) == IKE_CONNECTING)
		{
			/* this is a new half-open SA */
			entry->half_open = TRUE;
			entry->other = other->clone(other);
			put_half_open(this, entry);
		}
		DBG2(DBG_MGR, "check-in of IKE_SA successful.");
		entry->condvar->signal(entry->condvar);
	}
	else
	{
		entry = entry_create();
		entry->ike_sa_id = ike_sa_id->clone(ike_sa_id);
		entry->ike_sa = ike_sa;
		segment = put_entry(this, entry);
	}

	/* apply identities for duplicate test */
	if (ike_sa->get_state(ike_sa) == IKE_ESTABLISHED &&
		entry->my_id == NULL && entry->other_id == NULL)
	{
		entry->my_id = my_id->clone(my_id);
		entry->other_id = other_id->clone(other_id);
		if (!entry->other)
		{
			entry->other = other->clone(other);
		}
		put_connected_peers(this, entry);
	}

	unlock_single_segment(this, segment);

	charon->bus->set_sa(charon->bus, NULL);
}

METHOD(ike_sa_manager_t, checkin_and_destroy, void,
	private_ike_sa_manager_t *this, ike_sa_t *ike_sa)
{
	/* deletion is a bit complex, we must ensure that no thread is waiting for
	 * this SA.
	 * We take this SA from the table, and start signaling while threads
	 * are in the condvar.
	 */
	entry_t *entry;
	ike_sa_id_t *ike_sa_id;
	u_int segment;

	ike_sa_id = ike_sa->get_id(ike_sa);

	DBG2(DBG_MGR, "checkin and destroy IKE_SA %s[%u]", ike_sa->get_name(ike_sa),
			ike_sa->get_unique_id(ike_sa));

	if (get_entry_by_sa(this, ike_sa_id, ike_sa, &entry, &segment) == SUCCESS)
	{
		/* drive out waiting threads, as we are in hurry */
		entry->driveout_waiting_threads = TRUE;
		/* mark it, so no new threads can get this entry */
		entry->driveout_new_threads = TRUE;
		/* wait until all workers have done their work */
		while (entry->waiting_threads)
		{
			/* wake up all */
			entry->condvar->broadcast(entry->condvar);
			/* they will wake us again when their work is done */
			entry->condvar->wait(entry->condvar, this->segments[segment].mutex);
		}
		remove_entry(this, entry);
		unlock_single_segment(this, segment);

		if (entry->half_open)
		{
			remove_half_open(this, entry);
		}
		if (entry->my_id && entry->other_id)
		{
			remove_connected_peers(this, entry);
		}

		entry_destroy(entry);

		DBG2(DBG_MGR, "check-in and destroy of IKE_SA successful");
	}
	else
	{
		DBG1(DBG_MGR, "tried to check-in and delete nonexisting IKE_SA");
		ike_sa->destroy(ike_sa);
	}
	charon->bus->set_sa(charon->bus, NULL);
}

METHOD(ike_sa_manager_t, check_uniqueness, bool,
	private_ike_sa_manager_t *this, ike_sa_t *ike_sa, bool force_replace)
{
	bool cancel = FALSE;
	peer_cfg_t *peer_cfg;
	unique_policy_t policy;
	linked_list_t *list, *duplicate_ids = NULL;
	enumerator_t *enumerator;
	ike_sa_id_t *duplicate_id = NULL;
	identification_t *me, *other;
	u_int row, segment;
	rwlock_t *lock;

	peer_cfg = ike_sa->get_peer_cfg(ike_sa);
	policy = peer_cfg->get_unique_policy(peer_cfg);
	if (policy == UNIQUE_NO && !force_replace)
	{
		return FALSE;
	}

	me = ike_sa->get_my_id(ike_sa);
	other = ike_sa->get_other_id(ike_sa);

	row = chunk_hash_inc(other->get_encoding(other),
						 chunk_hash(me->get_encoding(me))) & this->table_mask;
	segment = row & this->segment_mask;

	lock = this->connected_peers_segments[segment & this->segment_mask].lock;
	lock->read_lock(lock);
	list = this->connected_peers_table[row];
	if (list)
	{
		connected_peers_t *current;
		host_t *other_host;

		other_host = ike_sa->get_other_host(ike_sa);
		if (list->find_first(list, (linked_list_match_t)connected_peers_match,
					(void**)&current, me, other,
					(uintptr_t)other_host->get_family(other_host)) == SUCCESS)
		{
			/* clone the list, so we can release the lock */
			duplicate_ids = current->sas->clone_offset(current->sas,
												offsetof(ike_sa_id_t, clone));
		}
	}
	lock->unlock(lock);

	if (!duplicate_ids)
	{
		return FALSE;
	}

	enumerator = duplicate_ids->create_enumerator(duplicate_ids);
	while (enumerator->enumerate(enumerator, &duplicate_id))
	{
		status_t status = SUCCESS;
		ike_sa_t *duplicate;

		duplicate = checkout(this, duplicate_id);
		if (!duplicate)
		{
			continue;
		}
		if (force_replace)
		{
			DBG1(DBG_IKE, "destroying duplicate IKE_SA for peer '%Y', "
				 "received INITIAL_CONTACT", other);
			checkin_and_destroy(this, duplicate);
			continue;
		}
		peer_cfg = duplicate->get_peer_cfg(duplicate);
		if (peer_cfg && peer_cfg->equals(peer_cfg, ike_sa->get_peer_cfg(ike_sa)))
		{
			switch (duplicate->get_state(duplicate))
			{
				case IKE_ESTABLISHED:
				case IKE_REKEYING:
					switch (policy)
					{
						case UNIQUE_REPLACE:
							DBG1(DBG_IKE, "deleting duplicate IKE_SA for peer "
									"'%Y' due to uniqueness policy", other);
							status = duplicate->delete(duplicate);
							break;
						case UNIQUE_KEEP:
							cancel = TRUE;
							/* we keep the first IKE_SA and delete all
							 * other duplicates that might exist */
							policy = UNIQUE_REPLACE;
							break;
						default:
							break;
					}
					break;
				default:
					break;
			}
		}
		if (status == DESTROY_ME)
		{
			checkin_and_destroy(this, duplicate);
		}
		else
		{
			checkin(this, duplicate);
		}
	}
	enumerator->destroy(enumerator);
	duplicate_ids->destroy_offset(duplicate_ids, offsetof(ike_sa_id_t, destroy));
	/* reset thread's current IKE_SA after checkin */
	charon->bus->set_sa(charon->bus, ike_sa);
	return cancel;
}

METHOD(ike_sa_manager_t, has_contact, bool,
	private_ike_sa_manager_t *this, identification_t *me,
	identification_t *other, int family)
{
	linked_list_t *list;
	u_int row, segment;
	rwlock_t *lock;
	bool found = FALSE;

	row = chunk_hash_inc(other->get_encoding(other),
						 chunk_hash(me->get_encoding(me))) & this->table_mask;
	segment = row & this->segment_mask;
	lock = this->connected_peers_segments[segment & this->segment_mask].lock;
	lock->read_lock(lock);
	list = this->connected_peers_table[row];
	if (list)
	{
		if (list->find_first(list, (linked_list_match_t)connected_peers_match,
							 NULL, me, other, family) == SUCCESS)
		{
			found = TRUE;
		}
	}
	lock->unlock(lock);

	return found;
}

METHOD(ike_sa_manager_t, get_count, u_int,
	private_ike_sa_manager_t *this)
{
	u_int segment, count = 0;
	mutex_t *mutex;

	for (segment = 0; segment < this->segment_count; segment++)
	{
		mutex = this->segments[segment & this->segment_mask].mutex;
		mutex->lock(mutex);
		count += this->segments[segment].count;
		mutex->unlock(mutex);
	}
	return count;
}

METHOD(ike_sa_manager_t, get_half_open_count, u_int,
	private_ike_sa_manager_t *this, host_t *ip)
{
	linked_list_t *list;
	u_int segment, row;
	rwlock_t *lock;
	chunk_t addr;
	u_int count = 0;

	if (ip)
	{
		addr = ip->get_address(ip);
		row = chunk_hash(addr) & this->table_mask;
		segment = row & this->segment_mask;
		lock = this->half_open_segments[segment & this->segment_mask].lock;
		lock->read_lock(lock);
		if ((list = this->half_open_table[row]) != NULL)
		{
			half_open_t *current;

			if (list->find_first(list, (linked_list_match_t)half_open_match,
								 (void**)&current, &addr) == SUCCESS)
			{
				count = current->count;
			}
		}
		lock->unlock(lock);
	}
	else
	{
		for (segment = 0; segment < this->segment_count; segment++)
		{
			lock = this->half_open_segments[segment & this->segment_mask].lock;
			lock->read_lock(lock);
			count += this->half_open_segments[segment].count;
			lock->unlock(lock);
		}
	}
	return count;
}

METHOD(ike_sa_manager_t, flush, void,
	private_ike_sa_manager_t *this)
{
	/* destroy all list entries */
	enumerator_t *enumerator;
	entry_t *entry;
	u_int segment;

	lock_all_segments(this);
	DBG2(DBG_MGR, "going to destroy IKE_SA manager and all managed IKE_SA's");
	/* Step 1: drive out all waiting threads  */
	DBG2(DBG_MGR, "set driveout flags for all stored IKE_SA's");
	enumerator = create_table_enumerator(this);
	while (enumerator->enumerate(enumerator, &entry, &segment))
	{
		/* do not accept new threads, drive out waiting threads */
		entry->driveout_new_threads = TRUE;
		entry->driveout_waiting_threads = TRUE;
	}
	enumerator->destroy(enumerator);
	DBG2(DBG_MGR, "wait for all threads to leave IKE_SA's");
	/* Step 2: wait until all are gone */
	enumerator = create_table_enumerator(this);
	while (enumerator->enumerate(enumerator, &entry, &segment))
	{
		while (entry->waiting_threads || entry->checked_out)
		{
			/* wake up all */
			entry->condvar->broadcast(entry->condvar);
			/* go sleeping until they are gone */
			entry->condvar->wait(entry->condvar, this->segments[segment].mutex);
		}
	}
	enumerator->destroy(enumerator);
	DBG2(DBG_MGR, "delete all IKE_SA's");
	/* Step 3: initiate deletion of all IKE_SAs */
	enumerator = create_table_enumerator(this);
	while (enumerator->enumerate(enumerator, &entry, &segment))
	{
		charon->bus->set_sa(charon->bus, entry->ike_sa);
		/* as the delete never gets processed, fire down events */
		switch (entry->ike_sa->get_state(entry->ike_sa))
		{
			case IKE_ESTABLISHED:
			case IKE_REKEYING:
			case IKE_DELETING:
				charon->bus->ike_updown(charon->bus, entry->ike_sa, FALSE);
				break;
			default:
				break;
		}
		entry->ike_sa->delete(entry->ike_sa);
	}
	enumerator->destroy(enumerator);

	DBG2(DBG_MGR, "destroy all entries");
	/* Step 4: destroy all entries */
	enumerator = create_table_enumerator(this);
	while (enumerator->enumerate(enumerator, &entry, &segment))
	{
		charon->bus->set_sa(charon->bus, entry->ike_sa);
		if (entry->half_open)
		{
			remove_half_open(this, entry);
		}
		if (entry->my_id && entry->other_id)
		{
			remove_connected_peers(this, entry);
		}
		remove_entry_at((private_enumerator_t*)enumerator);
		entry_destroy(entry);
	}
	enumerator->destroy(enumerator);
	charon->bus->set_sa(charon->bus, NULL);
	unlock_all_segments(this);

	this->rng->destroy(this->rng);
	this->rng = NULL;
	this->hasher->destroy(this->hasher);
	this->hasher = NULL;
}

METHOD(ike_sa_manager_t, destroy, void,
	private_ike_sa_manager_t *this)
{
	u_int i;

	for (i = 0; i < this->table_size; i++)
	{
		DESTROY_IF(this->ike_sa_table[i]);
		DESTROY_IF(this->half_open_table[i]);
		DESTROY_IF(this->connected_peers_table[i]);
	}
	free(this->ike_sa_table);
	free(this->half_open_table);
	free(this->connected_peers_table);
	for (i = 0; i < this->segment_count; i++)
	{
		this->segments[i].mutex->destroy(this->segments[i].mutex);
		this->half_open_segments[i].lock->destroy(this->half_open_segments[i].lock);
		this->connected_peers_segments[i].lock->destroy(this->connected_peers_segments[i].lock);
	}
	free(this->segments);
	free(this->half_open_segments);
	free(this->connected_peers_segments);

	free(this);
}

/**
 * This function returns the next-highest power of two for the given number.
 * The algorithm works by setting all bits on the right-hand side of the most
 * significant 1 to 1 and then increments the whole number so it rolls over
 * to the nearest power of two. Note: returns 0 for n == 0
 */
static u_int get_nearest_powerof2(u_int n)
{
	u_int i;

	--n;
	for (i = 1; i < sizeof(u_int) * 8; i <<= 1)
	{
		n |= n >> i;
	}
	return ++n;
}

/*
 * Described in header.
 */
ike_sa_manager_t *ike_sa_manager_create()
{
	private_ike_sa_manager_t *this;
	u_int i;

	INIT(this,
		.public = {
			.checkout = _checkout,
			.checkout_new = _checkout_new,
			.checkout_by_message = _checkout_by_message,
			.checkout_by_config = _checkout_by_config,
			.checkout_by_id = _checkout_by_id,
			.checkout_by_name = _checkout_by_name,
			.check_uniqueness = _check_uniqueness,
			.has_contact = _has_contact,
			.create_enumerator = _create_enumerator,
			.checkin = _checkin,
			.checkin_and_destroy = _checkin_and_destroy,
			.get_count = _get_count,
			.get_half_open_count = _get_half_open_count,
			.flush = _flush,
			.destroy = _destroy,
		},
	);

	this->hasher = lib->crypto->create_hasher(lib->crypto, HASH_PREFERRED);
	if (this->hasher == NULL)
	{
		DBG1(DBG_MGR, "manager initialization failed, no hasher supported");
		free(this);
		return NULL;
	}
	this->rng = lib->crypto->create_rng(lib->crypto, RNG_WEAK);
	if (this->rng == NULL)
	{
		DBG1(DBG_MGR, "manager initialization failed, no RNG supported");
		this->hasher->destroy(this->hasher);
		free(this);
		return NULL;
	}

	this->table_size = get_nearest_powerof2(lib->settings->get_int(lib->settings,
						"charon.ikesa_table_size", DEFAULT_HASHTABLE_SIZE));
	this->table_size = max(1, min(this->table_size, MAX_HASHTABLE_SIZE));
	this->table_mask = this->table_size - 1;

	this->segment_count = get_nearest_powerof2(lib->settings->get_int(lib->settings,
						"charon.ikesa_table_segments", DEFAULT_SEGMENT_COUNT));
	this->segment_count = max(1, min(this->segment_count, this->table_size));
	this->segment_mask = this->segment_count - 1;
	this->ike_sa_table = calloc(this->table_size, sizeof(linked_list_t*));

	this->segments = (segment_t*)calloc(this->segment_count, sizeof(segment_t));
	for (i = 0; i < this->segment_count; i++)
	{
		this->segments[i].mutex = mutex_create(MUTEX_TYPE_RECURSIVE);
		this->segments[i].count = 0;
	}

	/* we use the same table parameters for the table to track half-open SAs */
	this->half_open_table = calloc(this->table_size, sizeof(linked_list_t*));
	this->half_open_segments = calloc(this->segment_count, sizeof(shareable_segment_t));
	for (i = 0; i < this->segment_count; i++)
	{
		this->half_open_segments[i].lock = rwlock_create(RWLOCK_TYPE_DEFAULT);
		this->half_open_segments[i].count = 0;
	}

	/* also for the hash table used for duplicate tests */
	this->connected_peers_table = calloc(this->table_size, sizeof(linked_list_t*));
	this->connected_peers_segments = calloc(this->segment_count, sizeof(shareable_segment_t));
	for (i = 0; i < this->segment_count; i++)
	{
		this->connected_peers_segments[i].lock = rwlock_create(RWLOCK_TYPE_DEFAULT);
		this->connected_peers_segments[i].count = 0;
	}

	this->reuse_ikesa = lib->settings->get_bool(lib->settings,
												"charon.reuse_ikesa", TRUE);
	return &this->public;
}
