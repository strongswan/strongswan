/*
 * Copyright (C) 2013 Tobias Brunner
 * Coyyright (C) 2020 Noel Kuntze
 * Copyright (C) 2023 Andreas Steffen
 *
 * Copyright (C) secunet Security Networks AG
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

#include <unistd.h>
#include <fcntl.h>

#ifdef WIN32
#include <signal.h>
#include <synchapi.h>
#endif

#include "kernel_libipsec_router.h"

#include <daemon.h>
#include <ipsec.h>
#include <collections/hashtable.h>
#include <networking/tun_device.h>
#include <threading/rwlock.h>
#include <threading/thread.h>
#include <processing/jobs/callback_job.h>
#include <processing/jobs/acquire_job.h>

typedef struct private_kernel_libipsec_router_t private_kernel_libipsec_router_t;

/**
 * Entry in the TUN device map
 */
typedef struct {
	/** virtual IP (points to internal data of tun) */
	host_t *addr;

	/** underlying TUN file descriptor (cached from tun) */
#ifdef WIN32
	HANDLE handle;
#else /* !WIN32 */
	int fd;
#endif

	/** TUN device */
	tun_device_t *tun;
} tun_entry_t;

/**
 * Single instance of the router
 */
kernel_libipsec_router_t *router;

/**
 * Private data
 */
struct private_kernel_libipsec_router_t {

	/**
	 * Public interface
	 */
	kernel_libipsec_router_t public;

	/**
	 * Default TUN device if kernel interface does not require separate TUN
	 * devices per VIP or for tunnels without VIP.
	 */
	tun_entry_t tun;

	/**
	 * Hashtable that maps virtual IPs to TUN devices (tun_entry_t).
	 */
	hashtable_t *tuns;

	/**
	 * Lock for TUN device map
	 */
	rwlock_t *lock;

#ifdef WIN32
	/**
	 * Event we use to signal handle_plain() about changes regarding tun devices
	 */
	HANDLE event;

	/**
	 * This is a notification value that we atomically set and reset if we don't
	 * use events right now. It's used so that we can avoid using WaitFor*
	 * functions when busy looping.
	 */
	volatile bool notify;

	/**
	 * Setting for waiting on event or using busy loop
	 */
	bool use_events;

	/**
	 * Whether a packet could be read from any of the tun devices in the last
	 * iteration of handle_plain
	 */
	bool got_result;

	/**
	 * How long the spinloop should run in microseconds after failing to
	 * get a packet before it waits for events again.
	 */
	uint64_t spinloop_threshold;

	/**
	 * TBD
	 */
	LARGE_INTEGER switching_time;

	/**
	 * TBD
	 */
	bool windows_close;
#else /* !WIN32 */
	/**
	 * Pipe to signal handle_plain() about changes regarding TUN devices
	 */
	int notify[2];
#endif
};

/**
 * Hash function for TUN device map
 */
static u_int tun_entry_hash(tun_entry_t *entry)
{
	return chunk_hash(entry->addr->get_address(entry->addr));
}

/**
 * Comparison function for TUN device map
 */
static bool tun_entry_equals(tun_entry_t *a, tun_entry_t *b)
{
	return a->addr->ip_equals(a->addr, b->addr);
}

/**
 * Outbound callback
 */
static void send_esp(void *data, esp_packet_t *packet)
{
	charon->sender->send_no_marker(charon->sender, (packet_t*)packet);
}

/**
 * Raise an acquire event
 */
static void raise_acquire(uint32_t reqid, kernel_acquire_data_t *data)
{
	lib->processor->queue_job(lib->processor,
			(job_t *)acquire_job_create(reqid, data));
}

/**
 * Receiver callback
 */
static void receiver_esp_cb(void *data, packet_t *packet)
{
	ipsec->processor->queue_inbound(ipsec->processor,
									esp_packet_create_from_packet(packet));
}

/**
 * Inbound callback
 */
static void deliver_plain(private_kernel_libipsec_router_t *this,
						  ip_packet_t *packet)
{
	tun_device_t *tun;
	tun_entry_t *entry, lookup = {
		.addr = packet->get_destination(packet),
	};

	this->lock->read_lock(this->lock);
	entry = this->tuns->get(this->tuns, &lookup);
	tun = entry ? entry->tun : this->tun.tun;
	tun->write_packet(tun, packet->get_encoding(packet));
	this->lock->unlock(this->lock);
	packet->destroy(packet);
}

/**
 * Read and process outbound plaintext packet for the given TUN device
 */
static bool process_plain(tun_device_t *tun)
{
	chunk_t raw;

	if (tun->read_packet(tun, &raw))
	{
		ip_packet_t *packet;

		packet = ip_packet_create(raw);
		if (packet)
		{
			ipsec->processor->queue_outbound(ipsec->processor, packet);
		}
		else
		{
			DBG1(DBG_KNL, "invalid IP packet read from TUN device");
		}
		return TRUE;
	}
	return FALSE;
}

#ifndef WIN32
/**
 * Find flagged revents in a pollfd set by fd
 */
static int find_revents(struct pollfd *pfd, int count, int fd)
{
	int i;

	for (i = 0; i < count; i++)
	{
		if (pfd[i].fd == fd)
		{
			return pfd[i].revents;
		}
	}
	return 0;
}
#endif

/**
 * Job handling outbound plaintext packets
 */
static job_requeue_t handle_plain(private_kernel_libipsec_router_t *this)
{
	enumerator_t *enumerator;
	tun_entry_t *entry;
	int count = 0;
#ifdef WIN32
	uint64_t processed_packets = 0, failed_calls = 0;
	LARGE_INTEGER StartingTime = { .QuadPart = 0 };
	LARGE_INTEGER EndingTime = { .QuadPart = 0 };
	LARGE_INTEGER ElapsedMicrosecs = { .QuadPart = 0};
	LARGE_INTEGER Frequency = { .QuadPart = 0};

	QueryPerformanceFrequency(&Frequency);

	this->lock->read_lock(this->lock);

	if (this->use_events || !this->got_result)
	{
		HANDLE *tun_handles;
		DWORD ret;

		DBG2(DBG_LIB, "Running in event driven mode.");
		QueryPerformanceCounter(&this->switching_time);

		/* Check if any of the TUN devices has data for reading */
		tun_handles = alloca(sizeof(HANDLE)* (this->tuns->get_count(this->tuns)+2));
		tun_handles[count] = this->event;
		count++;
		tun_handles[count] = this->tun.handle;
		count++;

		enumerator = this->tuns->create_enumerator(this->tuns);
		while (enumerator->enumerate(enumerator, NULL, &entry))
		{
			tun_handles[count] = entry->handle;
			count++;
		}
		enumerator->destroy(enumerator);

		this->lock->unlock(this->lock);
		QueryPerformanceCounter(&StartingTime);
		ret = WaitForMultipleObjects(count, tun_handles, FALSE, INFINITE);
		QueryPerformanceCounter(&EndingTime);
		ElapsedMicrosecs.QuadPart = EndingTime.QuadPart - StartingTime.QuadPart;
		ElapsedMicrosecs.QuadPart *= 1000000000;
		ElapsedMicrosecs.QuadPart /= Frequency.QuadPart;
		DBG2(DBG_LIB, "Waited for %lld nanoseconds (%lld miliseconds)",
		ElapsedMicrosecs.QuadPart, ElapsedMicrosecs.QuadPart/1000000);
		this->lock->read_lock(this->lock);

		if (ret >= WAIT_OBJECT_0 || ret <= WAIT_OBJECT_0 + count -1)
		{
			int offset = ret - WAIT_OBJECT_0;
			this->got_result = TRUE;

			switch (offset)
			{
				case 0:
					DBG2(DBG_LIB, "Interrupt job from event");
					ResetEvent(tun_handles[offset]);
					break;
				case 1:
					DBG2(DBG_LIB, "got packet in event mode");
					process_plain(this->tun.tun);
					break;
				default:
					DBG2(DBG_LIB, "got packet in event mode");
					enumerator = this->tuns->create_enumerator(this->tuns);
					while (enumerator->enumerate(enumerator, NULL, &entry))
					{
						if (WaitForSingleObjectEx(entry->handle, 0, FALSE) == WAIT_OBJECT_0)
						{
							process_plain(entry->tun);
						}
					}
					enumerator->destroy(enumerator);
					break;
			}
		}
		else if (ret >= WAIT_ABANDONED_0 || ret <= WAIT_ABANDONED_0 + count -1)
		{
			int offset = ret - WAIT_ABANDONED_0;
			this->got_result = FALSE;
			switch(offset)
			{
				case 0:
					DBG2(DBG_LIB, "Notify handle closed.");
					break;
				case 1:
					DBG2(DBG_LIB, "Primary tun handle closed");
					break;
				default:
					DBG2(DBG_LIB, "Other tun handle closed at offset %d", offset);
					break;
			}
			return JOB_REQUEUE_NONE;
		}
		else if (ret == WAIT_FAILED)
		{
			DBG1(DBG_LIB, "Failed to wait for tun devices to be ready for reading");
		}
		QueryPerformanceCounter(&this->switching_time);
	}
	else
	{
		/* TODO: Set realtime priority for charon-svc.exe
		 * (otherwise Windows suspends the process after only a couple
		 * of processes or stops waking up the process events)
		 */

		/* Check each handle individually */
		QueryPerformanceCounter(&EndingTime);
		ElapsedMicrosecs.QuadPart = EndingTime.QuadPart -
									this->switching_time.QuadPart;
		ElapsedMicrosecs.QuadPart *= 1000000000;
		ElapsedMicrosecs.QuadPart /= Frequency.QuadPart;
		DBG2(DBG_LIB, "Delay between switching is %lld nanoseconds",
			 ElapsedMicrosecs.QuadPart);

		do {
			/* Because the NT kernel scheduler stops waking up the process
			 * if we wait too often, we need to avoid calling any WaitFor* functions.
			 * Thus we busy loop in user space until we get no result for some time */
			this->got_result = FALSE;
			if (process_plain(this->tun.tun))
			{
				this->got_result |= TRUE;
				processed_packets++;
			}
			else
			{
				failed_calls++;
			}
			ResetEvent(this->tun.handle);

			enumerator = this->tuns->create_enumerator(this->tuns);
			while(enumerator->enumerate(enumerator, NULL, &entry))
			{
				if (process_plain(entry->tun))
				{
					processed_packets++;
					this->got_result |= TRUE;
				}
				else
				{
					failed_calls++;
				}
				ResetEvent(entry->handle);
			}
			enumerator->destroy(enumerator);

			if (!this->got_result)
			{
				if (!StartingTime.QuadPart)
				{
					QueryPerformanceCounter(&StartingTime);
				}
				else
				{
					QueryPerformanceCounter(&EndingTime);
					ElapsedMicrosecs.QuadPart = EndingTime.QuadPart -
												StartingTime.QuadPart;
					ElapsedMicrosecs.QuadPart *= 1000000000;
					ElapsedMicrosecs.QuadPart /= Frequency.QuadPart;
				}

				enumerator = this->tuns->create_enumerator(this->tuns);
				while(enumerator->enumerate(enumerator, NULL, &entry))
				{
					ResetEvent(entry->handle);
				}
				enumerator->destroy(enumerator);

				if (ElapsedMicrosecs.QuadPart >= this->spinloop_threshold)
				{
					DBG2(DBG_LIB, "Processed %lld packets, "
						"failed %lld calls to read packets. "
						"Reached threshold at %lld ns, switching back to events.",
						 processed_packets, failed_calls,
						 ElapsedMicrosecs.QuadPart);

					ResetEvent(this->event);
					this->notify = FALSE;
					break;
				}
			}

			if(this->notify)
			{
				DBG2(DBG_LIB, "Processed %lld packets, Interrupt job from bool",
					 processed_packets);
				ResetEvent(this->event);
				this->notify = FALSE;
				break;
			}

		}
		while (TRUE);
	}
#else /* !WIN32 */
	bool oldstate;
	char buf[1];
	struct pollfd *pfd;

	this->lock->read_lock(this->lock);

	pfd = alloca(sizeof(*pfd) * (this->tuns->get_count(this->tuns) + 2));
	pfd[count].fd = this->notify[0];
	pfd[count].events = POLLIN;
	count++;
	pfd[count].fd = this->tun.fd;
	pfd[count].events = POLLIN;
	count++;

	enumerator = this->tuns->create_enumerator(this->tuns);
	while (enumerator->enumerate(enumerator, NULL, &entry))
	{
		pfd[count].fd = entry->fd;
		pfd[count].events = POLLIN;
		count++;
	}
	enumerator->destroy(enumerator);
	this->lock->unlock(this->lock);

	oldstate = thread_cancelability(TRUE);
	if (poll(pfd, count, -1) <= 0)
	{
		thread_cancelability(oldstate);
		return JOB_REQUEUE_FAIR;
	}
	thread_cancelability(oldstate);

	if (pfd[0].revents & POLLIN)
	{
		/* list of TUN devices changed, read notification data, rebuild FDs */
		while (read(this->notify[0], &buf, sizeof(buf)) == sizeof(buf))
		{
			/* nop */
		}
		return JOB_REQUEUE_DIRECT;
	}

	if (pfd[1].revents & POLLIN)
	{
		process_plain(this->tun.tun);
	}

	this->lock->read_lock(this->lock);
	enumerator = this->tuns->create_enumerator(this->tuns);
	while (enumerator->enumerate(enumerator, NULL, &entry))
	{
		if (find_revents(pfd, count, entry->fd) & POLLIN)
		{
			process_plain(entry->tun);
		}
	}
	enumerator->destroy(enumerator);
#endif
	this->lock->unlock(this->lock);
	return JOB_REQUEUE_DIRECT;
}

METHOD(kernel_listener_t, tun, bool,
	private_kernel_libipsec_router_t *this, tun_device_t *tun, bool created)
{
	tun_entry_t *entry, lookup;
#ifndef WIN32
	char buf[] = {0x01};
#endif

	this->lock->write_lock(this->lock);
	if (created)
	{
		INIT(entry,
			.addr = tun->get_address(tun, NULL),
#ifdef WIN32
			.handle = tun->get_handle(tun),
#else /* !WIN32 */
			.fd = tun->get_fd(tun),
#endif
			.tun = tun,
		);
		this->tuns->put(this->tuns, entry, entry);
	}
	else
	{
		lookup.addr = tun->get_address(tun, NULL);
		entry = this->tuns->remove(this->tuns, &lookup);
		free(entry);
	}
	/* notify handler thread to recreate FD set */
#ifdef WIN32
	SetEvent(this->event);
	this->notify = TRUE;
#else /* !WIN32 */
	ignore_result(write(this->notify[1], buf, sizeof(buf)));
#endif
	this->lock->unlock(this->lock);
	return TRUE;
}

METHOD(kernel_libipsec_router_t, get_tun_name, char*,
	private_kernel_libipsec_router_t *this, host_t *vip)
{
	tun_entry_t *entry, lookup = {
		.addr = vip,
	};
	tun_device_t *tun;
	char *name;

	if (!vip)
	{
		return strdup(this->tun.tun->get_name(this->tun.tun));
	}
	this->lock->read_lock(this->lock);
	entry = this->tuns->get(this->tuns, &lookup);
	tun = entry ? entry->tun : this->tun.tun;
	name = strdup(tun->get_name(tun));
	this->lock->unlock(this->lock);
	return name;
}

METHOD(kernel_libipsec_router_t, destroy, void,
	private_kernel_libipsec_router_t *this)
{
	charon->receiver->del_esp_cb(charon->receiver,
								(receiver_esp_cb_t)receiver_esp_cb);
	ipsec->processor->unregister_outbound(ipsec->processor,
										 (ipsec_outbound_cb_t)send_esp);
	ipsec->processor->unregister_inbound(ipsec->processor,
										 (ipsec_inbound_cb_t)deliver_plain);
	ipsec->processor->unregister_acquire(ipsec->processor,
										 (ipsec_acquire_cb_t)raise_acquire);
	charon->kernel->remove_listener(charon->kernel, &this->public.listener);
#ifdef WIN32
	SetEvent(this->event);
	this->tun.tun->destroy(this->tun.tun);
	CloseHandle(this->tun.handle);
	CloseHandle(this->event);
#else /* !WIN32 */
	close(this->notify[0]);
	close(this->notify[1]);
#endif
	this->lock->destroy(this->lock);
	this->tuns->destroy(this->tuns);
	router = NULL;
	free(this);
}

#ifndef WIN32
/**
 * Set O_NONBLOCK on the given socket.
 */
static bool set_nonblock(int socket)
{
	int flags = fcntl(socket, F_GETFL);
	return flags != -1 && fcntl(socket, F_SETFL, flags | O_NONBLOCK) != -1;
}
#endif

#ifdef WIN32
static void reload(private_kernel_libipsec_router_t *this)
{
	this->use_events = lib->settings->get_bool(
					lib->settings, "%s.use_events", FALSE, lib->ns);
	this->spinloop_threshold = lib->settings->get_int(
					lib->settings, "%s.spinloop_threshold", 4000000, lib->ns);
	DBG1(DBG_LIB, "Read new use_events setting %d and spinloop_threshold %lld",
	this->use_events, this->spinloop_threshold);
}
#endif

/*
 * See header file
 */
kernel_libipsec_router_t *kernel_libipsec_router_create()
{
	private_kernel_libipsec_router_t *this;

	INIT(this,
		.public = {
			.listener = {
				.tun = _tun,
			},
			.get_tun_name = _get_tun_name,
			.destroy = _destroy,
		},
		.tun = {
			.tun = lib->get(lib, "kernel-libipsec-tun"),
		}
	);

#ifdef WIN32
	reload(this);
	this->tun.handle = this->tun.tun->get_handle(this->tun.tun);
	if (!(this->event = CreateEvent(NULL, FALSE, FALSE, FALSE)))
#else /* !WIN32 */
	if (pipe(this->notify) != 0 ||
		!set_nonblock(this->notify[0]) || !set_nonblock(this->notify[1]))
#endif
	{
		DBG1(DBG_KNL, "creating notify for kernel-libipsec router failed");
		free(this);
		return NULL;
	}
#ifndef WIN32
	this->tun.fd = this->tun.tun->get_fd(this->tun.tun);
#endif
	this->tuns = hashtable_create((hashtable_hash_t)tun_entry_hash,
								  (hashtable_equals_t)tun_entry_equals, 4);
	this->lock = rwlock_create(RWLOCK_TYPE_DEFAULT);

	charon->kernel->add_listener(charon->kernel, &this->public.listener);
	ipsec->processor->register_outbound(ipsec->processor, send_esp, NULL);
	ipsec->processor->register_inbound(ipsec->processor,
									(ipsec_inbound_cb_t)deliver_plain, this);
	ipsec->processor->register_acquire(ipsec->processor, raise_acquire, NULL);
	charon->receiver->add_esp_cb(charon->receiver,
									(receiver_esp_cb_t)receiver_esp_cb, NULL);
	lib->processor->queue_job(lib->processor,
			(job_t*)callback_job_create((callback_job_cb_t)handle_plain, this,
									NULL, (callback_job_cancel_t)return_false));

	router = &this->public;
	return &this->public;
}
