/*
 * Copyright (C) 2021 Tobias Brunner
 * Copyright (C) 2010 Martin Willi
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

/*
 * For the Apple BPF implementation and refactoring packet handling.
 *
 * Copyright (C) 2020 Dan James <sddj@me.com>
 * Copyright (C) 2023 Dan James <sddj@me.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "pf_handler.h"

#include <library.h>
#include <unistd.h>

#if !defined(__APPLE__) && !defined(__FreeBSD__)
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/filter.h>
#include <threading/rwlock.h>
#else
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/bpf.h>
#include <net/if.h>
#include <net/if_dl.h>
#endif /* !defined(__APPLE__) && !defined(__FreeBSD__) */

#include <errno.h>
#include <net/ethernet.h>
#include <sys/ioctl.h>

#if !defined(__APPLE__) && !defined(__FreeBSD__)

struct pf_socket_t {
    /**
     * index of the interface
     */
    int if_index;
    /**
     * name of the interface
     */
    char if_name[IFNAMSIZ];
    /**
     * hardware (mac) address of the interface
     */
     u_char hwaddr[ETHER_ADDR_LEN];
     /**
      * chunk for the hardware (mac) address of the interface
      */
    chunk_t mac;
    /**
     * count of the times this info is used, for lru cache
     */
    int used;
};
typedef struct pf_socket_t pf_socket_t;

struct pf_sockets_t {
    /**
     * count of entries in use
     */
    int count;
    /**
     * fixed sized array of recently used interface information
     */
    pf_socket_t entries[8];
};
typedef struct pf_sockets_t pf_sockets_t;

#endif /* !defined(__APPLE__) && !defined(__FreeBSD__) */

typedef struct private_pf_handler_t private_pf_handler_t;

struct private_pf_handler_t {
    pf_handler_t public;
    const char* name;
    void *packet_this;
    pf_packet_handler_t packet_handler;
#if !defined(__APPLE__) && !defined(__FreeBSD__)
    /**
     * receive socket
     */
    int receive;
    /**
     * cache of recently used socket info
     */
    pf_sockets_t pf_sockets;
    /**
     * RWlock for socket slots
     */
    rwlock_t *lock;
#else
    /**
     * receive socket handlers -- freebsd & macos need to open multiple sockets
     */
    linked_list_t *pf_filter_handlers;
#endif /* !defined(__APPLE__) && !defined(__FreeBSD__) */
};

#if !defined(__APPLE__) && !defined(__FreeBSD__)

/**
 * @param this pf_sockets_t *
 * @return the slot in the array of entries to use for this request
 */
static int find_least_used_socket_entry(pf_sockets_t *this) {
    int i, idx, least_used, max = sizeof(this->entries) / sizeof(pf_socket_t);

    if (this->count + 1 < max) {
        /* not all slots used, choose the next unused slot */
        idx = ++this->count;
    } else {
        least_used = 0;
        idx = 0;

        /* all slots in use, choose the one with the lowest usage */
        for (i = 0; i < max; i++) {
            if (this->entries[i].used < least_used) {
                idx = i;
                least_used = this->entries[i].used;
            }
        }
    }

    return idx;
}

static pf_socket_t *find_socket(private_pf_handler_t *this, int fd,
                                struct sockaddr_ll *addr) {
    int idx;
    struct ifreq req;
    char if_name[IFNAMSIZ];
    pf_socket_t *entries = this->pf_sockets.entries;

    this->lock->read_lock(this->lock);
    for (idx = 0; idx < this->pf_sockets.count; idx++) {
        if (entries[idx].if_index == addr->sll_ifindex) {
            entries[idx].used++;
            this->lock->unlock(this->lock);
            return &entries[idx];
        }
    }
    this->lock->unlock(this->lock);

    req.ifr_ifindex = addr->sll_ifindex;
    if (ioctl(fd, SIOCGIFNAME, &req) == 0) {
        memcpy(if_name, req.ifr_name, IFNAMSIZ);
        if (ioctl(fd, SIOCGIFHWADDR, &req) == 0 &&
            req.ifr_hwaddr.sa_family == ARPHRD_ETHER) {
            this->lock->write_lock(this->lock);
            idx = find_least_used_socket_entry(&this->pf_sockets);
            entries[idx].if_index = addr->sll_ifindex;
            memcpy(entries[idx].if_name, req.ifr_name, IFNAMSIZ);
            memcpy(entries[idx].hwaddr, req.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
            entries[idx].mac = chunk_create(entries[idx].hwaddr, ETHER_ADDR_LEN);
            entries[idx].used = 1;
            this->lock->unlock(this->lock);
            return &entries[idx];
        } else {
            DBG1(DBG_NET, "find_socket(SIOCGIFHWADDR) failed: %s", strerror(errno));
        }
    } else {
        DBG1(DBG_NET, "find_socket(SIOCGIFNAME) failed: %s", strerror(errno));
    }

    return NULL;
}

/**
 * Receive responses
 */
CALLBACK(receive_packet, bool,
         private_pf_handler_t *this, int fd, watcher_event_t event)
{
	struct sockaddr_ll addr;
	socklen_t addr_len = sizeof(addr);
	u_int8_t packet[1500];
	size_t len = recvfrom(fd, &packet, sizeof(packet), MSG_DONTWAIT,
                          (struct sockaddr*)&addr, &addr_len);
    pf_socket_t *entry = find_socket(this, fd, &addr);
    if (entry) {
        this->packet_handler(this->packet_this, entry->if_name, entry->if_index,
                             &entry->mac, fd, &packet, len);
    } else {
        DBG1(DBG_NET, "receive_packet: no socket entry found");
    }

	return TRUE;
}

METHOD(pf_handler_t, destroy, void, private_pf_handler_t *this) {
    if (this->receive > 0)
    {
        lib->watcher->remove(lib->watcher, this->receive);
        close(this->receive);
        this->receive = 0;
        this->lock->destroy(this->lock);
    }
}

static bool setup_filter_handlers(private_pf_handler_t *this, char *iface,
                                  struct sock_fprog *packet_filter)
{
    int protocol = strcmp(this->name, "ARP") ? ETH_P_IP : ETH_P_ARP;
	this->receive = socket(AF_PACKET, SOCK_DGRAM, htons(protocol));
	if (this->receive == -1)
	{
		DBG1(DBG_NET, "opening receive socket failed: %s", strerror(errno));
		return FALSE;
	}
	if (setsockopt(this->receive, SOL_SOCKET, SO_ATTACH_FILTER, packet_filter,
                   sizeof(struct sock_fprog)) < 0)
	{
		DBG1(DBG_NET, "installing socket filter failed: %s", strerror(errno));
		return FALSE;
	}
	if (iface && !bind_to_device(this->receive, iface)) {
        return FALSE;
	}
	lib->watcher->add(lib->watcher, this->receive, WATCHER_READ,
                      (watcher_cb_t)receive_packet, this);
    DBG1(DBG_NET, "listening for %s(protocol=0x%04x) requests on fd=%d",
         this->name, protocol, this->receive);
    this->pf_sockets.count = 0;
    this->lock = rwlock_create(RWLOCK_TYPE_DEFAULT);
    return TRUE;
}

/**
 * Bind a socket to a particular interface name
 */
bool bind_to_device(int fd, char *iface)
{
    int status;
    struct ifreq ifreq = {};

    if (strlen(iface) > sizeof(ifreq.ifr_name))
    {
        DBG1(DBG_CFG, "name for DHCP interface too long: '%s'", iface);
        return FALSE;
    }
    memcpy(ifreq.ifr_name, iface, sizeof(ifreq.ifr_name));
    status = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &ifreq, sizeof(ifreq));
    if (status)
    {
        DBG1(DBG_CFG, "binding DHCP socket to '%s' failed: %s",
             iface, strerror(errno));
        return FALSE;
    }
    return TRUE;
}

#else

/**
 * A handler is required for each interface.
 */
struct pf_socket_t {
    /**
     * Reference to the private packet filter handler.
     */
    private_pf_handler_t *this;

    /**
     * The name of the interface to be handled.
     */
    char *name;

    /**
     * index of the interface
     */
    int if_index;

    /**
     * The Ethernet MAC address of this interface.
     */
    chunk_t mac;

    /**
     * The IPv4 address of this interface.
     */
    host_t *ipv4;

    /**
     * The BPF file descriptor for this interface.
     */
    int fd;

    /**
     * The BPF packet buffer length as read from the BPF fd.
     */
    size_t buflen;

    /**
     * An allocated buffer for receiving packets from BPF.
     */
    uint8_t *bufdat;
};

typedef struct pf_socket_t pf_socket_t;

/**
 * Free resources used by a handler.
 */
static void destroy_filter_handler(pf_socket_t *handler) {
    if (handler->fd >= 0) {
        lib->watcher->remove(lib->watcher, handler->fd);
        close(handler->fd);
    }
    DESTROY_IF(handler->ipv4);
    chunk_free(&handler->mac);
    free(handler->bufdat);
    free(handler->name);
    free(handler);
}

static void destroy_filter_handlers(private_pf_handler_t *this) {
    enumerator_t *enumerator;
    pf_socket_t *handler;

    if (this->pf_filter_handlers != NULL) {
        enumerator = this->pf_filter_handlers->create_enumerator(this->pf_filter_handlers);
        while (enumerator->enumerate(enumerator, &handler)) {
            destroy_filter_handler(handler);
        }
        enumerator->destroy(enumerator);
        this->pf_filter_handlers->destroy(this->pf_filter_handlers);
        this->pf_filter_handlers = NULL;
    }
}

/**
 * Find the handler for the named interface, creating one if needed.
 */
static pf_socket_t *get_handler(private_pf_handler_t *this, char *interface_name) {
    pf_socket_t *handler, *found = NULL;
    enumerator_t *enumerator;

    enumerator =
        this->pf_filter_handlers->create_enumerator(this->pf_filter_handlers);
    while (enumerator->enumerate(enumerator, &handler)) {
        if (streq(handler->name, interface_name)) {
            found = handler;
            break;
        }
    }
    enumerator->destroy(enumerator);

    if (!found) {
        INIT(found,
             .this = this,
             .name = strdup(interface_name),
             .fd = -1,
        );
        this->pf_filter_handlers->insert_last(this->pf_filter_handlers, found);
    }
    return found;
}

/**
 * Find and open an available BPF device.
 */
static int bpf_open() {
    static int no_cloning_bpf = 0;
    /* enough space for: /dev/bpf000\0 */
    char device[12];
    int n = no_cloning_bpf ? 0 : -1;
    int fd;

    do {
        if (n < 0) {
            snprintf(device, sizeof(device), "/dev/bpf");
        } else {
            snprintf(device, sizeof(device), "/dev/bpf%d", n);
        }

        fd = open(device, O_RDWR);

        if (n++ < 0 && fd < 0 && errno == ENOENT) {
            no_cloning_bpf = 1;
            errno = EBUSY;
        }
    } while (fd < 0 && errno == EBUSY && n < 1000);

    return fd;
}

/**
 * Receive and examine the available packets. Hand them off to the registered handler.
 */
CALLBACK(handler_onpkt, bool, pf_socket_t *handler, int fd, watcher_event_t event) {
    struct bpf_hdr *bh;
    void *a;
    uint8_t *p = handler->bufdat;
    ssize_t n;
    size_t pktlen;

    n = read(handler->fd, handler->bufdat, handler->buflen);
    if (n <= 0) {
        DBG1(DBG_NET, "reading %s request from %s failed: %s",
             handler->this->name, handler->name, strerror(errno));
        return FALSE;
    }

    while (p < handler->bufdat + n) {
        bh = (struct bpf_hdr *) p;
        a = (void *) (p + bh->bh_hdrlen + sizeof(struct ether_header));
        pktlen = bh->bh_caplen - sizeof(struct ether_header);
        handler->this->packet_handler(handler->this->packet_this, handler->name,
                                      handler->if_index, &handler->mac, handler->fd,
                                      a, pktlen);
        p += bh->bh_hdrlen + bh->bh_caplen;
    }
    return TRUE;
}

static int should_listen_to_handler(pf_socket_t *handler, char *iface) {
    return handler->mac.ptr && handler->ipv4 &&
        (iface == NULL || strcmp(handler->name, iface) == 0);
}

/**
 * Create an initialize a BPF handler for the interface specified in the farp
 * handler. This entails opening a BPF device, binding it to the interface,
 * setting the packet filter, and allocating a buffer for receiving packets.
 */
static bool setup_handler(pf_socket_t *handler, pf_program_t *program) {
    struct ifreq req;
    uint32_t disable = 1;
    uint32_t enable = 1;
    uint32_t dlt = 0;

    snprintf(req.ifr_name, sizeof(req.ifr_name), "%s", handler->name);

    if ((handler->fd = bpf_open()) < 0) {
        DBG1(DBG_NET, "bpf_open(%s): %s", handler->name, strerror(errno));
        return FALSE;
    }

    if (ioctl(handler->fd, BIOCSETIF, &req) < 0) {
        DBG1(DBG_NET, "BIOCSETIF(%s): %s", handler->name, strerror(errno));
        return FALSE;
    }

    if (ioctl(handler->fd, BIOCSHDRCMPLT, &enable) < 0) {
        DBG1(DBG_NET, "BIOCSHDRCMPLT(%s): %s", handler->name, strerror(errno));
        return FALSE;
    }

    if (ioctl(handler->fd, BIOCSSEESENT, &disable) < 0) {
        DBG1(DBG_NET, "BIOCSSEESENT(%s): %s", handler->name, strerror(errno));
        return FALSE;
    }

    if (ioctl(handler->fd, BIOCIMMEDIATE, &enable) < 0) {
        DBG1(DBG_NET, "BIOCIMMEDIATE(%s): %s", handler->name, strerror(errno));
        return FALSE;
    }

    if (ioctl(handler->fd, BIOCGDLT, &dlt) < 0) {
        DBG1(DBG_NET, "BIOCGDLT(%s): %s", handler->name, strerror(errno));
        return FALSE;
    } else if (dlt != DLT_EN10MB) {
        return FALSE;
    }

    if (ioctl(handler->fd, BIOCSETF, program) < 0) {
        DBG1(DBG_NET, "BIOCSETF(%s): %s", handler->name, strerror(errno));
        return FALSE;
    }

    if (ioctl(handler->fd, BIOCGBLEN, &handler->buflen) < 0) {
        DBG1(DBG_NET, "BIOCGBLEN(%s): %s", handler->name, strerror(errno));
        return FALSE;
    }
    handler->bufdat = malloc(handler->buflen);

    lib->watcher->add(lib->watcher, handler->fd, WATCHER_READ,
                      handler_onpkt, handler);
    return TRUE;
}

static bool setup_filter_handlers(private_pf_handler_t *this, char *iface,
                                  pf_program_t *program) {
    struct ifaddrs *ifas;
    struct ifaddrs *ifa;
    struct sockaddr_dl *dl;
    pf_socket_t * handler;
    enumerator_t *enumerator;
    host_t *ipv4;

    this->pf_filter_handlers = linked_list_create();
    if (this->pf_filter_handlers == NULL) {
        DBG1(DBG_NET, "%s cannot create a linked list", this->name);
        return FALSE;
    }
    if (getifaddrs(&ifas) < 0) {
        DBG1(DBG_NET, "%s cannot find interfaces: %s", this->name, strerror(errno));
        return FALSE;
    }
    for (ifa = ifas; ifa != NULL; ifa = ifa->ifa_next) {
        switch (ifa->ifa_addr->sa_family) {
            case AF_LINK:
                dl = (struct sockaddr_dl *) ifa->ifa_addr;
                if (dl->sdl_alen == ETHER_ADDR_LEN) {
                    handler = get_handler(this, ifa->ifa_name);
                    handler->mac = chunk_clone(chunk_create(LLADDR(dl), dl->sdl_alen));
                    handler->if_index = dl->sdl_index;
                }
                break;
            case AF_INET:
                ipv4 = host_create_from_sockaddr(ifa->ifa_addr);
                if (ipv4 && !ipv4->is_anyaddr(ipv4)) {
                    handler = get_handler(this, ifa->ifa_name);
                    if (!handler->ipv4) {
                        handler->ipv4 = ipv4->clone(ipv4);
                    }
                }
                DESTROY_IF(ipv4);
                break;
            default:
                break;
        }
    }
    freeifaddrs(ifas);

    enumerator = this->pf_filter_handlers->create_enumerator(this->pf_filter_handlers);
    while (enumerator->enumerate(enumerator, &handler)) {
        if (should_listen_to_handler(handler, iface) &&
            setup_handler(handler, program)) {
            DBG1(DBG_NET, "listening for %s requests on %s (%H, %#B)",
                 this->name, handler->name, handler->ipv4, &handler->mac);
        } else {
            this->pf_filter_handlers->remove_at(this->pf_filter_handlers, enumerator);
            destroy_filter_handler(handler);
        }
    }
    enumerator->destroy(enumerator);

    return this->pf_filter_handlers->get_count(this->pf_filter_handlers) > 0;
}

METHOD(pf_handler_t, destroy, void, private_pf_handler_t *this) {
    destroy_filter_handlers(this);
    free(this);
}

/**
 * Bind a socket to a particular interface name
 */
bool bind_to_device(int fd, char *iface)
{
#if defined(__FreeBSD__)
    DBG1(DBG_CFG, "binding DHCP socket to '%s' failed: IP_SENDIF not implemented yet.", iface);
    return FALSE;
#else /* defined(__FreeBSD__) */
    unsigned int idx = if_nametoindex(iface);
    int status = setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &idx, sizeof(idx));
    if (status)
    {
        DBG1(DBG_CFG, "binding DHCP socket to '%s' failed: %s",
             iface, strerror(errno));
        return FALSE;
    }
    return TRUE;
#endif /* defined(__FreeBSD__) */
}

#endif /* !defined(__APPLE__) && !defined(__FreeBSD__) */

pf_handler_t *pf_handler_create(void *packet_this, const char* name, char *iface,
                                pf_packet_handler_t packet_handler,
                                pf_program_t *program) {
    private_pf_handler_t *this;
    INIT(this,
         .public = {
            .destroy = _destroy,
         },
         .name = name,
         .packet_this = packet_this,
         .packet_handler = packet_handler,
    );
    if (!setup_filter_handlers(this, iface, program)) {
        destroy(this);
        return NULL;
    }
    return &this->public;
}
