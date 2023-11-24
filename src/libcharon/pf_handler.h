/*
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

#ifndef PF_HANDLER_H_
#define PF_HANDLER_H_

#include <sys/types.h>
#include <utils/chunk.h>

typedef struct pf_handler_t pf_handler_t;

/**
 * bpf implementation for freebsd / macos
 */
struct pf_handler_t {
	/**
	 * Destroy a pf_handlers_t.
	 */
	void (*destroy)(pf_handler_t *this);
};

typedef void (*pf_packet_handler_t)(void *this, char* if_name, int if_index,
        chunk_t *mac, int fd, void *packet, size_t packet_length);

#if !defined(__APPLE__) && !defined(__FreeBSD__)
typedef struct sock_fprog pf_program_t;
#else
typedef struct bpf_program pf_program_t;
#endif /* !defined(__APPLE__) && !defined(__FreeBSD__) */

/**
 * Create a pf_handler_t instance.
 */
pf_handler_t *pf_handler_create(void *packet_this, const char *name, char *iface,
                                pf_packet_handler_t packet_handler,
                                pf_program_t *program);

/**
 * Bind a socket to a particular interface name
 */
bool bind_to_device(int fd, char *iface);

#endif /** PF_HANDLER_H_ */
