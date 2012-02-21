/*
 * Copyright (C) 2012 Tobias Brunner
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

#include <stdio.h>

#include <library.h>
#include <utils/host.h>
#include <utils/enumerator.h>
#include <utils/linked_list.h>

#define swap(a, b) ({ typeof(a) _tmp = a; a = b; b = _tmp; })

typedef struct {
	host_t *net;
	int netmask;
} subnet_t;

static linked_list_t *nets;

static void subnet_destroy(subnet_t *this)
{
	this->net->destroy(this->net);
	free(this);
}

/**
 * Insert a subnet into the list of subnets sorted by increasing address.
 * The address is not masked, i.e. host bits are expected to be 0.
 */
static void add_subnet(int family, chunk_t addr, int netmask)
{
	enumerator_t *enumerator;
	subnet_t *subnet, *current;

	INIT(subnet,
		.net = host_create_from_chunk(family, addr, 0),
		.netmask = netmask,
	);

	enumerator = nets->create_enumerator(nets);
	while (enumerator->enumerate(enumerator, &current))
	{
		int cmp = chunk_compare(current->net->get_address(current->net), addr);
		if (cmp > 0 ||
		   (cmp == 0 && current->netmask > subnet->netmask))
		{
			break;
		}
	}
	nets->insert_before(nets, enumerator, subnet);
	enumerator->destroy(enumerator);
}

static void split_range(int family, chunk_t from, chunk_t to)
{
	static const u_char bitmask[] = { 0x80, 0x40, 0x20, 0x10,
									  0x08, 0x04, 0x02, 0x01 };
	int byte = 0, bit = 0, prefix, netmask, common_byte, common_bit,
		from_cur, from_prev, to_cur, to_prev;
	bool from_full = TRUE, to_full = TRUE;

	/* find a common prefix */
	while ((from.ptr[byte] & bitmask[bit]) == (to.ptr[byte] & bitmask[bit]) &&
			byte < from.len)
	{
		if (++bit == 8)
		{
			bit = 0;
			byte++;
		}
	}
	prefix = byte * 8 + bit;

	/* at this point we know that the current bit is 0 for the from and 1 for
	 * the to address. we skip this bit and analyze the remaining bits from the
	 * back, looking at them as two binary trees (0=left, 1=right).  in that
	 * process the host bits get zeroed out.  if the range is a single address
	 * we don't enter the loops below. */
	if (++bit == 8)
	{
		bit = 0;
		byte++;
	}
	common_byte = byte;
	common_bit = bit;
	netmask = from.len * 8;
	from_prev = 0, to_prev = 1;
	for (byte = from.len - 1; byte >= common_byte; byte--)
	{
		int bit_min = (byte == common_byte) ? common_bit : 0;
		for (bit = 7; bit >= bit_min; bit--)
		{
			u_char mask = bitmask[bit];

			from_cur = from.ptr[byte] & mask;
			if (!from_prev && from_cur)
			{	/* 0 -> 1: subnet includes the whole current (right) subtree */
				add_subnet(family, from, netmask);
				from_full = FALSE;
			}
			else if (from_prev && !from_cur)
			{	/* 1 -> 0: invert bit and add subnet (right subtree) */
				from.ptr[byte] ^= mask;
				add_subnet(family, from, netmask);
				from_cur = 1;
			}
			from.ptr[byte] &= ~mask;
			from_prev = from_cur;

			to_cur = to.ptr[byte] & mask;
			if (to_prev && !to_cur)
			{	/* 1 -> 0: subnet includes the whole current (left) subtree */
				add_subnet(family, to, netmask);
				to_full = FALSE;
			}
			else if (!to_prev && to_cur)
			{	/* 0 -> 1: invert bit and add subnet (left subtree) */
				to.ptr[byte] ^= mask;
				add_subnet(family, to, netmask);
				to_cur = 0;
			}
			to.ptr[byte] &= ~mask;
			to_prev = to_cur;
			netmask--;
		}
	}

	if (from_full && to_full)
	{	/* full subnet (i.e. from=to or from=0 and to=1 after common prefix) */
		add_subnet(family, from, prefix);
	}
	else if (from_full)
	{	/* full left subnet */
		add_subnet(family, from, prefix + 1);
	}
	else if (to_full)
	{	/* full right subnet */
		add_subnet(family, to, prefix + 1);
	}
}

/**
 * Split an IP address range into multiple distinct subnets.
 */
int main(int argc, char *argv[])
{
	enumerator_t *enumerator;
	host_t *from = NULL, *to = NULL;
	chunk_t from_addr, to_addr;
	subnet_t *subnet;
	char *token;
	int family;

	library_init(NULL);
	atexit(library_deinit);

	if (argc != 2)
	{
		printf("Usage: %s <from>-<to>\n", argv[0]);
		return -1;
	}

	enumerator = enumerator_create_token(argv[1], "-", " ");
	while (enumerator->enumerate(enumerator, &token))
	{
		host_t **host;
		host = !from ? &from : &to;
		*host = host_create_from_string(token, 0);
		if (*host == NULL)
		{
			printf("Unable to parse IP address: %s\n", token);
			enumerator->destroy(enumerator);
			DESTROY_IF(from);
			return -2;
		}
	}
	enumerator->destroy(enumerator);

	if (!to)
	{
		to = from->clone(from);
	}

	if (from->get_family(from) != to->get_family(to))
	{
		printf("Address family does not match!");
		from->destroy(from);
		to->destroy(to);
		return -3;
	}

	family = from->get_family(from);
	from_addr = from->get_address(from);
	to_addr = to->get_address(to);
	nets = linked_list_create();

	if (chunk_compare(from_addr, to_addr) > 0)
	{
		swap(from_addr, to_addr);
		swap(from, to);
	}

	printf("Splitting range %H-%H...\n", from, to);
	split_range(family, from_addr, to_addr);

	enumerator = nets->create_enumerator(nets);
	while (enumerator->enumerate(enumerator, &subnet))
	{
		printf(" %H/%d\n", subnet->net, subnet->netmask);
	}
	enumerator->destroy(enumerator);

	nets->destroy_function(nets, (void*)subnet_destroy);
	from->destroy(from);
	to->destroy(to);
	return 0;
}

