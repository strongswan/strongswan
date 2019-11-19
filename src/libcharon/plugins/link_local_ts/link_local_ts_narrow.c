/*
 * Copyright (C) 2019 Tobias Brunner
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

#include "link_local_ts_narrow.h"

#include <daemon.h>
#include <credentials/certificates/x509.h>

typedef struct private_link_local_ts_narrow_t private_link_local_ts_narrow_t;

/**
 * Private data.
 */
struct private_link_local_ts_narrow_t {

	/**
	 * Public interface.
	 */
	link_local_ts_narrow_t public;
};

static traffic_selector_t *create_link_local_ts(host_t *vip)
{
	chunk_t link_local = chunk_from_chars(
								0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
								0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);

	/* copy the last 64 address bits of the virtual IP */
	memcpy(link_local.ptr + 8, vip->get_address(vip).ptr + 8, 8);

	return traffic_selector_create_from_bytes(0, TS_IPV6_ADDR_RANGE, link_local,
											  0, link_local, 0xffff);
}

METHOD(listener_t, narrow, bool,
	private_link_local_ts_narrow_t *this, ike_sa_t *ike_sa,
	child_sa_t *child_sa, narrow_hook_t type, linked_list_t *local,
	linked_list_t *remote)
{
	enumerator_t *enumerator;
	host_t *vip;

	/* only Windows clients currently rely on ND to receive routes (i.e.
	 * they actually ignore the remote TS assigned by the server, even if it
	 * is ::/0) */
	if (type == NARROW_RESPONDER &&
		ike_sa->supports_extension(ike_sa, EXT_MS_WINDOWS))
	{
		enumerator = ike_sa->create_virtual_ip_enumerator(ike_sa, FALSE);
		while (enumerator->enumerate(enumerator, &vip))
		{
			if (vip->get_family(vip) == AF_INET6)
			{
				remote->insert_last(remote, create_link_local_ts(vip));
				break;
			}
		}
		enumerator->destroy(enumerator);
	}
	return TRUE;
}

METHOD(link_local_ts_narrow_t, destroy, void,
	private_link_local_ts_narrow_t *this)
{
	free(this);
}

/*
 * Described in header
 */
link_local_ts_narrow_t *link_local_ts_narrow_create()
{
	private_link_local_ts_narrow_t *this;

	INIT(this,
		.public = {
			.listener.narrow = _narrow,
			.destroy = _destroy,
		},
	);

	return &this->public;
}
