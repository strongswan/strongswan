#ifndef KERNEL_VPP_SHARED_H_
#define KERNEL_VPP_SHARED_H_

#include <assert.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/api/vpe_msg_enum.h>

#define vl_typedefs
#include <vpp/api/vpe_all_api_h.h>
#undef vl_typedefs

typedef struct vac_t vac_t;

#define IPV4_LEN 4
#define IPV6_LEN 16

/**
 * Callback function invoked for received event messages.
 *
 * @param data     associated event message, destroyed by VPP API wrapper
 * @param data_len length of the event message
 * @param ctx      user data, as passed to register_event
 */
typedef void (*event_cb_t)(char *data, int data_len, void *ctx);

/**
 * Wrapper around VPP binary API client.
 */
struct vac_t {

	/**
	 * Destroy the VPP API client.
	 */
	void (*destroy)(vac_t *this);

	/* XXX chopps: FIX THIS.
	 * these functions end up taking a shmem allocated message which knows its
	 * size, they then create another shmem message and copy the data into that
	 * and then send that message. The use of "in_len" has caused multiple debug
	 * sessions with not passing in variable length additions, this could be
	 * avoided by simply reading the length from the message directly, and also
	 * not bother copying the message again.
	 *
	 * The only problem is what if we have a timeout, we return to the caller,
	 * and then we free the message, does this work with vpp or do things crash?
	 */

	/**
	 * Send VPP API message and wait for a reply
	 *
	 * @param in      VPP API message to send
	 * @param in_len  length of the message to send
	 * @param out     received VPP API message
	 * @param out_len length of the received message
	 */
	status_t (*send)(vac_t *this, char *in, int in_len, char **out,
					 int *out_len);

	/**
	 * Send VPP API dump message and wait for a reply.
	 *
	 * @param in      VPP API message to send
	 * @param in_len  length of the message to send
	 * @param out     received VPP API message
	 * @param out_len length of the received message
	 */
	status_t (*send_dump)(vac_t *this, char *in, int in_len, char **out,
						  int *out_len);

	/**
	 * Register for VPP API event of a given kind.
	 *
	 * @param in       VPP API event message to register
	 * @param in_len   length of the event message to register
	 * @param cb       callback function to register
	 * @param event_id event ID
	 * @param ctx      user data passed to callback invocations
	 */
	status_t (*register_event)(vac_t *this, char *in, int in_len, event_cb_t cb,
							   uint16_t event_id, void *ctx);
};

extern vac_t *vac;

/**
 * Establishing a binary API connection to VPP.
 *
 * @param name client name
 * @return     vac_t instance
 */
vac_t *vac_create(char *name);

/**
 * Convert a Strongswan chunk to VPP address union
 *
 * @param chunk Strongswan chunk_t.
 * @param addr  VPP API address union to fill in.
 */
static inline void
chunk_to_addrun(chunk_t chunk, vl_api_address_union_t *addrun)
{
	assert(chunk.len == IPV4_LEN || chunk.len == IPV6_LEN);
	memcpy(addrun, chunk.ptr, chunk.len);
}

/**
 * Convert a Strongswan chunk to VPP address
 *
 * @param chunk Strongswan chunk_t.
 * @param addr  VPP API address to fill in.
 */
static inline void
chunk_to_api(chunk_t chunk, vl_api_address_t *addr)
{
	addr->af = chunk.len == IPV4_LEN ? ADDRESS_IP4 : ADDRESS_IP6;
	chunk_to_addrun(chunk, &addr->un);
}

/**
 * Get chunks details of a VPP address union.
 *
 * @param addr  VPP API address get chunk details from.
 * @returns     Strongswan chunk_t.
 */
static inline chunk_t
addrun_to_chunk(vl_api_address_union_t *addrun, int len)
{
	assert(len == IPV4_LEN || len == IPV6_LEN);
	chunk_t chunk = {addrun->ip4, len};
	return chunk;
}

/**
 * Convert a VPP address union to a Strongswan host.
 *
 * @param addr  VPP API address union convert.
 * @returns     Strongswan host_t (must be freed).
 */
static inline host_t *
addrun_to_host(vl_api_address_union_t *addrun, int len)
{
	int family = (len == IPV4_LEN) ? AF_INET : AF_INET6;
	chunk_t chunk = addrun_to_chunk(addrun, len);
	return host_create_from_chunk(family, chunk, 0);
}

/**
 * Convert a VPP address union to a Strongswan host.
 *
 * @param addr  VPP API address convert.
 * @returns     Strongswan host_t (must be freed).
 */
static inline host_t *
addr_to_host(vl_api_address_t *addr)
{
	vl_api_address_family_t af = addr->af;
	assert(af == ADDRESS_IP4 || af == ADDRESS_IP6);
	return host_create_from_chunk(
		af == ADDRESS_IP6 ? AF_INET6 : AF_INET,
		addrun_to_chunk(&addr->un, af == ADDRESS_IP6 ? IPV6_LEN : IPV4_LEN), 0);
}

#define KDBG1(...) DBG1(DBG_KNL, "KERNEL-VPP: " __VA_ARGS__)
#define KDBG2(...) DBG2(DBG_KNL, "KERNEL-VPP: " __VA_ARGS__)
#define KDBG3(...) DBG3(DBG_KNL, "KERNEL-VPP: " __VA_ARGS__)
#define KDBG4(...) DBG4(DBG_KNL, "KERNEL-VPP: " __VA_ARGS__)
#define LDBG1(...) DBG1(DBG_LIB, "KERNEL-VPP: " __VA_ARGS__)
#define LDBG2(...) DBG2(DBG_LIB, "KERNEL-VPP: " __VA_ARGS__)
#define LDBG3(...) DBG3(DBG_LIB, "KERNEL-VPP: " __VA_ARGS__)
#define LDBG4(...) DBG4(DBG_LIB, "KERNEL-VPP: " __VA_ARGS__)
#define NDBG1(...) DBG1(DBG_NET, "KERNEL-VPP: " __VA_ARGS__)
#define NDBG2(...) DBG2(DBG_NET, "KERNEL-VPP: " __VA_ARGS__)
#define NDBG3(...) DBG3(DBG_NET, "KERNEL-VPP: " __VA_ARGS__)
#define NDBG4(...) DBG4(DBG_NET, "KERNEL-VPP: " __VA_ARGS__)

extern const char *vpp_api_msg_names[];
extern int vpp_api_nmsg_names;

#ifdef HAVE_VPP_API_ENDIAN_FUNCS
#define vl_endianfun
#include <vpp/api/vpe_all_api_h.h>
#undef vl_endianfun
#else
/*
 * These functions were adapted from vpp 20.01 generated version to be used for
 * 19.08.
 */

/*
 * interface_types.api.h
 */
static inline void vl_api_interface_index_t_endian (vl_api_interface_index_t *a)
{
    *a = clib_net_to_host_u32(*a);
}

/*
 * ip_types.api.h
 */

static inline void vl_api_address_family_t_endian (vl_api_address_family_t *a)
{
    *a = clib_net_to_host_u32(*a);
}

static inline void vl_api_ip_proto_t_endian (vl_api_ip_proto_t *a)
{
    *a = clib_net_to_host_u32(*a);
}

static inline void vl_api_address_t_endian (vl_api_address_t *a)
{
    vl_api_address_family_t_endian(&a->af);
}

static inline void vl_api_prefix_t_endian (vl_api_prefix_t *a)
{
    vl_api_address_t_endian(&a->address);
    /* a->len = a->len (no-op) */
}

static inline void vl_api_mprefix_t_endian (vl_api_mprefix_t *a)
{
    vl_api_address_family_t_endian(&a->af);
    a->grp_address_length = clib_net_to_host_u16(a->grp_address_length);
}

/*
 * fib_types.api.h
 */

static inline void vl_api_fib_path_t_endian (vl_api_fib_path_t *a)
{
	int i;
    a->sw_if_index = clib_net_to_host_u32(a->sw_if_index);
    a->table_id = clib_net_to_host_u32(a->table_id);
    a->rpf_id = clib_net_to_host_u32(a->rpf_id);
    a->type = clib_net_to_host_u32(a->type);
    a->flags = clib_net_to_host_u32(a->flags);
    a->proto = clib_net_to_host_u32(a->proto);
    a->nh.via_label = clib_net_to_host_u32(a->nh.via_label);
    a->nh.obj_id = clib_net_to_host_u32(a->nh.obj_id);
    a->nh.classify_table_index = clib_net_to_host_u32(a->nh.classify_table_index);
    for (i = 0; i < a->n_labels; i++) {
        a->label_stack[i].label = clib_net_to_host_u32(a->label_stack[i].label);
    }
}

/*
 *  ip.api.h
 */
static inline void vl_api_ip_table_t_endian (vl_api_ip_table_t *a)
{
    a->table_id = clib_net_to_host_u32(a->table_id);
    /* a->is_ip6 = a->is_ip6 (no-op) */
    /* a->name = a->name (no-op) */
}

//                 vl_api_ip_address_dump_t_endian(mp);
static inline void vl_api_ip_address_dump_t_endian(vl_api_ip_address_dump_t *a)
{
	a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
	a->client_index = clib_net_to_host_u32(a->client_index);
	a->context = clib_net_to_host_u32(a->context);
	vl_api_interface_index_t_endian(&a->sw_if_index);
	/* a->is_ipv6 = a->is_ipv6 (no-op) */
}

//                 vl_api_ip_route_add_del_reply_t_endian(rmp);
static inline void vl_api_ip_route_add_del_reply_t_endian(vl_api_ip_route_add_del_reply_t *a)
{
	a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
	a->context = clib_net_to_host_u32(a->context);
	a->retval = clib_net_to_host_i32(a->retval);
	a->stats_index = clib_net_to_host_u32(a->stats_index);
}

//                 vl_api_ip_route_t_endian(route);
static inline void vl_api_ip_route_t_endian(vl_api_ip_route_t *a)
{
	int i;
	a->table_id = clib_net_to_host_u32(a->table_id);
	a->stats_index = clib_net_to_host_u32(a->stats_index);
	vl_api_prefix_t_endian(&a->prefix);
	/* a->n_paths = a->n_paths (no-op) */
	for (i = 0; i < a->n_paths; i++)
	{
		vl_api_fib_path_t_endian(&a->paths[i]);
	}
}

//                 vl_api_ip_route_add_del_t_endian(mp);
static inline void vl_api_ip_route_add_del_t_endian (vl_api_ip_route_add_del_t *a)
{
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->client_index = clib_net_to_host_u32(a->client_index);
    a->context = clib_net_to_host_u32(a->context);
    /* a->is_add = a->is_add (no-op) */
    /* a->is_multipath = a->is_multipath (no-op) */
    vl_api_ip_route_t_endian(&a->route);
}

//                 vl_api_ip_route_dump_t_endian(mp);
static inline void vl_api_ip_route_dump_t_endian(vl_api_ip_route_dump_t *a)
{
	a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
	a->client_index = clib_net_to_host_u32(a->client_index);
	a->context = clib_net_to_host_u32(a->context);
	vl_api_ip_table_t_endian(&a->table);
}

// vl_api_ip_route_lookup_reply_t_endian(rmp);
// vl_api_ip_route_lookup_t_endian(mp);


/*
 * ipsec.api.h
 */

static inline void vl_api_ipsec_spd_action_t_endian (vl_api_ipsec_spd_action_t *a)
{
    *a = clib_net_to_host_u32(*a);
}

static inline void vl_api_ipsec_spd_entry_t_endian (vl_api_ipsec_spd_entry_t *a)
{
    a->spd_id = clib_net_to_host_u32(a->spd_id);
    a->priority = clib_net_to_host_i32(a->priority);
    /* a->is_outbound = a->is_outbound (no-op) */
    a->sa_id = clib_net_to_host_u32(a->sa_id);
    vl_api_ipsec_spd_action_t_endian(&a->policy);
    /* a->protocol = a->protocol (no-op) */
    vl_api_address_t_endian(&a->remote_address_start);
    vl_api_address_t_endian(&a->remote_address_stop);
    vl_api_address_t_endian(&a->local_address_start);
    vl_api_address_t_endian(&a->local_address_stop);
    a->remote_port_start = clib_net_to_host_u16(a->remote_port_start);
    a->remote_port_stop = clib_net_to_host_u16(a->remote_port_stop);
    a->local_port_start = clib_net_to_host_u16(a->local_port_start);
    a->local_port_stop = clib_net_to_host_u16(a->local_port_stop);
}

static inline void vl_api_ipsec_sad_entry_t_endian(vl_api_ipsec_sad_entry_t *a)
{
	a->sad_id = clib_net_to_host_u32(a->sad_id);
	a->spi = clib_net_to_host_u32(a->spi);
	a->protocol = clib_net_to_host_u32(a->protocol);
	a->crypto_algorithm = clib_net_to_host_u32(a->crypto_algorithm);
	a->integrity_algorithm = clib_net_to_host_u32(a->integrity_algorithm);
	a->flags = clib_net_to_host_u32(a->flags);
	vl_api_address_t_endian(&a->tunnel_src);
	vl_api_address_t_endian(&a->tunnel_dst);
	a->tx_table_id = clib_net_to_host_u32(a->tx_table_id);
	a->salt = clib_net_to_host_u32(a->salt);
}

//                 vl_api_ipsec_interface_add_del_spd_t_endian(mp);
static inline void vl_api_ipsec_interface_add_del_spd_t_endian(
	vl_api_ipsec_interface_add_del_spd_t *a)
{
	a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
	a->client_index = clib_net_to_host_u32(a->client_index);
	a->context = clib_net_to_host_u32(a->context);
	/* a->is_add = a->is_add (no-op) */
	a->sw_if_index = clib_net_to_host_u32(a->sw_if_index);
	a->spd_id = clib_net_to_host_u32(a->spd_id);
}

//                 vl_api_ipsec_interface_add_del_spd_reply_t_endian(rmp);
static inline void vl_api_ipsec_interface_add_del_spd_reply_t_endian(
	vl_api_ipsec_interface_add_del_spd_reply_t *a)
{
	a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
	a->context = clib_net_to_host_u32(a->context);
	a->retval = clib_net_to_host_i32(a->retval);
}

//                 vl_api_ipsec_sa_details_t_endian(rmp);
static inline void vl_api_ipsec_sa_details_t_endian(vl_api_ipsec_sa_details_t *a)
{
	a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
	a->context = clib_net_to_host_u32(a->context);
	vl_api_ipsec_sad_entry_t_endian(&a->entry);
	a->sw_if_index = clib_net_to_host_u32(a->sw_if_index);
	a->salt = clib_net_to_host_u32(a->salt);
	a->seq_outbound = clib_net_to_host_u64(a->seq_outbound);
	a->last_seq_inbound = clib_net_to_host_u64(a->last_seq_inbound);
	a->replay_window = clib_net_to_host_u64(a->replay_window);
	a->total_data_size = clib_net_to_host_u64(a->total_data_size);
}

//                 vl_api_ipsec_sa_dump_t_endian(mp);
static inline void vl_api_ipsec_sa_dump_t_endian(vl_api_ipsec_sa_dump_t *a)
{
	a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
	a->client_index = clib_net_to_host_u32(a->client_index);
	a->context = clib_net_to_host_u32(a->context);
	a->sa_id = clib_net_to_host_u32(a->sa_id);
}

//                 vl_api_ipsec_sad_entry_add_del_reply_t_endian(rmp);
static inline void vl_api_ipsec_sad_entry_add_del_reply_t_endian(
	vl_api_ipsec_sad_entry_add_del_reply_t *a)
{
	a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
	a->context = clib_net_to_host_u32(a->context);
	a->retval = clib_net_to_host_i32(a->retval);
	a->stat_index = clib_net_to_host_u32(a->stat_index);
}

//                 vl_api_ipsec_sad_entry_add_del_t_endian(mp);
static inline void vl_api_ipsec_sad_entry_add_del_t_endian(vl_api_ipsec_sad_entry_add_del_t *a)
{
	a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
	a->client_index = clib_net_to_host_u32(a->client_index);
	a->context = clib_net_to_host_u32(a->context);
	/* a->is_add = a->is_add (no-op) */
	vl_api_ipsec_sad_entry_t_endian(&a->entry);
}

//                 vl_api_ipsec_spd_add_del_reply_t_endian(rmp);
static inline void vl_api_ipsec_spd_add_del_reply_t_endian(vl_api_ipsec_spd_add_del_reply_t *a)
{
	a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
	a->context = clib_net_to_host_u32(a->context);
	a->retval = clib_net_to_host_i32(a->retval);
}

//                 vl_api_ipsec_spd_add_del_t_endian(mp);
static inline void vl_api_ipsec_spd_add_del_t_endian(vl_api_ipsec_spd_add_del_t *a)
{
	a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
	a->client_index = clib_net_to_host_u32(a->client_index);
	a->context = clib_net_to_host_u32(a->context);
	a->spd_id = clib_net_to_host_u32(a->spd_id);
}

//                 vl_api_ipsec_spd_entry_add_del_reply_t_endian(rmp);
static inline void vl_api_ipsec_spd_entry_add_del_reply_t_endian(
	vl_api_ipsec_spd_entry_add_del_reply_t *a)
{
	a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
	a->context = clib_net_to_host_u32(a->context);
	a->retval = clib_net_to_host_i32(a->retval);
	a->stat_index = clib_net_to_host_u32(a->stat_index);
}

//                 vl_api_ipsec_spd_entry_add_del_t_endian(mp);
static inline void vl_api_ipsec_spd_entry_add_del_t_endian(vl_api_ipsec_spd_entry_add_del_t *a)
{
	a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
	a->client_index = clib_net_to_host_u32(a->client_index);
	a->context = clib_net_to_host_u32(a->context);
	vl_api_ipsec_spd_entry_t_endian(&a->entry);
}

/*
 * punt.api.h
 */

//                 vl_api_punt_type_t_endian(&mp->punt.type);
static inline void vl_api_punt_type_t_endian(vl_api_punt_type_t *a)
{
	*a = clib_net_to_host_u32(*a);
}

/*
 * interface.api.h
 */

//                 vl_api_sw_interface_details_t_endian(rmp);
static inline void vl_api_sw_interface_details_t_endian(vl_api_sw_interface_details_t *a)
{
	int i;
	a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
	a->context = clib_net_to_host_u32(a->context);
	vl_api_interface_index_t_endian(&a->sw_if_index);
	a->sup_sw_if_index = clib_net_to_host_u32(a->sup_sw_if_index);
	a->l2_address_length = clib_net_to_host_u32(a->l2_address_length);
	a->link_speed = clib_net_to_host_u32(a->link_speed);
	a->link_mtu = clib_net_to_host_u16(a->link_mtu);
	for (i = 0; i < 4; i++)
	{
		a->mtu[i] = clib_net_to_host_u32(a->mtu[i]);
	}
	a->sub_id = clib_net_to_host_u32(a->sub_id);
	a->sub_outer_vlan_id = clib_net_to_host_u16(a->sub_outer_vlan_id);
	a->sub_inner_vlan_id = clib_net_to_host_u16(a->sub_inner_vlan_id);
	a->vtr_op = clib_net_to_host_u32(a->vtr_op);
	a->vtr_push_dot1q = clib_net_to_host_u32(a->vtr_push_dot1q);
	a->vtr_tag1 = clib_net_to_host_u32(a->vtr_tag1);
	a->vtr_tag2 = clib_net_to_host_u32(a->vtr_tag2);
	a->outer_tag = clib_net_to_host_u16(a->outer_tag);
	a->b_vlanid = clib_net_to_host_u16(a->b_vlanid);
	a->i_sid = clib_net_to_host_u32(a->i_sid);
}

//                 vl_api_sw_interface_dump_t_endian(mp);
static inline void vl_api_sw_interface_dump_t_endian(vl_api_sw_interface_dump_t *a)
{
	a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
	a->client_index = clib_net_to_host_u32(a->client_index);
	a->context = clib_net_to_host_u32(a->context);
	vl_api_interface_index_t_endian(&a->sw_if_index);
	// 19.08 is using vl_api_to/from_api_string which already does the conversion
	// a->name_filter.length = clib_net_to_host_u32(a->name_filter.length);
}

//                 vl_api_sw_interface_event_t_endian(event);
static inline void vl_api_sw_interface_event_t_endian(vl_api_sw_interface_event_t *a)
{
	a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
	a->client_index = clib_net_to_host_u32(a->client_index);
	a->pid = clib_net_to_host_u32(a->pid);
	vl_api_interface_index_t_endian(&a->sw_if_index);
}

//                 vl_api_want_interface_events_t_endian(emp);
static inline void vl_api_want_interface_events_t_endian(vl_api_want_interface_events_t *a)
{
	a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
	a->client_index = clib_net_to_host_u32(a->client_index);
	a->context = clib_net_to_host_u32(a->context);
	a->enable_disable = clib_net_to_host_u32(a->enable_disable);
	a->pid = clib_net_to_host_u32(a->pid);
}

#endif

/*
 * The generated version of this function is wrong in versions through 20.01
 * for the prefix conversion, it's also wrong in 20.05 but the address family
 * has become 8 bit in 20.05 so the missing conversion is a no-op.
 */
static inline void fixed_vl_api_ip_address_details_t_endian (vl_api_ip_address_details_t *a)
{
    a->_vl_msg_id = clib_net_to_host_u16(a->_vl_msg_id);
    a->context = clib_net_to_host_u32(a->context);
    vl_api_interface_index_t_endian(&a->sw_if_index);
	/* In the generated version of this function its a no-op which is wrong */
	vl_api_prefix_t_endian(&a->prefix);
}


#endif /* KERNEL_VPP_SHARED_H_ */

/*
 * fd.io coding-style-patch-verification: CXLANG
 *
 * Local Variables:
 * c-file-style: "bsd"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: t
 * End:
 */
