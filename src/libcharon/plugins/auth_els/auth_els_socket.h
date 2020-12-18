/* Copyright (C) 2019-2020 Marvell */

/**
 * @defgroup auth_els_socket auth_els_socket
 * @{ @ingroup auth_els
 */

#ifndef AUTH_ELS_SOCKET_H_
#define AUTH_ELS_SOCKET_H_

#include <sa/ike_sa.h>
#include <collections/hashtable.h>
#include <network/socket.h>

/**
 * Socket to send/received SA synchronization data
 */
typedef struct auth_els_socket_t auth_els_socket_t;
struct auth_els_socket_t {

	socket_t socket;
};

/**
 * Create a default auth_els_socket instance.
 */
auth_els_socket_t *auth_els_socket_create();

#endif /** AUTH_ELS_SOCKET_ @}*/
