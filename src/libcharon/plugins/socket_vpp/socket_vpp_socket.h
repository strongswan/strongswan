/**
 * @defgroup socket_vpp_socket socket_win_socket
 * @{ @ingroup socket_vpp
 */

#ifndef SOCKET_VPP_SOCKET_H_
#define SOCKET_VPP_SOCKET_H_

typedef struct socket_vpp_socket_t socket_vpp_socket_t;

#include <network/socket.h>

/**
 * Winsock2 based socket implementation.
 */
struct socket_vpp_socket_t {

    /**
     * Implements the socket_t interface.
     */
    socket_t socket;
};

/**
 * Create a socket_vpp_socket instance.
 */
socket_vpp_socket_t *socket_vpp_socket_create();

#endif /** SOCKET_VPP_SOCKET_H_ @}*/
