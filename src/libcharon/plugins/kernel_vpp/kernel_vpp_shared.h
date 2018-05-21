#ifndef KERNEL_VPP_SHARED_H_
#define KERNEL_VPP_SHARED_H_

typedef struct vac_t vac_t;

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

    /**
     * Send VPP API message and wait for a reply
     *
     * @param in      VPP API message to send
     * @param in_len  length of the message to send
     * @param out     received VPP API message
     * @param out_len length of the received message
     */
    status_t (*send)(vac_t *this, char *in, int in_len, char **out, int *out_len);

    /**
     * Send VPP API dump message and wait for a reply.
     *
     * @param in      VPP API message to send
     * @param in_len  length of the message to send
     * @param out     received VPP API message
     * @param out_len length of the received message
     */
    status_t (*send_dump)(vac_t *this, char *in, int in_len, char **out, int *out_len);

    /**
     * Register for VPP API event of a given kind.
     *
     * @param in       VPP API event message to register
     * @param in_len   length of the event message to register
     * @param cb       callback function to register
     * @param event_id event ID
     * @param ctx      user data passed to callback invocations
     */
    status_t (*register_event)(vac_t *this, char *in, int in_len, event_cb_t cb, uint16_t event_id, void *ctx);
};

extern vac_t *vac;

/**
 * Establishing a binary API connection to VPP.
 *
 * @param name client name
 * @return     vac_t instance
 */
vac_t *vac_create(char *name);

#endif /* KERNEL_VPP_SHARED_H_ */
