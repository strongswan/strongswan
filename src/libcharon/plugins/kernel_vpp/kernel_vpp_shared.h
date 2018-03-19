#ifndef KERNEL_VPP_SHARED_H_
#define KERNEL_VPP_SHARED_H_

typedef struct vac_t vac_t;
typedef void (*event_cb_t)(char *data, int data_len, void *ctx);

struct vac_t {
    void (*destroy)(vac_t *this);
    status_t (*send)(vac_t *this, char *in, int in_len, char **out, int *out_len);
    status_t (*send_dump)(vac_t *this, char *in, int in_len, char **out, int *out_len);
    status_t (*register_event)(vac_t *this, char *in, int in_len, event_cb_t cb, uint16_t event_id, void *ctx);
};

extern vac_t *vac;
vac_t *vac_create(char *name);

#endif /* KERNEL_VPP_SHARED_H_ */
