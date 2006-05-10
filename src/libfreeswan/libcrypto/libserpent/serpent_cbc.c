#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <sys/types.h>
#endif
#include "serpent_cbc.h"
#include "cbc_generic.h"
CBC_IMPL_BLK16(serpent_cbc_encrypt, serpent_context, u_int8_t *, serpent_encrypt, serpent_decrypt);
