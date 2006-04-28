#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <sys/types.h>
#endif
#include "twofish_cbc.h"
#include "cbc_generic.h"
CBC_IMPL_BLK16(twofish_cbc_encrypt, twofish_context, u_int8_t *, twofish_encrypt, twofish_decrypt);
