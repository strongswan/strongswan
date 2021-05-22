#ifndef _SM3_H_
#define _SM3_H_

#include <stdint.h>
#include "typedef.h"

typedef struct {
	uint32_t total[2];    /*!< number of bytes processed  */
	uint32_t state[8];    /*!< intermediate digest state  */
	uint8_t buffer[64];   /*!< data block being processed */
	uint8_t ipad[64];     /*!< HMAC: inner padding        */
	uint8_t opad[64];     /*!< HMAC: outer padding        */
} sm3_ctx;

int sm3_init(sm3_ctx *ctx);
int sm3_update(sm3_ctx *ctx, const uint8_t *input, uint32_t ilen);
int sm3_finish(sm3_ctx *ctx, uint8_t *output);

#endif /* _SM3_H_ */
