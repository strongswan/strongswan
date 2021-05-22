#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>

#include "debug.h"
#include "sm3.h"

u8 in[64];
u8 hash[32];
u8 len = 64;

int main(int argc, char **agv)
{
	sm3_ctx ctx[1];
	int i;

	for (i = 0; i < len; i++) {
		in[i] = i;
	}
		
	sm3_init(ctx);
	sm3_update(ctx, in, len);
	sm3_update(ctx, in, len);
	sm3_finish(ctx, hash);

	printHex("hash", hash, 32);

	return 0;
}
