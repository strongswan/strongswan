#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>

#include "debug.h"
#include "sm4.h"

u8 iv[16];
u8 key[16];
u8 in[128];
u8 out[128];
u8 len = 64;

int main(int argc, char **agv)
{
	sm4_ctx ctx[1];
	int i;

	for (i = 0; i < len; i++) {
		in[i] = i;
	}
	memset(key, 0x88, 16);
	memset(iv, 0x99, 16);

	sm4_cbc_encrypt(ctx, key, iv, in, len, out);

	printHex("encrypt key ", key, 16);
	printHex("encrypt iv ", iv, 16);
	printHex("encrypt in ", in, len);
	printHex("encrypt out", out, len);

	sm4_cbc_decrypt(ctx, key, iv, out, len, in);

	printHex("encrypt key ", key, 16);
	printHex("encrypt iv ", iv, 16);
	printHex("decrypt out", out, len);
	printHex("decrypt in ", in, len);

	return 0;
}
