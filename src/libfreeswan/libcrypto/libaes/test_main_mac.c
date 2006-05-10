#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include "aes.h"
#include "aes_xcbc_mac.h"
#define STR "Hola guasssso c|mo estais ...012"  
void print_hash(const __u8 *hash) {
	printf("%08x %08x %08x %08x\n", 
			*(__u32*)(&hash[0]), 
			*(__u32*)(&hash[4]), 
			*(__u32*)(&hash[8]), 
			*(__u32*)(&hash[12]));
}
int main(int argc, char *argv[]) {
	aes_block key= { 0xdeadbeef, 0xceedcaca, 0xcafebabe, 0xff010204 };
	__u8  hash[16];
	char *str = argv[1];
	aes_context_mac ctx;
	if (str==NULL) {
		fprintf(stderr, "pasame el str\n");
		return 255;
	}
	AES_xcbc_mac_set_key(&ctx, (__u8 *)&key, sizeof(key));
	AES_xcbc_mac_hash(&ctx, str, strlen(str), hash);
	print_hash(hash);
	str[2]='x';
	AES_xcbc_mac_hash(&ctx, str, strlen(str), hash);
	print_hash(hash);
	return 0;
}
