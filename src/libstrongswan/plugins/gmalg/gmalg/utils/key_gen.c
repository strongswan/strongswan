#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>

#include "sm2.h"
#include "debug.h"

int main(int argc, char **argv)
{
	u8 pri[ECC_NUMWORD];
	ecc_point pub[1];

	int i = 1;
	while(i--){
		speed_test("aa", 2);
		sm2_make_prikey(pri);
		sm2_make_pubkey(pri, pub);
	}

	printHex("private", pri, 32);
	printHex("public_x",pub->x, 32);
	printHex("public_y",pub->y, 32);

	return 0;
}
