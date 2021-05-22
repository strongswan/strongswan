#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>

#include "sm2.h"
#include "debug.h"

u8 selfPriKey[ECC_NUMWORD];
u8 selfTempPriKey[ECC_NUMWORD];
ecc_point selfPubKey[1];
ecc_point selfTempPubKey[1];

u8 otherPriKey[ECC_NUMWORD];
u8 otherTempPriKey[ECC_NUMWORD];
ecc_point otherPubKey[1];
ecc_point otherTempPubKey[1];

ecc_point selfPoint[1];
ecc_point otherPoint[1];

u8 selfId[16] = {
	0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38
};
u8 otherId[16] = {
	0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38
};
u8 selfIdLen = 16;
u8 otherIdLen = 16;

u8 ZA[ECC_NUMWORD];
u8 ZB[ECC_NUMWORD];

u8 selfKey[16];
u8 otherKey[16];
u32 selfKeyLen = 16;
u32 otherKeyLen = 16;

int main(int argc, char **argv)
{

	sm2_make_keypair(selfPriKey, selfPubKey);
	sm2_make_keypair(selfTempPriKey, selfTempPubKey);
	sm2_make_keypair(otherPriKey, otherPubKey);
	sm2_make_keypair(otherTempPriKey, otherTempPubKey);


	sm2_shared_point(selfPriKey, selfTempPriKey, selfTempPubKey, otherPubKey, otherTempPubKey, selfPoint);
	printHex("selfkey x", (u8*)selfPoint, ECC_NUMWORD*2);

	sm2_shared_point(otherPriKey, otherTempPriKey, otherTempPubKey, selfPubKey, selfTempPubKey, otherPoint);
	printHex("otherkey x", (u8*)otherPoint, ECC_NUMWORD*2);

	sm3_z(selfId, selfIdLen, selfPubKey, ZA);
	sm3_z(otherId, otherIdLen, otherPubKey, ZB);

	sm2_shared_key(selfPoint, ZA, ZB, selfKeyLen, selfKey);
	sm2_shared_key(otherPoint, ZA, ZB, otherKeyLen, otherKey);

	sm2_point_mult(otherPubKey, selfPriKey, selfPoint); /* U=[x2_]RB */
	printHex("selfkey x", (u8*)selfPoint, ECC_NUMWORD*2);

	sm2_point_mult(selfPubKey, otherPriKey, otherPoint); /* U=[x2_]RB */
	printHex("otherkey x", (u8*)otherPoint, ECC_NUMWORD*2);


	return 0;
}
