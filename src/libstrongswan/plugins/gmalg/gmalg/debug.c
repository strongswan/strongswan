#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include<time.h>

void printHex(unsigned char *name, unsigned char *c, int n)
{
	int i;

	#define  _print	printf

	_print ("\n---------------------[%s ,len = %d, start ]----------------------\n",name,n);
	for (i = 0; i < n; i++) {
		_print("0x%02X, ", c[i]);
		if ((i%4) == 3)
		    _print(" ");

		if ((i%16) == 15)
		    _print("\n");
	}
	if ((i%16) != 0)
		_print("\n");
	_print("----------------------[%s       end        ]----------------------\n",name);
}

void speed_test( char *name, int len)
{
	static volatile unsigned long long byte = 0;
	static volatile unsigned long long count = 0;
	static time_t t1, t2;
	static int flag = 0;

	if (!flag) {
		flag = 3;
		time(&t1);
	}

	byte += len;
	count++;

	time(&t2);
	if ((t2-t1) >= flag) {

		unsigned long long byte_temp = byte;
		unsigned long long count_temp = count;

		if (byte_temp)
			byte_temp = byte_temp*8/flag/1024/1024;

		if (count_temp)
			count_temp = count_temp/flag;

		printf(" %s speed = %lld Mb, %lld Hz \n", name, byte_temp, count_temp);
		t1 = t2;
		byte = 0;
		count = 0;
	}
}
