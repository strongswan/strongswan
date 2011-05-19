
#include <stdio.h>

/**
 * convert standard input to SQL hex binary
 */
int main(int argc, char *argv[])
{
	unsigned char byte;

	printf("X'");
	while (1)
	{
		if (fread(&byte, 1, 1, stdin) != 1)
		{
			break;
		}
		printf("%02x", (unsigned int)byte);
	}
	printf("'\n");
	return 0;
}

