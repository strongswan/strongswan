
#include <stdio.h>

/**
 * convert standard input to binary data to a c array
 */
int main(int argc, char *argv[])
{
	int i, end = 0;
	unsigned char byte;

	printf("char %s[] = {\n", argc > 1 ? argv[1] : "data");
	while (1)
	{
		printf("  ");
		for (i = 0; i < 16; i++)
		{
			if (fread(&byte, 1, 1, stdin) != 1)
			{
				end = 1;
				break;
			}
			printf("0x%02x,", (unsigned int)byte);
		}
		printf("\n");
		if (end)
		{
			break;
		}
	}
	printf("};\n");
	return 0;
}

