
#include <stdio.h>
#include <utils/identification.h>

/**
 * convert an identity to type and encoding
 */
int main(int argc, char *argv[])
{
	identification_t *id;
	chunk_t enc;
	int i;

	if (argc < 2)
	{
		return -1;
	}

	id = identification_create_from_string(argv[1]);
	if (!id)
	{
		return -2;
	}
	printf("type\tencoding\n");
	printf("%d,\t", id->get_type(id));
	enc = id->get_encoding(id);

	printf("X'");
	for (i = 0; i < enc.len; i++)
	{
		printf("%02x", (unsigned int)enc.ptr[i]);
	}
	printf("'\n");
	return 0;
}

