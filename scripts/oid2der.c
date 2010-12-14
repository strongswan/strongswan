
#include <stdio.h>
#include <asn1/asn1.h>

/**
 * convert string OID to DER encoding
 */
int main(int argc, char *argv[])
{
	int i, nr = 0;
	chunk_t oid;

	while (argc > ++nr)
	{
		oid = asn1_oid_from_string(argv[nr]);
		if (oid.len)
		{
			for (i = 0; i < oid.len; i++)
			{
				printf("0x%02x,", oid.ptr[i]);
			}
			printf("\n");
			free(oid.ptr);
		}
		else
		{
			return 1;
		}
	}
	return 0;
}
