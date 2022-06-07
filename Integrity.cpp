#include "Integrity.hpp"
#include <stdio.h>

bool Integrity::Check(uint64_t Address, int nBytes, byte* originalBytes)
{
	bool memorySpoiled = false;

	for (int i = 0; i < nBytes; i++)
	{
		byte x = Utility<byte>::DereferenceSafe(Address + i);

		if (originalBytes[i] != x)
		{
			printf("Memory mismatch!\n");
			memorySpoiled = true;
		}
	}

	return true;
}

//we can build an array here at some memory location with nBytes, then SHA256 
uint8_t* Integrity::GetHash(uint64_t Address, int nBytes)
{
	byte* arr = new byte[nBytes];
	memcpy(&arr[0], (void*)&Address, nBytes);

	SHA256 sha;
	sha.update(arr);
	uint8_t* digest = sha.digest();

	//printf("%s\n", SHA256::toString(digest).c_str());
	printf("%llx\n", SHA256::GetStackedMultiple(digest));

	return digest;
}
