#include "AntiTamper/Integrity.hpp"
#include <stdio.h>
#include <algorithm>

//Call chain: GetHash() to get a hash list of module, then later call Check with the result from GetHash originally.
//working! returns false if any static memory is modified (assuming we pass in moduleBase and sizeOfModule.
bool Integrity::Check(uint64_t Address, int nBytes, std::list<uint64_t>* hashList)
{
	list<uint64_t>* hashes = GetHash(Address, nBytes);

	bool b_perm = std::is_permutation(hashList->begin(), hashList->end(), hashes->begin());
	
	delete hashes;

	return b_perm;
}

//we can build an array here at some memory location with nBytes, then SHA256 
list<uint64_t>* Integrity::GetHash(uint64_t Address, int nBytes)
{
	std::list<uint64_t>* hashList = new list<uint64_t>();

	byte* arr = new byte[nBytes];
	memcpy(arr, (void*)Address, nBytes);

	SHA256 sha;
	uint8_t* digest = 0;
	UINT64 digestCache = 0; //we keep adding 

	for (int i = 0; i < nBytes; i = i + 32)
	{
		sha.update(&arr[i], 32);
		digest = sha.digest();
		digestCache += *(UINT64*)digest + i;
		hashList->push_back(digestCache);
		printf("%llx ", digestCache);
		delete digest;
	}

	return hashList;
}
