#pragma once
#include "../Common/Utility.hpp"
#include "../Process/Process.hpp"
#include "SHA256/SHA256.hpp"

class Integrity
{
public:

	bool Check(uint64_t Address, int nBytes, std::list<uint64_t>* hashList);
	list<uint64_t>* GetHash(uint64_t Address, int nBytes);

private:

	uint64_t _Checksum = 0;
	uint64_t _SectionHashes[255];


	Process* _Proc = new Process(); //get memory sections, etc, make hash of each section
};
