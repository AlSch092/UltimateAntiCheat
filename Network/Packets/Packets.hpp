#pragma once
#include "PacketWriter.hpp"
#include <list>
#include <stdint.h>

using namespace std;

namespace Packets
{
	namespace Opcodes
	{
		enum CS //client2server
		{
			CS_HELLO = 1,
			CS_GOODBYE,
			CS_CLIENTHASH,
			CS_HEARTBEAT,
			CS_INFO_LOGGING,
			CS_BINARY_HASH,
			CS_BAD_BEHAVIOUR
		};

		enum SC //server2client
		{
			SC_HELLO = 1,
			SC_GOODBYE,
			SC_CLIENTHASH,
			SC_HEARTBEAT,
			SC_INFOLOGGING,
			SC_SHELLCODE, //shellcode sent from the server is where the real fun begins, and seperates 'typical' anti-cheats from the truly glorious ones.
			SC_GENERATEKEY,
			SC_QUERYMEMORY, //query bytes at a specific memory address, used to detect tampering
		};	
	}

	namespace Builder
	{
		PacketWriter* ClientHello(string HWID, string Ipv4, string MACAddress);
		PacketWriter* ClientGoodbye(int reason);
		PacketWriter* Heartbeat(uint64_t responseKey);
		PacketWriter* BinaryHashes(list<uint64_t> HashList); //integrity checking of .text section
		PacketWriter* DetectedBadBehavior(int flagsDetected); //we can pack our detected things into an int on each bit
	}
}
