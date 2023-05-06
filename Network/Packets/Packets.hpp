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
			SC_INFOLOGGING
		};	
	}

	namespace Builder
	{
		PacketWriter* ClientHello(string HWID, string Ipv4, string MACAddress);
		PacketWriter* ClientGoodbye(int reason);
		
		PacketWriter* BinaryHashes(list<uint64_t> HashList);
		PacketWriter* DetectedBadBehavior(int flagsDetected); //we can pack our detected things into an int on each bit
	}
}
