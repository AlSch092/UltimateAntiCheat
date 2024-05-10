#pragma once
#include "PacketWriter.hpp"
#include "PacketReader.hpp"
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
			CS_GOODBYE, //there is no SC_GOODBYE
			CS_HEARTBEAT, //heartbeats will be a 128-length text string which must be determinated by the server. this means both client and server need to know how to generate the next valid response
			CS_INFO_LOGGING, //hostname + mac address + hardware ID
			CS_FLAGGED_CHEATER, 
			CS_QUERY_MEMORY,
		};

		enum SC //server2client
		{
			SC_HELLO = 1,
			SC_HEARTBEAT,
			SC_INFO_LOGGING,
			SC_FLAGGED_CHEATER,
			SC_QUERY_MEMORY,
		};	
	}

	namespace Builder
	{
		PacketWriter* ClientHello(string gameCode, string HWID, string Ipv4, string MACAddress);
		PacketWriter* ClientGoodbye(int reason);
		PacketWriter* Heartbeat(const char* cookie_str);
		PacketWriter* DetectedCheater(int flags); //we can pack our detected things into an int on each bit
		PacketWriter* QueryMemory(byte* bytestring, int size);
	}
}
