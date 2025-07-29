#include "Packets.hpp"

PacketWriter* Packets::Builder::ClientHello(__in const std::string gameCode, __in const std::string HWID, __in const std::string hostname, __in  const std::string MACAddress)
{
	PacketWriter* p = new PacketWriter(Packets::Opcodes::CS_HELLO);
	p->WriteString(gameCode.c_str());
	p->WriteString(HWID.c_str());
	p->WriteString(hostname.c_str());
	p->WriteString(MACAddress.c_str());
	return p;
}

PacketWriter* Packets::Builder::ClientGoodbye(__in const int reason)
{
	PacketWriter* p = new PacketWriter(Packets::Opcodes::CS_GOODBYE);
	p->Write<int>(reason);
	return p;
}

PacketWriter* Packets::Builder::DetectedCheater(__in  const int flags) //todo: finish these
{
	PacketWriter* p = new PacketWriter(Packets::Opcodes::CS_FLAGGED_CHEATER);
	p->Write<int>(flags);
	return p;
}

/*
	DetectedCheater - flag a user as cheating, with some string data about what it found
*/
PacketWriter* Packets::Builder::DetectedCheater(__in const uint32_t flags, __in const std::string detectedModule, __in const DWORD pid)
{
	PacketWriter* p = new PacketWriter(Packets::Opcodes::CS_FLAGGED_CHEATER);
	p->Write<uint32_t>(flags);
	p->Write<uint32_t>(pid);
	p->WriteString(detectedModule);
	return p;
}

PacketWriter* Packets::Builder::Heartbeat(__in const char* cookie_str) //todo: add more into this packet, such as integrity checking or detected flags.
{
	PacketWriter* p = new PacketWriter(Packets::Opcodes::CS_HEARTBEAT);
	p->WriteString(cookie_str);
	return p;
}

PacketWriter* Packets::Builder::QueryMemory(__in const byte* bytestring, __in  const int size)
{
	PacketWriter* p = new PacketWriter(Packets::Opcodes::CS_QUERY_MEMORY);
	p->Write<uint16_t>(size);

	for (int i = 0; i < size; i++)
	{
	    p->Write<BYTE>(bytestring[i]);
	}

	return p;
}