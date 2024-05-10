#include "Packets.hpp"

PacketWriter* Packets::Builder::ClientHello(string gameCode, string HWID, string hostname, string MACAddress)
{
	PacketWriter* p = new PacketWriter(Packets::Opcodes::CS_HELLO);
	p->WriteString(gameCode.c_str());
	p->WriteString(HWID.c_str());
	p->WriteString(hostname.c_str());
	p->WriteString(MACAddress.c_str());
	return p;
}

PacketWriter* Packets::Builder::ClientGoodbye(int reason)
{
	PacketWriter* p = new PacketWriter(Packets::Opcodes::CS_GOODBYE);
	p->Write<int>(reason);
	return p;
}

PacketWriter* Packets::Builder::DetectedCheater(int flags) //todo: finish these
{
	PacketWriter* p = new PacketWriter(Packets::Opcodes::CS_FLAGGED_CHEATER);
	p->Write<int>(flags);
	return p;
}

PacketWriter* Packets::Builder::Heartbeat(const char* cookie_str) //todo: add more into this packet, such as integrity checking or detected flags.
{
	PacketWriter* p = new PacketWriter(Packets::Opcodes::CS_HEARTBEAT);
	p->WriteString(cookie_str);
	return p;
}

PacketWriter* Packets::Builder::QueryMemory(byte* bytestring, int size)
{
	PacketWriter* p = new PacketWriter(Packets::Opcodes::CS_QUERY_MEMORY);
	p->Write<uint16_t>(size);

	for (int i = 0; i < size; i++)
	{
	    p->Write<BYTE>(bytestring[i]);
	}

	return p;
}