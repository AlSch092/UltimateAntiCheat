#include "Packets.hpp"

PacketWriter* Packets::Builder::ClientHello(string HWID, string hostname, string MACAddress)
{
	PacketWriter* p = new PacketWriter(Packets::Opcodes::CS_HELLO);
	p->WriteString(HWID);
	p->WriteString(hostname);
	p->WriteString(MACAddress);
	return p;
}

PacketWriter* Packets::Builder::ClientGoodbye(int reason)
{
	PacketWriter* p = new PacketWriter(Packets::Opcodes::CS_GOODBYE);
	p->Write<int>(reason);
	return p;
}

PacketWriter* Packets::Builder::BinaryHashes(list<uint64_t> HashList) //todo: finish these
{
	PacketWriter* p = new PacketWriter(Packets::Opcodes::CS_BINARY_HASH);
	return p;
}

PacketWriter* Packets::Builder::DetectedBadBehavior(int flagsDetected) //todo: finish these
{
	PacketWriter* p = new PacketWriter(Packets::Opcodes::CS_BAD_BEHAVIOUR);
	return p;
}

PacketWriter* Packets::Builder::Heartbeat(uint64_t responseKey) //todo: add more into this packet, such as integrity checking or detected flags.
{
	PacketWriter* p = new PacketWriter(Packets::Opcodes::CS_HEARTBEAT);
	p->Write<uint64_t>(responseKey);
	return p;
}
