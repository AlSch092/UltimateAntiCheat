//By AlSch092 @github
#include "AntiCheat.hpp"

//normally the server would send this packet to us as a heartbeat. the first data has no 'added' encryption on it, the ones after it use a secret key contained in the previous message. a payload is then executed by xoring each byte in the packet with the secret key
void AntiCheat::TestNetworkHeartbeat()
{
    //the first packet sent has no additional encryption, the ones sent after will be encrypted with the secret key of the last request
    BYTE shellcode[] = { 0x54,0x48,0x81,0xEC,0x80,0x00,0x00,0x00,0x51,0xB0,0x08,0x48,0xC7,0xC1,0x01,0x02,0x03,0x04,0x48,0xC7,0xC2,0x37,0x13,0x00,0x00,0x48,0x33,0xCA,0x48,0x81,0xC2,0x34,0x12,0x00,0x00,0x84,0xC0,0xFE,0xC8,0x75,0xF0,0x48,0x8B,0xC1,0x59,0x48,0x81,0xC4,0x80,0x00,0x00,0x00,0x5C,0xC3 };

    PacketWriter* p = new PacketWriter(Packets::Opcodes::SC_HEARTBEAT, shellcode, sizeof(shellcode)); //write opcode onto packet, then buffer

    if (!GetNetworkClient()->ExecutePacketPayload(p)) //so that we don't need a server running, just simulate a packet. every heartbeat is encrypted using the hash of the last heartbeat/some server gen'd key to prevent external message injection
    {
        PacketWriter* packet_1 = new PacketWriter(Packets::Opcodes::SC_HEARTBEAT);
        uint64_t hash = GetNetworkClient()->GetResponseHashList().back();

        for (int i = 0; i < sizeof(shellcode); i++) //this time we should xor our 'packet' by the last hash to simulate real environment/server, if we don't then we will get execution error        
            packet_1->Write<byte>(shellcode[i] ^ (BYTE)hash);

        if (!GetNetworkClient()->ExecutePacketPayload(packet_1)) //we call this a 2nd time to demonstrate how encrypting using the last hash works        
            printf("secret key gen failed: No server is present?\n");

        delete packet_1;
    }

    delete p;
}

