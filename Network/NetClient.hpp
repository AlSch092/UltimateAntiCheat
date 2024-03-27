//By AlSch092 @github
/*
NetClient.hpp
Notes:

can we somehow hide an encryption function inside the data of a packet, and then execute the packet buffer such that it automatically unpacks itself, runs an encryption method, and returns the value to server?
-> Yes, simple XOR stuff should work at the very least. -> Check UnpackAndExecute() for proof of concept, which we can now use to make a server-sided design

if we send 'random' shellcode to generate a hash from the server to client it means the client has to be running the code we send them, or we d/c them. is this possible to bypass?
-> yes. they will let the anticheat run in specific spots (hash generation/replying) while patching over the spots they need to allow their hack to work. we need to 'couple in' integrity checks inside the key generation shellcode routine to see if anything is hooked.

how can we implement something 'as powerful' as a driver?
->Completely server-sided design, possibly

*/

#define DEFAULT_RECV_LENGTH 512
#define MINIMUM_PACKET_SIZE 4

#pragma once
#include <winsock2.h>
#include <Iphlpapi.h>
#include <list>

#include "../Common/Error.hpp"
#include "Packets/Packets.hpp"

#include <stdint.h>
#include <string>

#pragma comment(lib, "ws2_32")
#pragma comment(lib, "iphlpapi.lib")

using namespace std;

/*
Class NetClient - Client-side of networking portion
*/
class NetClient
{
public:

	NetClient()
	{
	}

	NetClient(const char* serverEndpoint, uint16_t port)
	{
		Ip = serverEndpoint;
		Port = port;
	}

	Error Initialize(string ip, uint16_t port); //connects, sends CS_HELLO, verifies the response of a version number from server
	Error EndConnection(int reason); //sends CS_GOODBYE and disconnects the socket

	Error SendData(PacketWriter* outPacket); //all data sent to the server after CS_HELLO should go through this

	static void ProcessRequests(LPVOID Param); //calls recv in a loop to handle requests, and if this routine is not running the program should be exited

	SOCKET GetClientSocket() { return this->Socket; }
	string GetConnectedIP() { return this->Ip; }
	uint16_t GetConnectedPort() { return this->Port; }

	list<uint64_t> GetResponseHashList() { return this->HeartbeatHashes; }

	static string GetHostname();
	string GetMACAddress();
	string GetHardwareID();

	uint64_t MakeHashFromServerResponse(PacketWriter* p);
	Error HandleInboundPacket(PacketWriter* p);

	bool ExecutePacketPayload(PacketWriter* p); //unpacks receive packet which contains a secret key + payload

	bool HandshakeCompleted;
	bool Initialized;

private:

	SOCKET Socket = SOCKET_ERROR;

	bool Connected = false;

	string Ip;
	uint16_t Port = 0;

	unsigned int ConnectedDuration = 0;
	unsigned long ConnectedAt = 0; //unix timestamp

	string Hostname;
	string HardwareID;
	string MACAddress;

	Error Status = Error::OK;

	HANDLE RecvLoopThread = NULL;
	DWORD recvThreadId = 0;

	list<uint64_t> HeartbeatHashes; //each next reply should be built using the hash of the last response, similar to a blockchain . if this goes out of sync at any point, server d/cs client
};

