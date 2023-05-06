/*
NetClient.hpp
Notes:

if we send 'random' shellcode to generate a hash from the server to client it means the client 100% has to be running the code we send them or we d/c them, is this possible to bypass?
-> yes. they will let the anticheat run in specific spots (hash generation/replying) while patching over the spots they need to allow their hack to work.


can we somehow hide an encryption function -inside- the data of a packet, and then execute the packet buffer such that it automatically unpacks itself, runs an encryption method, and returns the value to server?
-> I think so, simple XOR stuff should work at the least.


how can we implement something which defeats the purpose of needing a driver?
->Complete server-sided design, possibly
*/

#define DEFAULT_PORT 5445
#define DEFAULT_RECV_LENGTH 512

#pragma once
#include <winsock2.h>
#include <Iphlpapi.h>
#include <list>

#include "Packets/Packets.hpp"

#include <stdint.h>
#include <string>
#include <time.h>

#pragma comment(lib, "ws2_32")
#pragma comment(lib, "iphlpapi.lib")

using namespace std;

enum Error //same as a "Status, an Error can still mean normal execution"
{
	OK,
	CANT_STARTUP,
	CANT_CONNECT,
	CANT_RECIEVE,
	CANT_SEND,
	LOST_CONNECTION,
	SERVER_KICKED,
	INCOMPLETE_SEND,
	INCOMPLETE_RECV,
	NO_RECV_THREAD,
	BAD_OPCODE,
	DATA_LENGTH_MISMATCH,
	NULL_MEMORY_REFERENCE,
};

/*
Class NetClient - Client-side of networking
*/
class NetClient
{
public:

	Error Initialize(string ip, uint16_t port); //connects, sends CS_HELLO, verifies the response of a version number from server
	Error EndConnection(int reason); //sends CS_GOODBYE and disconnects the socket

	Error SendData(PacketWriter* outPacket); //all data sent to the server after CS_HELLO should go through this

	static void ProcessRequests(LPVOID Param); //calls recv in a loop to handle requests, and if this routine is not running the program should be exited

	SOCKET GetClientSocket() { return this->Socket; }
	string GetConnectedIP() { return this->Ip; }
	uint16_t GetConnectedPort() { return this->Port; }

	static string GetIpv4();
	string GetMACAddress();
	string GetHardwareID(string driveRoot);

	uint64_t MakeHashFromServerResponse(PacketWriter* p);
	Error HandleInboundPacket(PacketWriter* p);

private:

	SOCKET Socket = SOCKET_ERROR;

	bool Connected = false;

	string Ip;
	uint16_t Port = DEFAULT_PORT;

	time_t ConnectedDuration = 0;
	time_t ConnectedAt;

	string ipv4;
	string HardwareID;
	string MACAddress;

	Error Status;

	HANDLE RecvLoopThread = NULL;
	DWORD recvThreadId;

	std::list<uint64_t> ResponseHashes; //each next reply should be built using the hash of the last response, similar to a blockchain . if this goes out of sync at any point, server d/cs client
};