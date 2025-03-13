//UltimateAnticheat Server - By AlSch092 @ Github
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace UACServer.Network
{
    class AnticheatServer
    {
        private const short versionNum = 100;
        private const int heartbeatDelay = 60000; //1 minute between hb's

        private TcpListener listener;
        private List<AntiCheatClient> clients = new List<AntiCheatClient>();
        private bool isRunning = false;

        public static Dictionary<DetectionFlags, string> Detections = new Dictionary<DetectionFlags, string>();

        public void Start(string ipAddress, int port)
        {
            listener = new TcpListener(IPAddress.Parse(ipAddress), port);
            listener.Start();
            isRunning = true;

            Logger.Log("UACServer.log", "Server started. Listening for connections...");  
            listener.BeginAcceptTcpClient(HandleClientConnected, null); //listen for client connections asynchronously
        }

        private void AddDetectionDictionary()
        {
            //general Detections
            Detections.Add(DetectionFlags.PAGE_PROTECTIONS, "Page protections are not as expected");
            Detections.Add(DetectionFlags.CODE_INTEGRITY, "Code integrity check failed");
            Detections.Add(DetectionFlags.DLL_TAMPERING, "DLL tampering detected");
            Detections.Add(DetectionFlags.BAD_IAT, "Invalid IAT detected");
            Detections.Add(DetectionFlags.OPEN_PROCESS_HANDLES, "Unexpected open process handles detected");
            Detections.Add(DetectionFlags.UNSIGNED_DRIVERS, "Unsigned drivers detected");
            Detections.Add(DetectionFlags.INJECTED_ILLEGAL_PROGRAM, "Injected illegal program detected");
            Detections.Add(DetectionFlags.EXTERNAL_ILLEGAL_PROGRAM, "External illegal program detected");
            Detections.Add(DetectionFlags.HYPERVISOR, "Hypervisor detected");
            Detections.Add(DetectionFlags.REGISTRY_KEY_MODIFICATIONS, "Registry key modifications detected");

            //debug-related Detections
            Detections.Add(DetectionFlags.DEBUG_WINAPI_DEBUGGER, "WinAPI debugger detected");
            Detections.Add(DetectionFlags.DEBUG_PEB, "PEB (Process Environment Block) debugger detected");
            Detections.Add(DetectionFlags.DEBUG_HARDWARE_REGISTERS, "Hardware register debugger detected");
            Detections.Add(DetectionFlags.DEBUG_HEAP_FLAG, "Heap flag debugger detected");
            Detections.Add(DetectionFlags.DEBUG_INT3, "INT3 breakpoint detected");
            Detections.Add(DetectionFlags.DEBUG_INT2C, "INT2C breakpoint detected");
            Detections.Add(DetectionFlags.DEBUG_CLOSEHANDLE, "CloseHandle debugger detected");
            Detections.Add(DetectionFlags.DEBUG_DEBUG_OBJECT, "Debug object detected");
            Detections.Add(DetectionFlags.DEBUG_VEH_DEBUGGER, "VEH (Vector Exception Handler) debugger detected");
            Detections.Add(DetectionFlags.DEBUG_KERNEL_DEBUGGER, "Kernel debugger detected");
            Detections.Add(DetectionFlags.DEBUG_TRAP_FLAG, "Trap flag debugger detected");
            Detections.Add(DetectionFlags.DEBUG_DEBUG_PORT, "Debug port detected");
            Detections.Add(DetectionFlags.DEBUG_PROCESS_DEBUG_FLAGS, "Process debug flags detected");
            Detections.Add(DetectionFlags.DEBUG_REMOTE_DEBUGGER, "Remote debugger detected");
            Detections.Add(DetectionFlags.DEBUG_DBG_BREAK, "Debug break detected");
        }

        private void HandleClientConnected(IAsyncResult result)
        {
            if (!isRunning)
                return;

            TcpClient client = listener.EndAcceptTcpClient(result);

            Logger.Log("UACServer.log", $"Client connected: {((IPEndPoint)client.Client.RemoteEndPoint).Address}");

            AntiCheatClient c = new AntiCheatClient();
            c.id = new Random().Next(0, int.MaxValue); //right now not concerned about duplicate id's, chance is very low to encounter this
            c.net_client = client;
            c.ip_addr = ((IPEndPoint)client.Client.RemoteEndPoint).Address;
            c.connected_at = Environment.TickCount;
            this.clients.Add(c);

            byte[] buffer = new byte[1024];
            
            try
            {
                client.GetStream().BeginRead(buffer, 0, buffer.Length, HandleMessageReceived, new object[] { client, buffer });
            }
            catch(IOException ex)
            {
                Logger.Log("UACServer.log", "Failed to read client data @ HandleClientConnected");
                return;
            }
            
            listener.BeginAcceptTcpClient(HandleClientConnected, null); //Continue accepting more client connections
        }

        private void HandleMessageReceived(IAsyncResult result)
        {
            if (!isRunning)
                return;

            object[] asyncState = (object[])result.AsyncState;
            TcpClient client = (TcpClient)asyncState[0];
            AntiCheatClient c = null;
            byte[] buffer = (byte[])asyncState[1];

            int bytesRead = 0;

            try
            {
                bytesRead = client.GetStream().EndRead(result);
            }
            catch (IOException ex)
            {
                Logger.Log("UACServer.log", "IOExcpetion @ HandleMessageReceived(): " + ex.Message);
                Console.WriteLine("Removing client from list");
                this.clients.Remove(c);
                return;
            }

            foreach (AntiCheatClient ca in clients)
            {
                if (ca.net_client == client) //need this for HandlePacket
                    c = ca;
            }

            if (bytesRead > 0)
            {        
                if(!HandlePacket(c, buffer, bytesRead))
                {
                    Logger.Log("UACServer.log", "Client heartbeat was incorrect, disconnecting client " +  c.hardware_id);
                    c.net_client.Client.Disconnect(false);
                    c.net_client.Dispose();
                    return;
                }

                if(!c.in_heartbeat_loop)
                {
                    c.in_heartbeat_loop = true;

                    // Send something to client every 60 seconds after receiving the first piece of data
                    ThreadPool.QueueUserWorkItem(state => //...not the best C# code by any means
                    {
                        var clientState = (object[])state;
                        var clientToSend = (TcpClient)clientState[0];

                        Thread.Sleep(heartbeatDelay);

                        if (clientToSend.Connected)
                        {
                            Console.WriteLine("Sending heartbeat...");
                            if (!SendHeartbeat(c))
                            {
                                clientToSend.Client.Disconnect(false);
                                return;
                            }
                            else
                            {
                                c.in_heartbeat_loop = false;
                            }
                        }
                        else
                        {
                            return;
                        }

                    }, asyncState);
                }

                try
                {
                    client.GetStream().BeginRead(buffer, 0, buffer.Length, HandleMessageReceived, asyncState);
                }
                catch(IOException ex)
                {
                    Logger.Log("UACServer.log", "Failed to read client data @ HandleMessageReceived");
                    return;
                }
            }
            else
            {
                Logger.Log("UACServer.log", $"Client {((IPEndPoint)client.Client.RemoteEndPoint).Address} disconnected."); //disconnected client

                AntiCheatClient toRemove = null;

                foreach (AntiCheatClient ca in clients)
                {
                    if (ca.net_client == client)
                        toRemove = ca;
                }

                if(toRemove != null)
                    clients.Remove(toRemove);

                client.Close();
            }
        }

        private bool SendBytes(AntiCheatClient c, PacketWriter p)
        {
            if (!c.net_client.Client.Connected)
                return false;

            byte[] buffer = p.m_stream.GetBuffer();

            Cipher(buffer, buffer.Length);

            if (c.net_client.Connected)
            {
                c.net_client.GetStream().Write(buffer, 0, buffer.Length);
                return true;
            }

            return false;
        }

        private bool SendClientHello(AntiCheatClient c)
        {         
            PacketWriter p = Factory.ClientHello(versionNum);
            return SendBytes(c, p);
        }

        private bool SendHeartbeat(AntiCheatClient c)
        {    
            string cookie = RandomStringGenerator.GenerateRandomString(128);
            PacketWriter p = Factory.MakeHeartbeat(cookie);
            c.heartbeat_responses.Add(cookie); //save heartbeats so that we can compare client responses to them fpr .
            return SendBytes(c, p);
        }

        private void Cipher(byte[] buffer, int length)
        {
            const byte xorKey = 0x90;
            const byte operationKey = 0x14;

            for(int i = 0; i < length; i++)
            {
                if (i % 2 == 0)
                    buffer[i] = (byte)((buffer[i] - operationKey ) ^ xorKey);
                else
                    buffer[i] = (byte)((buffer[i] + operationKey ) ^ xorKey);
            }
        }

        private bool HandlePacket(AntiCheatClient c, byte[] buffer, int length)
        {
            if (buffer == null || length == 0)
                return false;

            //decrypt buffer
            Cipher(buffer, length);

            PacketReader p = new PacketReader(buffer);
            ushort opcode = p.ReadUShort();

            switch ((Opcodes.CS)opcode)
            {
                case Opcodes.CS.CS_HELLO: //client hello
                {
                    if (!Handlers.HandleClientHello(c, p))
                    {
                        Logger.Log("UACServer.log", "Client hello transaction failed: gamecode/license was not correct.");
                        return false;
                    }
                    else
                    {
                            Logger.Log("UACServer.log", "Client info: Hostname=" + c.hostname + ", GameCode=" + c.gamecode + ", ID=" + c.id + ", IP=" + c.ip_addr);
                    }

                    if(!SendClientHello(c))
                    {
                        Logger.Log("UACServer.log", "Client hello transaction failed: failure sending bytes to client");
                        return false;
                    }
                }
                break;

                case Opcodes.CS.CS_HEARTBEAT: //heartbeat
                {
                    short cookie_len = p.ReadShort();
                    string cookie_str = p.ReadString(128);

                    if (!Handlers.HandleClientHeartbeat(c, cookie_str))
                    {
                        Logger.Log("UACServer.log", "Client heartbeat transaction failed: client heartbeat cookie was incorrect.");
                        return false;
                    }
                    else
                    {
                        Console.WriteLine("Heartbeat from client {0} was successful", c.id);
                    }

                    c.current_heartbeat_count++;
                }
                break;

                case Opcodes.CS.CS_FLAGGED_CHEATER: //flagged as cheater
                {
                    c.flagged_cheater = true; //...then ban the cheater at some random time within the next 12h
                    DetectionFlags cheat_reason = (DetectionFlags)p.ReadShort();
                    Handlers.HandleClientFlaggedCheater(c, cheat_reason);
                } break;

                case Opcodes.CS.CS_QUERY_MEMORY: //todo: finish this
                {

                }
                break;

                default:
                    Logger.Log("UACServer.log", "Unknown opcode @ HandlePacket");
                    return false;
            };

            return true;
        }

        public void Stop()
        {
            isRunning = false;

            // Close all client connections
            foreach (AntiCheatClient client in clients)
            {
                client.net_client.Close();
            }
            clients.Clear();

            // Stop listening for new connections
            listener.Stop();

            Console.WriteLine("Server stopped.");
        }
    }

}

