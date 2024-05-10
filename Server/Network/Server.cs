using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace UACServer.Network
{
    class TCPServer
    {
        private const short versionNum = 100;

        private TcpListener listener;
        private List<AntiCheatClient> clients = new List<AntiCheatClient>();
        private bool isRunning = false;

        public void Start(string ipAddress, int port)
        {
            listener = new TcpListener(IPAddress.Parse(ipAddress), port);
            listener.Start();
            isRunning = true;

            Logger.Log("UACServer.log", "Server started. Listening for connections...");

            // Start accepting client connections asynchronously
            listener.BeginAcceptTcpClient(HandleClientConnected, null);
        }

        private void HandleClientConnected(IAsyncResult result)
        {
            if (!isRunning)
                return;

            TcpClient client = listener.EndAcceptTcpClient(result);

            Logger.Log("UACServer.log", $"Client connected: {((IPEndPoint)client.Client.RemoteEndPoint).Address}");

            AntiCheatClient c = new AntiCheatClient();
            c.net_client = client;
            c.ip_addr = ((IPEndPoint)client.Client.RemoteEndPoint).Address;
            c.connected_at = Environment.TickCount;
            this.clients.Add(c);

            // Start asynchronously listening for messages from this client
            byte[] buffer = new byte[1024];
            client.GetStream().BeginRead(buffer, 0, buffer.Length, HandleMessageReceived, new object[] { client, buffer });

            // Continue accepting more client connections
            listener.BeginAcceptTcpClient(HandleClientConnected, null);
        }

        private void HandleMessageReceived(IAsyncResult result)
        {
            if (!isRunning)
                return;

            const int heartbeatDelay = 60000;

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
                return;
            }

            foreach (AntiCheatClient ca in clients)
            {
                if (ca.net_client == client) //need this for HandlePacket
                    c = ca;
            }

            if (bytesRead > 0)
            {
                string message = Encoding.ASCII.GetString(buffer, 0, bytesRead);
                Logger.Log("UACServer.log", $"Received from client {((IPEndPoint)client.Client.RemoteEndPoint).Address}: {message}");

                HandlePacket(c, buffer, bytesRead);

                // Send something to client every 60 seconds after receiving the first piece of data
                ThreadPool.QueueUserWorkItem(state =>
                {
                    var clientState = (object[])state;
                    var clientToSend = (TcpClient)clientState[0];
                    while (isRunning)
                    {
                        Thread.Sleep(heartbeatDelay); // 60 seconds between heartbeats
                        SendHeartbeat(c);                       
                    }
                }, asyncState);

                client.GetStream().BeginRead(buffer, 0, buffer.Length, HandleMessageReceived, asyncState);
            }
            else
            {
                Logger.Log("UACServer.log", $"Client {((IPEndPoint)client.Client.RemoteEndPoint).Address} disconnected."); //disconnected client

                foreach (AntiCheatClient ca in clients)
                {
                    if (ca.net_client == client)
                        clients.Remove(ca);
                }

                client.Close();
            }
        }

        private bool SendBytes(AntiCheatClient c, PacketWriter p)
        {
            if (!c.net_client.Client.Connected)
                return false;

            byte[] buffer = p.m_stream.GetBuffer();
            c.net_client.GetStream().Write(buffer, 0, buffer.Length);
            return true;
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

            c.heartbeat_responses.Add(cookie); //save heartbeats so that we can compare client responses to them.

            return SendBytes(c, p);
        }

        private bool HandlePacket(AntiCheatClient c, byte[] buffer, int length)
        {
            if (buffer == null || length == 0)
                return false;

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

                        if(!SendClientHello(c))
                        {
                            Logger.Log("UACServer.log", "Client hello transaction failed: failure sending bytes to client");
                            return false;
                        }
                    }
                    break;

                case Opcodes.CS.CS_GOODBYE: //client disconnect
                    Handlers.HandleClientGoodbye(c);
                    break;

                case Opcodes.CS.CS_HEARTBEAT: //heartbeat

                    string cookie_str = p.ReadString(128);

                    if (!Handlers.HandleClientHeartbeat(c, cookie_str))
                    {
                        Logger.Log("UACServer.log", "Client heartbeat transaction failed: client heartbeat cookie was incorrect.");
                        return false;
                    }
                    break;

                case Opcodes.CS.CS_FLAGGED_CHEATER:
                    c.flagged_cheater = true; //...then ban the cheater at some random time within the next 12h
                    break;

                case Opcodes.CS.CS_QUERY_MEMORY:

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

