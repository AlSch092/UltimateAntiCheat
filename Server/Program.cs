//UltimateAnticheat Server - By AlSch092 @ Github
using System;
using UACServer.Network;

namespace UACServer
{
    internal class Program
    {
        static void Main(string[] args)
        {
            const string listen_addr = "0.0.0.0";
            const int port = 5445;

            AnticheatServer server = new AnticheatServer();
            server.Start(listen_addr, port);

            Logger.Log("UACServer.log", "Press any key to stop the server...");
            Console.ReadKey();

            server.Stop();

            Logger.Log("UACServer.log", "Finished listening...");
        }
    }
}
