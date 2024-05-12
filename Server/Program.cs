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

            const string current_ver = "v1.0.0";

            Console.Title = "UltimateAntiCheat Server " + current_ver;

            AnticheatServer server = new AnticheatServer();
            server.Start(listen_addr, port);

            Logger.Log("UACServer.log", "Server initialized: Press the Q key to stop the program...");

            bool listening_input = true;

            while(listening_input)
            {
                ConsoleKeyInfo key = Console.ReadKey();
                if (key.KeyChar == 'q')
                {
                    listening_input = false;
                    server.Stop();
                }
            }

            Logger.Log("UACServer.log", "Finished listening...");
        }
    }
}
