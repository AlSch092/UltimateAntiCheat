//UltimateAnticheat Server - By AlSch092 @ Github

using System;
using System.Text;

namespace UACServer.Network
{
    internal class Handlers
    {
        public static bool HandleClientHello(AntiCheatClient c, PacketReader p) //hardwareID, hostname, MAC addr as fields
        {
            ushort gamecode_len = p.ReadUShort();
            string gamecode = p.ReadString(gamecode_len);

            ushort hardware_id_len = p.ReadUShort();
            string hardware_id = p.ReadString(hardware_id_len);

            ushort hostname_len = p.ReadUShort();
            string hostname = p.ReadString(hostname_len);

            ushort MAC_len = p.ReadUShort();
            string MAC = p.ReadString(MAC_len);

            if (hardware_id_len == 0 || hostname_len == 0 || MAC_len == 0)
                return false;

            c.hardware_id = hardware_id;
            c.hostname = hostname;
            c.mac_address = MAC;
            c.gamecode = gamecode;

            return true;
        }

        public static void HandleClientGoodbye(AntiCheatClient c) //todo: finish this
        {
        }

        public static bool HandleClientHeartbeat(AntiCheatClient c, string heartbeat)
        {
            byte Transformer = 0x18;
            const int cookie_size = 128;

            if (heartbeat.Length != cookie_size)
                return false;

            byte[] byteArray = Encoding.UTF8.GetBytes(heartbeat);
            byte[] byteArrayTransformed = new byte[cookie_size];

            for(int i = 0; i < cookie_size; i++)
            {
                byte b = (byte)((byte)byteArray[i] ^ Transformer);
                byteArrayTransformed[i] = b;
            }

            //check client response against what we sent originally, it should match
            string last_heartbeat = c.heartbeat_responses[c.current_heartbeat_count]; //get last entry in list

            string untransformed_cookie = Encoding.UTF8.GetString(byteArrayTransformed);

            if (last_heartbeat != untransformed_cookie)
            {
                return false;
            }


            Console.WriteLine("Heartbeat from client {0} was successful", c.id);
            return true;
        }

        public static bool HandleClientQueryMemory(AntiCheatClient c, string heartbeat)
        {
            return true;
        }
    }
}
