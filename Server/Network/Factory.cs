//By AlSch092 @ Github - UltimateAnticheat Server
using System.Net;

namespace UACServer.Network
{
    public static class Factory
    {
        public static PacketWriter ClientHello(short versionNum)
        {
            PacketWriter writer = new PacketWriter((short)Opcodes.SC.SC_HELLO);
            writer.WriteShort(versionNum);
            return writer;
        }

        public static PacketWriter MakeHeartbeat(string cookie)
        {
            PacketWriter writer = new PacketWriter((short)Opcodes.SC.SC_HEARTBEAT);
            writer.WriteShort((short)cookie.Length);
            writer.WriteString(cookie);
            return writer;
        }

    }
}
