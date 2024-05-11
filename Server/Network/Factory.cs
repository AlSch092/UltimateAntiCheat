//UltimateAnticheat Server - By AlSch092 @ Github

namespace UACServer.Network
{
    public static class Factory
    {
        public static PacketWriter ClientHello(short versionNum) //SYN/ACK
        {
            PacketWriter writer = new PacketWriter((short)Opcodes.SC.SC_HELLO);
            writer.WriteShort(versionNum);
            return writer;
        }

        public static PacketWriter MakeHeartbeat(string cookie) //PING
        {
            PacketWriter writer = new PacketWriter((short)Opcodes.SC.SC_HEARTBEAT);
            writer.WriteShort((short)cookie.Length);
            writer.WriteString(cookie);
            return writer;
        }

    }
}
