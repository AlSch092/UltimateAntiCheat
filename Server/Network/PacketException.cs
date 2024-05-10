//By AlSch092 @ Github - UltimateAnticheat Server
namespace UACServer.Network
{
    public sealed class PacketException : System.Exception
    {
        public PacketException(string message)
            : base(message)
        {
        }
    }
}
