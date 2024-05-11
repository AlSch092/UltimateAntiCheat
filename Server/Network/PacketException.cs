//UltimateAnticheat Server - By AlSch092 @ Github
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
