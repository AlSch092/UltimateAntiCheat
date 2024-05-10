//By AlSch092 @ Github - UltimateAnticheat Server

namespace UACServer.Network.Opcodes
{
    public enum CS //client2server
    {
        CS_HELLO = 1,
        CS_GOODBYE, //there is no SC_GOODBYE
        CS_HEARTBEAT,
        CS_INFO_LOGGING, //hostname + mac address + hardware ID
        CS_FLAGGED_CHEATER,
        CS_QUERY_MEMORY,
    };

    public enum SC //server2client
    {
        SC_HELLO = 1,
        SC_HEARTBEAT,
        SC_INFO_LOGGING,
        SC_FLAGGED_CHEATER,
        SC_QUERY_MEMORY,
    };
}
