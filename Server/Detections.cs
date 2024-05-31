//UltimateAnticheat Server - By AlSch092 @ Github

namespace UACServer
{
    enum DetectionFlags //used in client-server comms to flag cheaters
    {
        DEBUGGER,
        PAGE_PROTECTIONS, //re-remapping
        CODE_INTEGRITY,   //.text section changes
        OPEN_PROCESS_HANDLES,
        UNSIGNED_DRIVERS,
        INJECTED_ILLEGAL_PROGRAM,
        EXTERNAL_ILLEGAL_PROGRAM,
    };
}
