//UltimateAnticheat Project by AlSch092 @ Github
#pragma once
#include "../Common/Logger.hpp"
#include "../Network/HttpClient.hpp"
#include "../Common/json_fwd.hpp"
#include <mutex>
#include <string>
#include <queue>
#include <chrono>
#include <thread>
#include <atomic>

using json = nlohmann::json;

enum class EventType
{
    PLAYER_MOVE,
    PLAYER_DIE,
    PLAYER_CROUCH,
    PLAYER_JUMP,
    WEAPON_FIRE,
    ENEMY_HEAD_IN_CROSSHAIR,
    ITEM_PICKUP,
    ON_KILL_ENEMY,
    CUSTOM, //specify in the actual message details
    UNKNOWN
};

struct GameEvent
{
    EventType type;
    std::string playerID;
    uint64_t timestamp; // Unix timestamp in milliseconds
    std::string details;
};

/*
	EventLogger - A singleton class that logs game events to a server endpoint.
	It uses a separate thread to send data to the server asynchronously.

	Purely for telemetry, this class does not perform any security checks or validations.
    You should call this as `EventLogger::GetInstance().LogEvent(event);` from your game after setting your server endpoint via `SetEndpoint(string url)`
*/
class EventLogger
{
public:
    EventLogger();
    ~EventLogger();

    static EventLogger& GetInstance();

    void LogEvent(const GameEvent& event);
    void SetEndpoint(const std::string& endpoint);
    static uint64_t GetUnixTimestampMs();

private:
    std::mutex mtx;
    std::thread workerThread;
    std::queue<GameEvent> eventQueue;
    std::string ServerEndpoint;
    std::atomic<bool> running;

    void SendDataToServer();
};
