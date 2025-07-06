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
    CUSTOM,
    UNKNOWN
};

struct GameEvent
{
    EventType type;
    std::string playerID;
    uint64_t timestamp; // Unix timestamp in milliseconds
    std::string details;
};

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
