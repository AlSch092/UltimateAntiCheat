//UltimateAnticheat Project by AlSch092 @ Github
#include "EventLogger.hpp"
#include "../Common/json.hpp"

EventLogger::EventLogger()
{
    running.store(true);

    workerThread = std::thread([this]() {
        while (running.load()) {
            {
                std::lock_guard<std::mutex> lock(mtx);
                if (!eventQueue.empty()) {
                    SendDataToServer();
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
        });
}

EventLogger::~EventLogger()
{
    running.store(false);
    if (workerThread.joinable())
        workerThread.join();
}

EventLogger& EventLogger::GetInstance()
{
    static EventLogger instance;
    return instance;
}

void EventLogger::LogEvent(const GameEvent& event)
{
    std::lock_guard<std::mutex> lock(mtx);
    eventQueue.emplace(event);
}

void EventLogger::SendDataToServer()
{
    std::vector<std::string> requestHeaders = {
        "Content-Type: application/json",
        "Accept: application/json",
        "User-Agent: GameEventLogger/1.0"
    };

    std::vector<std::string> responseHeaders;
    std::string requestCookie = "";

    int sendFailureCount = 0;

    while (true)
    {
        GameEvent event;

        {
            std::lock_guard<std::mutex> lock(mtx);
            if (eventQueue.empty())
                break;

            event = eventQueue.front();
            eventQueue.pop();
        }

        if (event.details.empty() || event.playerID.empty() || event.timestamp == 0)
            continue;

        json j = {
            {"type", static_cast<int>(event.type)},
            {"playerID", event.playerID},
            {"timestamp", event.timestamp},
            {"details", event.details}
        };

        std::string response = HttpClient::PostRequest(
            ServerEndpoint,
            requestHeaders,
            requestCookie,
            j.dump(),
            responseHeaders
        );

        if (responseHeaders.empty() && sendFailureCount < 5)
        {
            Logger::log(Err, "Failed to send event data to server.");
            sendFailureCount++;

            std::lock_guard<std::mutex> lock(mtx);
            eventQueue.push(event);
            continue;
        }
        else if (sendFailureCount >= 5)
        {
            Logger::log(Err, "Failed to send event data after multiple attempts.");
            std::lock_guard<std::mutex> lock(mtx);
            eventQueue.push(event);
            break;
        }

        bool success = std::any_of(responseHeaders.begin(), responseHeaders.end(), [](const std::string& h) { return h.find("200 OK") != std::string::npos; });

        if (success)
        {
            Logger::log(Info, "Event data sent successfully: " + response);
        }
    }
}

uint64_t EventLogger::GetUnixTimestampMs()
{
    using namespace std::chrono;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

void EventLogger::SetEndpoint(const std::string& endpoint)
{
	ServerEndpoint = endpoint;
}