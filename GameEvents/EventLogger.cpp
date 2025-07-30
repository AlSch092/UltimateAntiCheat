//UltimateAnticheat Project by AlSch092 @ Github
#include "EventLogger.hpp"
#include "../Common/json.hpp"

/**
 * @brief class object constructor
 *
 * @details This constructor should not directly be used, instead use `EventLogger::GetInstance()` to get the singleton instance.
 *           A worker thread is created which calls `SendDataToServer` if the event queue is not empty.
 * 
 * @return newly allocated class object
 *
 * @usage  Do not use!
 */
EventLogger::EventLogger()
{
	running.store(true);

	workerThread = std::thread([this]()
		{
			while (running.load())
			{
				{
					std::lock_guard<std::mutex> lock(mtx);
					if (!eventQueue.empty())
					{
						if (!SendDataToServer()) //failed after 5 re-tries
						{
							Logger::log(Err, "Could not push event data after multiple tries. Network may be down, or server is not available.");
						}
					}
				}
				std::this_thread::sleep_for(std::chrono::milliseconds(500));
			}
		});
}

/**
 * @brief Cleans up resources used by the class object
 *
 * @return None
 *
 * @usage
 * delete eventLogger;
 */
EventLogger::~EventLogger()
{
	running.store(false);
	if (workerThread.joinable())
		workerThread.join();
}

/**
 * @brief Obtains the singleton instance of the EventLogger class
 *
 *
 * @return reference to the singleton instance of EventLogger
 *
 * @usage
 * EventLogger& logger = EventLogger::GetInstance();
 */
EventLogger& EventLogger::GetInstance()
{
	static EventLogger instance;
	return instance;
}

/**
 * @brief places a game event into the queue to be sent to the server
 *
 * @param `event` GameEvent object containing the event type, timestamp, and details
 *
 * @return void
 *
 * @usage
 * EventLogger::GetInstance().LogEvent({ EventType::PLAYER_MOVE, "player123", EventLogger::GetUnixTimestampMs(), "Player moved to position (100, 200)" });
 */
void EventLogger::LogEvent(const GameEvent& event)
{
	std::lock_guard<std::mutex> lock(mtx);
	eventQueue.emplace(event);
}

/**
 * @brief Pushes the queue of events to the endpoint server
 * @details  if failure occurs, will re-try 5 times until success
 * @return true/false, indicating successful network request
 * @usage  Should not be directly called. A worker thread is created in the class constructor to handle data pushes
 */
bool EventLogger::SendDataToServer()
{
	if (this->ServerEndpoint.empty())
	{
		Logger::log(Err, "Server endpoint is not set. Cannot send event data.");
		return false;
	}

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

		json j =
		{
			{"type", static_cast<int>(event.type)},
			{"playerID", event.playerID},
			{"timestamp", event.timestamp},
			{"details", event.details}
		};

		HttpRequest request;
		request.url = ServerEndpoint;
		request.cookie = "";
		request.body = j.dump();
		request.requestHeaders =
		{
		    "Content-Type: application/json",
		    "Accept: application/json",
		    "User-Agent: GameEventLogger/1.0"
		};

		if (!HttpClient::PostRequest(request) || (request.responseHeaders.empty() && sendFailureCount < 5) )
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

		bool success = std::any_of(request.responseHeaders.begin(), request.responseHeaders.end(), [](const std::string& h) { return h.find("200 OK") != std::string::npos; });

		if (success)
		{
			Logger::log(Info, "Event data sent successfully: " + request.responseText);
			return true;
		}
	}

	return false;
}

/**
 * @brief Returns the current unix timestamp in milliseconds
 * @return 64-bit unsigned integer representing the unix timestamp in milliseconds
 * @usage  uint64_t timestampMS = EventLogger::GetUnixTimestampMs();
 */
uint64_t EventLogger::GetUnixTimestampMs()
{
	using namespace std::chrono;
	return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

/**
 * @brief Sets the data endpoint location
 * @details  Should be a URL supporting HTTP(s) requests
 * @return void
 * @usage EventLogger::GetInstance().SetEndpoint("http://mycoolgame.com/GameEvent");
 */
void EventLogger::SetEndpoint(const std::string& endpoint)
{
	ServerEndpoint = endpoint;
}