//By AlSch092 @github
#pragma once
#include <string>
#include <vector>
#include "../Common/DetectionFlags.hpp"
#include "../Network/HttpClient.hpp"
#include "../Common/Utility.hpp"
#include "../Common/json.hpp"

using json = nlohmann::json;

/*
    EventReporter sends detection events to a remote API endpoint
    Used for logging anti-cheat detections to a server
*/
class EventReporter final
{
public:
    EventReporter(const std::string& apiDomain);
    ~EventReporter() = default;

    // Send a detection event to the API
    bool ReportDetection(
        __in DetectionFlags flag,
        __in const std::string& detectionName,
        __in const std::string& detectionDetails,
        __in DWORD processId);

    // Get the last error message
    std::string GetLastError() const { return this->lastError; }

private:
    std::string apiDomain; // Base domain for API (e.g., "https://api.yourgame.com")
    std::string lastError;

    // Build the JSON payload for detection events
    std::string BuildDetectionPayload(
        __in DetectionFlags flag,
        __in const std::string& detectionName,
        __in const std::string& detectionDetails,
        __in DWORD processId,
        __in const std::vector<std::string>& macAddresses);
};
